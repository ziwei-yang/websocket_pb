// msg/mkt_dedup.hpp
// Shared MktEvent duplicate detection state machine
// Reconciled logic from mkt_viewer.cpp (canonical behavior):
//   - Snapshot: accept channel if src_seq >= ch_seq (same-seq OK)
//   - Delta same-seq: DUP only if ALL entries already seen (overlap == count)
//   - Delta older-seq: DUP unconditionally
//   - BBO/Trade: DUP if src_seq > 0 && src_seq <= last_seq
//   - src_seq == 0: skip dedup entirely
#pragma once

#include "mkt_event.hpp"
#include <unordered_set>

namespace websocket::msg {

inline uint64_t delta_content_key(const DeltaEntry& de) {
    return (static_cast<uint64_t>(de.price) << 1) | (de.flags & DeltaFlags::SIDE_ASK);
}

enum class DupVerdict : uint8_t { NEW, DUP_SEQ, DUP_CONTENT, DUP_SNAP };

struct MktDedupResult {
    DupVerdict verdict;
    uint8_t    channel;        // depth channel (for DELTA)
    uint8_t    overlap;        // overlapping entries (for DELTA same-seq)
    uint8_t    entry_count;    // total entries in event
    uint8_t    snap_accepted;  // bitmask of channels that accepted snapshot
    bool is_dup() const { return verdict != DupVerdict::NEW; }
};

template<int DepthChannels = 3>
struct MktDedupState {
    int64_t  ob_channel_seq[DepthChannels] = {};
    int64_t  trade_seq = 0;
    int64_t  bbo_seq   = 0;
    int64_t  liq_seq   = 0;
    int64_t  mark_price_seq = 0;
    uint64_t dup_count = 0;
    int64_t  last_dup_seq = 0;
    std::unordered_set<uint64_t> ob_seen_deltas[DepthChannels];

    MktDedupResult check(const MktEvent& evt) {
        MktDedupResult r{DupVerdict::NEW, 0, 0, evt.count, 0};

        if (evt.is_book_snapshot()) {
            bool any_accepted = false;
            for (int c = 0; c < DepthChannels; c++) {
                if (evt.src_seq >= ob_channel_seq[c]) {
                    ob_channel_seq[c] = evt.src_seq;
                    ob_seen_deltas[c].clear();
                    r.snap_accepted |= (1 << c);
                    any_accepted = true;
                }
            }
            if (!any_accepted) {
                r.verdict = DupVerdict::DUP_SNAP;
                dup_count++;
                last_dup_seq = evt.src_seq;
            }
            return r;
        }

        if (evt.is_book_delta()) {
            uint8_t ch = evt.depth_channel();
            if (ch >= DepthChannels) ch = 0;
            r.channel = ch;
            int64_t& ch_seq = ob_channel_seq[ch];
            auto& ch_seen = ob_seen_deltas[ch];

            if (evt.src_seq > 0 && evt.src_seq <= ch_seq) {
                if (evt.src_seq == ch_seq) {
                    // Same seq — content-based dedup for multi-flush
                    uint8_t overlap = 0;
                    for (uint8_t i = 0; i < evt.count; i++) {
                        if (ch_seen.count(delta_content_key(evt.payload.deltas.entries[i])))
                            overlap++;
                    }
                    r.overlap = overlap;
                    if (overlap == evt.count) {
                        // ALL entries already seen = true dup
                        r.verdict = DupVerdict::DUP_CONTENT;
                        dup_count++;
                        last_dup_seq = evt.src_seq;
                        return r;
                    }
                    // Partial overlap = multi-flush fragment, insert new keys
                    for (uint8_t i = 0; i < evt.count; i++)
                        ch_seen.insert(delta_content_key(evt.payload.deltas.entries[i]));
                } else {
                    // Older seq
                    r.verdict = DupVerdict::DUP_SEQ;
                    dup_count++;
                    last_dup_seq = evt.src_seq;
                    return r;
                }
            } else {
                // New seq (or src_seq == 0)
                ch_seen.clear();
                for (uint8_t i = 0; i < evt.count; i++)
                    ch_seen.insert(delta_content_key(evt.payload.deltas.entries[i]));
            }
            ch_seq = std::max(ch_seq, evt.src_seq);
            return r;
        }

        // Liquidation / Mark Price / BBO / Trade — simple monotonic seq check
        if (evt.src_seq > 0) {
            int64_t* seq_p = evt.is_trade_array()  ? &trade_seq :
                             evt.is_liquidation()   ? &liq_seq :
                             evt.is_mark_price()    ? &mark_price_seq :
                                                      &bbo_seq;
            if (evt.src_seq <= *seq_p) {
                r.verdict = DupVerdict::DUP_SEQ;
                dup_count++;
                last_dup_seq = evt.src_seq;
            }
            *seq_p = std::max(*seq_p, evt.src_seq);
        }
        return r;
    }

    void reset() {
        for (int c = 0; c < DepthChannels; c++) {
            ob_channel_seq[c] = 0;
            ob_seen_deltas[c].clear();
        }
        trade_seq = 0;
        bbo_seq = 0;
        liq_seq = 0;
        mark_price_seq = 0;
        dup_count = 0;
        last_dup_seq = 0;
    }
};

}  // namespace websocket::msg
