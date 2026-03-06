#!/usr/bin/env node
// tools/mkt_verifer_binance_usdm.js
// Pure-JS reference implementation of Binance USDM JSON streaming parser.
// Re-parses raw WS frame payloads using character-level scanning (no JSON.parse),
// applies dedup/merge, and compares against C++ MktEvent output to detect parser bugs.
//
// Architecture:
//   WSFrame → Per-Connection Context → StreamClassifier
//     → Exchange-Specific Parser (positional scanning, handles partial data)
//       → General Parsed Structs (ParsedTrade / ParsedBookLevel / ParsedDelta)
//         → Unified MktEvent Generator (dedup, merge, flush, emit)
//           → MktEvent[]
//
// Usage:
//   node tools/mkt_verifer_binance_usdm.js wsframes.txt mktevents.txt

'use strict';

const fs = require('fs');

// ============================================================================
// Section 1: Constants (must match C++ exactly)
// ============================================================================

const PRICE_SCALE = 1000000n;   // market_conf.hpp:21 — 10^(8-2) for BTCUSDT 2dp
const QTY_SCALE   = 100000n;    // market_conf.hpp:22 — 10^(8-3) for BTCUSDT 3dp

const MAX_TRADES      = 11;  // mkt_event.hpp:142 — 472/40 = 11
const MAX_DELTAS      = 19;  // mkt_event.hpp:123 — 472/24 = 19
const MAX_BOOK_LEVELS = 29;  // mkt_event.hpp:133 — 472/16 = 29
const SNAPSHOT_HALF   = 14;  // 01_binance_usdm_json.hpp:856 — 29/2 = 14

// EventType enum (mkt_event.hpp:20-26)
const EVENT_BOOK_DELTA    = 0;
const EVENT_BOOK_SNAPSHOT = 1;
const EVENT_TRADE_ARRAY   = 2;
const EVENT_SYSTEM_STATUS = 3;

// DeltaAction enum (mkt_event.hpp:34-38)
const ACTION_NEW    = 0;
const ACTION_UPDATE = 1;
const ACTION_DELETE = 2;

// Flag bits (mkt_event.hpp:58-63)
const FLAG_SIDE_ASK  = 0x01;  // DeltaFlags::SIDE_ASK
const FLAG_IS_BUYER  = 0x01;  // TradeFlags::IS_BUYER

// WSFrameInfo flags (pipeline_data.hpp)
const WS_FLAG_FIN             = 0x01;
const WS_FLAG_FRAGMENTED      = 0x02;
const WS_FLAG_LAST_FRAGMENT   = 0x04;
const WS_FLAG_DISCARD_EARLY   = 0x10;
const WS_FLAG_MERGED          = 0x40;
const WS_FLAG_LAST_IN_BATCH   = 0x80;

// EventFlags (mkt_event.hpp:50-56)
const EVT_FLAG_SNAPSHOT      = 0x0001;
const EVT_FLAG_CONTINUATION  = 0x0002;
const EVT_FLAG_LAST_IN_BATCH = 0x0004;
const EVT_FLAG_CONN_ID_SHIFT = 8;

// Stream types (01_binance_usdm_json.hpp:140-142)
const STREAM_UNKNOWN       = 0;
const STREAM_AGG_TRADE     = 1;
const STREAM_DEPTH_PARTIAL = 2;
const STREAM_DEPTH_DIFF    = 3;

// ============================================================================
// Section 2: JSON Scanning Primitives
// Mirrors 01_binance_usdm_json.hpp lines 29-128.
// All functions work on a string `s` with integer position `pos`.
// Returns new position, or -1 if truncated (hit end of string).
// ============================================================================

// Skip past a quoted string. pos at opening '"'.
// Returns position past closing '"', or -1 if truncated.
// Mirrors: skip_string(p, end) — line 29
function skipString(s, pos) {
    if (pos >= s.length || s[pos] !== '"') return pos;
    pos++;  // skip opening '"'
    while (pos < s.length) {
        if (s[pos] === '\\') { pos += 2; continue; }  // skip escaped char
        if (s[pos] === '"') return pos + 1;            // past closing '"'
        pos++;
    }
    return -1;  // truncated
}

// Skip past a number. pos at first digit/'-'.
// Returns position past last digit/'.'/etc, or -1 if truncated.
// Mirrors: skip_number(p, end) — line 41
function skipNumber(s, pos) {
    while (pos < s.length) {
        const c = s[pos];
        if ((c >= '0' && c <= '9') || c === '-' || c === '.' || c === 'e' || c === 'E' || c === '+')
            pos++;
        else
            break;
    }
    return pos;
}

// Skip past any JSON value. pos at start of value.
// Returns position past value, or -1 if truncated.
// Mirrors: skip_value(p, end) — line 48
function skipValue(s, pos) {
    if (pos >= s.length) return -1;
    const c = s[pos];
    if (c === '"') return skipString(s, pos);
    if (c === '{') {
        pos++;
        let depth = 1;
        while (pos < s.length && depth > 0) {
            if (s[pos] === '"') { pos = skipString(s, pos); if (pos === -1) return -1; continue; }
            if (s[pos] === '{') depth++;
            else if (s[pos] === '}') depth--;
            pos++;
        }
        return depth === 0 ? pos : -1;
    }
    if (c === '[') {
        pos++;
        let depth = 1;
        while (pos < s.length && depth > 0) {
            if (s[pos] === '"') { pos = skipString(s, pos); if (pos === -1) return -1; continue; }
            if (s[pos] === '[') depth++;
            else if (s[pos] === ']') depth--;
            pos++;
        }
        return depth === 0 ? pos : -1;
    }
    if (c === 't') return pos + 4 <= s.length ? pos + 4 : -1;  // true
    if (c === 'f') return pos + 5 <= s.length ? pos + 5 : -1;  // false
    if (c === 'n') return pos + 4 <= s.length ? pos + 4 : -1;  // null
    return skipNumber(s, pos);  // number
}

// Skip one full "key":value field. pos at '"' of key.
// Returns position past value+comma/spaces, or -1 if truncated.
// Mirrors: skip_field(p, end) — line 82
function skipField(s, pos) {
    pos = skipString(s, pos);   // skip key
    if (pos === -1) return -1;
    while (pos < s.length && s[pos] !== ':') pos++;
    if (pos >= s.length) return -1;
    pos++;  // skip ':'
    while (pos < s.length && s[pos] === ' ') pos++;
    pos = skipValue(s, pos);    // skip value
    if (pos === -1) return -1;
    while (pos < s.length && (s[pos] === ',' || s[pos] === ' ')) pos++;
    return pos;
}

// Skip "key": prefix. pos at '"' of key.
// Returns position at value start, or -1 if truncated.
// Mirrors: to_value(p, end) — line 93
function toValue(s, pos) {
    pos = skipString(s, pos);   // skip key
    if (pos === -1) return -1;
    while (pos < s.length && s[pos] !== ':') pos++;
    if (pos >= s.length) return -1;
    pos++;  // skip ':'
    while (pos < s.length && s[pos] === ' ') pos++;
    return pos;
}

// Parse int64 at pos (first digit/'-'). Returns {value: BigInt, endPos}.
// Returns null if truncated.
// Mirrors: parse_int64_fast(p, end) — line 102
function parseInt64(s, pos) {
    if (pos >= s.length) return null;
    let neg = false;
    if (s[pos] === '-') { neg = true; pos++; }
    let v = 0n;
    const start = pos;
    while (pos < s.length && s[pos] >= '0' && s[pos] <= '9') {
        v = v * 10n + BigInt(s.charCodeAt(pos) - 48);
        pos++;
    }
    if (pos === start) return null;  // no digits parsed
    return { value: neg ? -v : v, endPos: pos };
}

// Parse quoted decimal "50123.40" → mantissa 5012340n.
// pos at opening '"'. Returns {value: BigInt, endPos} past closing '"'.
// Returns null if truncated.
// Mirrors: parse_decimal_string(p, end) — line 114
function parseDecStr(s, pos) {
    if (pos >= s.length || s[pos] !== '"') return null;
    pos++;  // skip opening '"'
    let neg = false;
    if (pos < s.length && s[pos] === '-') { neg = true; pos++; }
    let v = 0n;
    while (pos < s.length && s[pos] !== '"') {
        if (s[pos] === '.') { pos++; continue; }
        if (s[pos] >= '0' && s[pos] <= '9')
            v = v * 10n + BigInt(s.charCodeAt(pos) - 48);
        pos++;
    }
    if (pos >= s.length) return null;  // truncated — no closing '"'
    pos++;  // skip closing '"'
    return { value: neg ? -v : v, endPos: pos };
}

// Parse bool at pos ('t'=true, 'f'=false). Returns {value: bool, endPos}.
function parseBool(s, pos) {
    if (pos >= s.length) return null;
    if (s[pos] === 't') return { value: true, endPos: pos + 4 };
    if (s[pos] === 'f') return { value: false, endPos: pos + 5 };
    return null;
}

// Legacy parseDecimal for comparison section (takes bare string, no position tracking)
function parseDecimal(s) {
    if (s.startsWith('"')) s = s.slice(1);
    if (s.endsWith('"')) s = s.slice(0, -1);
    let neg = false;
    let i = 0;
    if (s[i] === '-') { neg = true; i++; }
    let v = 0n;
    for (; i < s.length; i++) {
        if (s[i] === '.') continue;
        if (s[i] >= '0' && s[i] <= '9')
            v = v * 10n + BigInt(s.charCodeAt(i) - 48);
    }
    return neg ? -v : v;
}

// ============================================================================
// Section 3: Stream Classification
// Mirrors classify_stream() — line 148
// ============================================================================

function classifyStream(name) {
    if (name.endsWith('aggTrade')) return STREAM_AGG_TRADE;
    const idx = name.indexOf('@depth');
    if (idx >= 0) {
        const after = name[idx + 6];
        if (after === '@') return STREAM_DEPTH_DIFF;
        if (after >= '0' && after <= '9') return STREAM_DEPTH_PARTIAL;
    }
    return STREAM_UNKNOWN;
}

// ============================================================================
// Section 4: decodeEssential
// Mirrors BinanceUSDMJsonDecoder::decode_essential() — lines 234-289
// Extracts stream type, seq, event_time from combined stream wrapper.
// Returns { valid, msgType, seq, eventTimeMs, resumePos } or { valid: false }.
// ============================================================================

function decodeEssential(payload) {
    const result = { valid: false, msgType: 0, seq: 0n, eventTimeMs: 0n, txnTimeMs: 0n, resumePos: 0 };

    // Find first '"' — start of "stream" key
    let p = 0;
    while (p < payload.length && payload[p] !== '"') p++;
    if (p >= payload.length) return result;

    // Skip "stream" key, get value
    p = toValue(payload, p);
    if (p === -1 || p >= payload.length || payload[p] !== '"') return result;

    // Extract stream name
    const nameStart = p + 1;
    const nameEnd = skipString(payload, p);
    if (nameEnd === -1) return result;
    const streamName = payload.slice(nameStart, nameEnd - 1);
    const streamType = classifyStream(streamName);
    if (streamType === STREAM_UNKNOWN) return result;

    result.msgType = streamType;

    // Skip comma, advance to "data" field
    p = nameEnd;
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;
    if (p >= payload.length || payload[p] !== '"') return result;

    // Skip "data" key to get to '{' of data object
    p = toValue(payload, p);
    if (p === -1 || p >= payload.length) return result;

    // p at '{' of data object
    if (payload[p] !== '{') return result;
    p++;
    while (p < payload.length && payload[p] === ' ') p++;

    switch (streamType) {
    case STREAM_AGG_TRADE: {
        // e(skip), E(extract), next(skip), next(extract=seq)
        // Position-agnostic: actual order may be e,E,a,s or e,E,s,a
        // Mirrors C++ lines 251-270
        p = skipField(payload, p);       // skip "e"
        if (p === -1) return result;

        p = toValue(payload, p);         // "E" value
        if (p === -1) return result;
        const eRes = parseInt64(payload, p);
        if (!eRes) return result;
        result.eventTimeMs = eRes.value;
        p = eRes.endPos;
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

        p = skipField(payload, p);       // skip next field (may be "a" or "s")
        if (p === -1) return result;

        p = toValue(payload, p);         // extract next field
        if (p === -1) return result;
        const seqRes = parseInt64(payload, p);
        if (seqRes) {
            result.seq = seqRes.value;
            p = seqRes.endPos;
        } else {
            // Hit a string field — skip past it
            p = skipValue(payload, p);
            if (p === -1) return result;
        }
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

        // Fallback: if positional parse got 0, scan for "a": (lines 259-268)
        if (result.seq === 0n) {
            for (let a = 0; a + 4 < payload.length; a++) {
                if (payload[a] === '"' && payload[a+1] === 'a' && payload[a+2] === '"' && payload[a+3] === ':') {
                    let ap = a + 4;
                    while (ap < payload.length && payload[ap] === ' ') ap++;
                    const fallback = parseInt64(payload, ap);
                    if (fallback) result.seq = fallback.value;
                    break;
                }
            }
        }

        result.resumePos = p;
        result.valid = true;
        break;
    }

    case STREAM_DEPTH_PARTIAL:
    case STREAM_DEPTH_DIFF: {
        // Field order: e(skip), E(extract), T(extract), s(skip), U(skip), u(extract=seq)
        // Mirrors lines 273-284
        p = skipField(payload, p);   // skip "e"
        if (p === -1) return result;

        p = toValue(payload, p);     // "E" value
        if (p === -1) return result;
        const eRes = parseInt64(payload, p);
        if (!eRes) return result;
        result.eventTimeMs = eRes.value;
        p = eRes.endPos;
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

        p = toValue(payload, p);     // "T" value
        if (p === -1) return result;
        const tRes = parseInt64(payload, p);
        if (!tRes) return result;
        result.txnTimeMs = tRes.value;
        p = tRes.endPos;
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

        p = skipField(payload, p);   // skip "s"
        if (p === -1) return result;
        p = skipField(payload, p);   // skip "U"
        if (p === -1) return result;

        p = toValue(payload, p);     // "u" value
        if (p === -1) return result;
        const uRes = parseInt64(payload, p);
        if (!uRes) return result;
        result.seq = uRes.value;
        p = uRes.endPos;
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

        result.resumePos = p;
        result.valid = true;
        break;
    }
    default:
        throw new Error(`decodeEssential: unknown streamType ${streamType}`);
    }
    return result;
}

// ============================================================================
// Section 5: Exchange-Specific Remaining-Field Parsers
// ============================================================================

// Parse aggTrade remaining fields after decode_essential's resume position.
// Mirrors parse_agg_trade_remaining() — lines 303-335
// Returns { valid, priceMantissa, qtyMantissa, tradeTimeMs, buyerIsMaker }
function parseAggTradeRemaining(payload, startPos) {
    const r = { valid: false, priceMantissa: 0n, qtyMantissa: 0n, tradeTimeMs: 0n, buyerIsMaker: false };
    let p = startPos;

    // Field 5: "p" (price string)
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    const pRes = parseDecStr(payload, p);
    if (!pRes) return r;
    r.priceMantissa = pRes.value;
    p = pRes.endPos;
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

    // Field 6: "q" (quantity string)
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    const qRes = parseDecStr(payload, p);
    if (!qRes) return r;
    r.qtyMantissa = qRes.value;
    p = qRes.endPos;
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

    // Field 7: "nq" — skip
    if (p >= payload.length || payload[p] !== '"') return r;
    p = skipField(payload, p);
    if (p === -1) return r;

    // Field 8: "f" — skip
    if (p >= payload.length || payload[p] !== '"') return r;
    p = skipField(payload, p);
    if (p === -1) return r;

    // Field 9: "l" — skip
    if (p >= payload.length || payload[p] !== '"') return r;
    p = skipField(payload, p);
    if (p === -1) return r;

    // Field 10: "T" (trade time)
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    const tRes = parseInt64(payload, p);
    if (!tRes) return r;
    r.tradeTimeMs = tRes.value;
    p = tRes.endPos;
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

    // Field 11: "m" (buyer is maker)
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    const mRes = parseBool(payload, p);
    if (!mRes) return r;
    r.buyerIsMaker = mRes.value;

    r.valid = true;
    return r;
}

// Parse depth remaining fields after decode_essential's resume position.
// Mirrors parse_depth_remaining() — lines 345-363
// Returns { valid, bidsArrayPos, asksArrayPos }
function parseDepthRemaining(payload, startPos) {
    const r = { valid: false, bidsArrayPos: -1, asksArrayPos: -1 };
    let p = startPos;

    // Field 7: "pu" — skip
    if (p >= payload.length || payload[p] !== '"') return r;
    p = skipField(payload, p);
    if (p === -1) return r;

    // Field 8: "b" (bids array) — locate
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    r.bidsArrayPos = p;
    p = skipValue(payload, p);
    if (p === -1) return r;
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ')) p++;

    // Field 9: "a" (asks array) — locate
    if (p >= payload.length || payload[p] !== '"') return r;
    p = toValue(payload, p);
    if (p === -1) return r;
    r.asksArrayPos = p;

    r.valid = true;
    return r;
}

// Parse [["price","qty"],...] levels incrementally.
// Mirrors parse_levels_streaming() — lines 654-728
// startOffset is byte offset into payload. buf is output array.
// Each level's inner ["p","q"] must be fully available before committing.
// On truncation mid-level, reverts to level start.
// Returns { newLevels: [{price, qty, action, isBid}], resumeOffset, arrayDone }
function parseLevelsStreaming(payload, startOffset, isAsk, maxLevels) {
    const result = { newLevels: [], resumeOffset: startOffset, arrayDone: false };

    let p = startOffset;
    // Caller must have advanced past outer '[' — startOffset should
    // point inside the array (first element or whitespace/comma).

    while (p < payload.length && result.newLevels.length < maxLevels) {
        // Skip whitespace/commas
        while (p < payload.length && (payload[p] === ',' || payload[p] === ' ' || payload[p] === '\n' || payload[p] === '\r')) p++;
        if (p >= payload.length) break;

        // Check for end of array
        if (payload[p] === ']') {
            result.arrayDone = true;
            result.resumeOffset = p + 1;
            return result;
        }

        // Save position for revert on truncation
        const levelStart = p;

        // Expect inner '['
        if (payload[p] !== '[') break;
        p++;

        // Parse price string: find opening '"'
        while (p < payload.length && payload[p] !== '"') p++;
        if (p >= payload.length) { result.resumeOffset = levelStart; return result; }
        const priceRes = parseDecStr(payload, p);
        if (!priceRes) { result.resumeOffset = levelStart; return result; }
        p = priceRes.endPos;

        // Skip comma between price and qty, find '"'
        while (p < payload.length && payload[p] !== '"') p++;
        if (p >= payload.length) { result.resumeOffset = levelStart; return result; }
        const qtyRes = parseDecStr(payload, p);
        if (!qtyRes) { result.resumeOffset = levelStart; return result; }
        p = qtyRes.endPos;

        // Find closing ']' of inner array
        while (p < payload.length && payload[p] !== ']') p++;
        if (p >= payload.length) { result.resumeOffset = levelStart; return result; }
        p++;  // skip ']'

        // Commit this level — qty=0 → DELETE, else UPDATE (line 708-710)
        const action = qtyRes.value === 0n ? ACTION_DELETE : ACTION_UPDATE;
        result.newLevels.push({
            price: priceRes.value,
            qty: qtyRes.value,
            action: action,
            flags: isAsk ? FLAG_SIDE_ASK : 0,
        });
    }

    // Update resume offset to current position
    result.resumeOffset = p;

    // Check if next non-whitespace is ']' (line 720-725)
    while (p < payload.length && (payload[p] === ',' || payload[p] === ' ' || payload[p] === '\n' || payload[p] === '\r')) p++;
    if (p < payload.length && payload[p] === ']') {
        result.arrayDone = true;
        result.resumeOffset = p + 1;
    }

    return result;
}

// ============================================================================
// Section 6: ConnectionParseContext
// Per-connection streaming parse state.
// Mirrors JsonParseState (lines 609-640)
// ============================================================================

const PHASE_IDLE           = 0;
const PHASE_HEADER_PARSED  = 1;  // decode_essential done, metadata saved, dedup passed
const PHASE_BIDS_PARSING   = 2;  // parsing bid levels
const PHASE_ASKS_PARSING   = 3;  // parsing ask levels
const PHASE_DONE           = 4;  // fully parsed, skip on subsequent fragments

class ConnectionParseContext {
    constructor(connId) {
        this.connId = connId;
        this.reset();
    }

    reset() {
        this.accumulatedPayload = '';
        this.phase = PHASE_IDLE;
        this.streamType = STREAM_UNKNOWN;
        this.seq = 0n;
        this.eventTimeMs = 0n;
        this.resumeOffset = 0;
        this.deltaBuf = [];           // accumulated DeltaEntry-like objects
        this.snapshotBidCount = 0;    // bids in deltaBuf (for snapshot bid/ask split)
        this.bidsCount = 0;
        this.asksCount = 0;
        this.flushCount = 0;          // depth flush counter (for CONTINUATION flag)
        this.deduped = false;         // set when initial dedup fires DONE
        this.isFragmented = false;
        this.fragmentOpcode = 0;
    }
}

// ============================================================================
// Section 7: MktEventBuilder — Unified, exchange-agnostic event generator
// Owns dedup state and trade merge buffer. Does NOT know about JSON or Binance.
// ============================================================================

class MktEventBuilder {
    constructor(opts = {}) {
        // Dedup counters per domain
        this.lastBookSeq = -1n;     // shared by BOOK_SNAPSHOT + BOOK_DELTA
        this.lastTradeSeq = -1n;    // TRADE_ARRAY only

        // Trade merge buffer (mirrors lines 1012-1018)
        this.pendingTrades = [];
        this.hasPendingTrades = false;
        this.pendingTradesMaxId = -1n;
        this.pendingTradesConnId = -1;
        this.pendingTradesEventTsNs = 0n;

        // Output
        this.events = [];
        this.onEvent = opts.onEvent || null;
    }

    _pushEvent(event) {
        this.events.push(event);
        if (this.onEvent) this.onEvent(event);
    }

    // --- Dedup checks (return true if should SKIP) ---

    // Trade dedup: seq <= effective trade id (line 1073)
    // Must consider pending buffer when checking (lines 1070-1072)
    isTradeDuplicate(seq) {
        const effTid = this.hasPendingTrades
            ? (this.lastTradeSeq > this.pendingTradesMaxId ? this.lastTradeSeq : this.pendingTradesMaxId)
            : this.lastTradeSeq;
        return seq <= effTid;
    }

    // Book dedup: seq <= last_book_seq (line 1101)
    isBookDuplicate(seq) {
        return seq <= this.lastBookSeq;
    }

    // --- Event builders ---

    // Buffer a trade into the merge buffer.
    // parsedTrade: { priceMantissa, qtyMantissa, tradeTimeMs, tradeId, buyerIsMaker }
    // Scale factors applied here at buffer time (matching C++ trade_streaming_continue line 744-745)
    bufferTrade(connId, seq, eventTsNs, parsedTrade) {
        // Connection change → flush (line 750-751)
        if (this.hasPendingTrades && this.pendingTradesConnId !== connId) {
            this.flushPendingTrades();
        }

        // Buffer full → flush (line 762)
        if (this.pendingTrades.length >= MAX_TRADES) {
            this.flushPendingTrades();
        }

        this.hasPendingTrades = true;
        this.pendingTradesConnId = connId;
        this.pendingTradesEventTsNs = eventTsNs;
        if (seq > this.pendingTradesMaxId) {
            this.pendingTradesMaxId = seq;
        }

        // buyer_is_maker → flags: m=true → 0, m=false → IS_BUYER (line 774)
        const flags = parsedTrade.buyerIsMaker ? 0 : FLAG_IS_BUYER;

        this.pendingTrades.push({
            price: parsedTrade.priceMantissa * PRICE_SCALE,
            qty: parsedTrade.qtyMantissa * QTY_SCALE,
            trade_time_ns: parsedTrade.tradeTimeMs * 1000000n,
            trade_id: seq,
            flags: flags,
        });
    }

    // Emit BOOK_SNAPSHOT from accumulated bids + asks.
    // bids/asks are arrays of {price, qty} — raw mantissa, scale applied here (lines 838-840).
    emitBookSnapshot(connId, seq, eventTsNs, bids, asks, flushCount = 0, isFinal = false) {
        const flags = EVT_FLAG_SNAPSHOT
            | (flushCount > 0 ? EVT_FLAG_CONTINUATION : 0)
            | (isFinal ? EVT_FLAG_LAST_IN_BATCH : 0)
            | (connId << EVT_FLAG_CONN_ID_SHIFT);
        this._pushEvent({
            type: 'BOOK_SNAPSHOT',
            seq: seq,
            event_ts_ns: eventTsNs,
            count: bids.length,
            count2: asks.length,
            conn_id: connId,
            flags: flags,
            bids: bids.map(b => ({ price: b.price * PRICE_SCALE, qty: b.qty * QTY_SCALE })),
            asks: asks.map(a => ({ price: a.price * PRICE_SCALE, qty: a.qty * QTY_SCALE })),
        });
    }

    // Emit BOOK_DELTA(s) from delta array.
    // deltas: array of {price, qty, action, flags} — raw mantissa, scale applied here (lines 810-812).
    // Chunks at MAX_DELTAS if needed (line 903).
    emitBookDelta(connId, seq, eventTsNs, deltas, flushCount = 0, isFinal = false) {
        const evtFlags = (flushCount > 0 ? EVT_FLAG_CONTINUATION : 0)
            | (isFinal ? EVT_FLAG_LAST_IN_BATCH : 0)
            | (connId << EVT_FLAG_CONN_ID_SHIFT);
        for (let i = 0; i < deltas.length; i += MAX_DELTAS) {
            const chunk = deltas.slice(i, i + MAX_DELTAS);
            this._pushEvent({
                type: 'BOOK_DELTA',
                seq: seq,
                event_ts_ns: eventTsNs,
                count: chunk.length,
                conn_id: connId,
                flags: evtFlags,
                deltas: chunk.map(d => ({
                    price: d.price * PRICE_SCALE,
                    qty: d.qty * QTY_SCALE,
                    action: d.action,
                    flags: d.flags,
                })),
            });
        }
    }

    // --- Flush triggers ---

    // Flush pending trades into a TRADE_ARRAY event.
    // seq = last trade's trade_id (line 1164).
    // Scale already applied at bufferTrade time.
    flushPendingTrades() {
        if (!this.hasPendingTrades || this.pendingTrades.length === 0) return;
        this.hasPendingTrades = false;

        const trades = this.pendingTrades.slice();
        this._pushEvent({
            type: 'TRADE_ARRAY',
            seq: trades[trades.length - 1].trade_id,   // last trade's id (line 1164)
            event_ts_ns: this.pendingTradesEventTsNs,
            count: trades.length,
            conn_id: this.pendingTradesConnId,
            flags: (this.pendingTradesConnId << EVT_FLAG_CONN_ID_SHIFT),
            trades: trades,
        });

        // Update global dedup after flush (line 1159)
        if (this.pendingTradesMaxId > this.lastTradeSeq) {
            this.lastTradeSeq = this.pendingTradesMaxId;
        }
        this.pendingTrades = [];
        this.pendingTradesMaxId = -1n;
    }

    // Flush trades before processing depth (line 1096)
    flushTradesBeforeDepth() {
        this.flushPendingTrades();
    }

    // Batch end: flush any remaining trades (line 1132-1134)
    onBatchEnd() {
        this.flushPendingTrades();
    }

}

// ============================================================================
// Section 8: BinanceUSDMVerifier — Orchestrator
// Per-connection contexts + MktEventBuilder. Processes WSFrameInfo records.
// ============================================================================

class BinanceUSDMVerifier {
    constructor(opts = {}) {
        this.connCtx = {};  // connId → ConnectionParseContext
        this.verbose = opts.verbose || false;
        this.builder = new MktEventBuilder({
            onEvent: this.verbose ? (ev) => console.log(`[EVENT] ${formatEvent(ev)}`) : null,
        });
    }

    get events() { return this.builder.events; }

    getOrCreateCtx(connId) {
        if (!this.connCtx[connId]) {
            this.connCtx[connId] = new ConnectionParseContext(connId);
        }
        return this.connCtx[connId];
    }

    processFrame(frame) {
        const { conn_id, opcode, flags, payload } = frame;
        const isLastInBatch = !!(flags & WS_FLAG_LAST_IN_BATCH);

        // Skip non-data opcodes (PING=9, PONG=10, CLOSE=8)
        if (opcode !== 1 && opcode !== 2 && opcode !== 0) {
            if (isLastInBatch) this.builder.onBatchEnd();
            return;
        }

        const isFragmented = !!(flags & WS_FLAG_FRAGMENTED);
        const isLastFragment = !!(flags & WS_FLAG_LAST_FRAGMENT);
        const ctx = this.getOrCreateCtx(conn_id);

        if (!isFragmented) {
            // Complete, unfragmented message
            ctx.accumulatedPayload = payload;
            ctx.isFragmented = false;
            this.onWsData(ctx, conn_id, ctx.accumulatedPayload);
            ctx.reset();
        } else {
            // Fragment handling
            if (opcode === 1 || opcode === 2) {
                // First fragment of a new message (TEXT or BINARY)
                ctx.accumulatedPayload = payload;
                ctx.isFragmented = true;
                ctx.fragmentOpcode = opcode;
                // Try streaming parse on first fragment
                this.onWsData(ctx, conn_id, ctx.accumulatedPayload);
            } else if (opcode === 0) {
                // Continuation frame — append and resume
                ctx.accumulatedPayload += payload;
                this.onWsData(ctx, conn_id, ctx.accumulatedPayload);
            }

            if (isLastFragment) {
                // Message complete — final parse + reset
                // (onWsData already called above with full payload)
                ctx.reset();
            }
        }

        if (isLastInBatch) this.builder.onBatchEnd();
    }

    onWsData(ctx, ci, payload) {
        // If phase is DONE, skip (already fully parsed, line 1043)
        if (ctx.phase === PHASE_DONE) return;

        // Resume in-progress streaming parse (line 1028)
        if (ctx.phase !== PHASE_IDLE) {
            // Re-check dedup: another connection may have superseded while streaming
            if (ctx.streamType === STREAM_AGG_TRADE) {
                if (this.builder.isTradeDuplicate(ctx.seq)) {
                    ctx.deduped = true;
                    ctx.phase = PHASE_DONE;
                    return;
                }
            } else if (ctx.streamType === STREAM_DEPTH_PARTIAL || ctx.streamType === STREAM_DEPTH_DIFF) {
                if (ctx.seq < this.builder.lastBookSeq) {
                    ctx.deduped = true;
                    ctx.phase = PHASE_DONE;
                    return;
                }
            }

            if (ctx.streamType === STREAM_AGG_TRADE)
                this.tradeStreamingContinue(ctx, ci, payload);
            else if (ctx.streamType === STREAM_DEPTH_PARTIAL || ctx.streamType === STREAM_DEPTH_DIFF)
                this.depthStreamingContinue(ctx, ci, payload);
            else
                throw new Error(`onWsData resume: unknown streamType ${ctx.streamType}`);
            return;
        }

        // Stage 1: decode essential (line 1055)
        const e = decodeEssential(payload);
        if (!e.valid) return;

        switch (e.msgType) {
        case STREAM_AGG_TRADE: {
            // Stage 4: early dedup by agg_trade_id (line 1073)
            if (this.builder.isTradeDuplicate(e.seq)) {
                ctx.deduped = true;
                ctx.phase = PHASE_DONE;
                return;
            }

            // Initialize streaming state (lines 1080-1086)
            ctx.phase = PHASE_HEADER_PARSED;
            ctx.streamType = e.msgType;
            ctx.seq = e.seq;
            ctx.eventTimeMs = e.eventTimeMs;
            ctx.resumeOffset = e.resumePos;

            this.tradeStreamingContinue(ctx, ci, payload);
            break;
        }

        case STREAM_DEPTH_PARTIAL:
        case STREAM_DEPTH_DIFF: {
            // Flush pending trades before depth (line 1096)
            this.builder.flushTradesBeforeDepth();

            // Dedup (line 1101)
            if (this.builder.isBookDuplicate(e.seq)) {
                ctx.deduped = true;
                ctx.phase = PHASE_DONE;
                return;
            }
            this.builder.lastBookSeq = e.seq;

            // Initialize streaming state (lines 1108-1117)
            ctx.phase = PHASE_HEADER_PARSED;
            ctx.streamType = e.msgType;
            ctx.seq = e.seq;
            ctx.eventTimeMs = e.eventTimeMs;
            ctx.resumeOffset = e.resumePos;
            ctx.deltaBuf = [];
            ctx.snapshotBidCount = 0;
            ctx.bidsCount = 0;
            ctx.asksCount = 0;

            this.depthStreamingContinue(ctx, ci, payload);
            break;
        }
        default:
            throw new Error(`onWsData: unknown msgType ${e.msgType}`);
        }
    }

    // AGG_TRADE streaming: retry parse on each fragment (lines 733-797)
    tradeStreamingContinue(ctx, ci, payload) {
        if (ctx.phase === PHASE_DONE) return;

        const r = parseAggTradeRemaining(payload, ctx.resumeOffset);
        if (!r.valid) return;  // wait for more data

        const eventTsNs = ctx.eventTimeMs * 1000000n;

        // Build parsed trade and pass to builder
        this.builder.bufferTrade(ci, ctx.seq, eventTsNs, {
            priceMantissa: r.priceMantissa,
            qtyMantissa: r.qtyMantissa,
            tradeTimeMs: r.tradeTimeMs,
            tradeId: ctx.seq,
            buyerIsMaker: r.buyerIsMaker,
        });

        ctx.phase = PHASE_DONE;
    }

    // DEPTH streaming: phase state machine (lines 858-991)
    depthStreamingContinue(ctx, ci, payload) {
        if (ctx.phase === PHASE_DONE) return;

        const isSnapshot = (ctx.streamType === STREAM_DEPTH_PARTIAL);

        // HEADER_PARSED → locate bids array (lines 869-875)
        if (ctx.phase === PHASE_HEADER_PARSED) {
            const r = parseDepthRemaining(payload, ctx.resumeOffset);
            if (!r.valid) return;  // need more data
            // Found bids array — skip outer '[' and transition to BIDS_PARSING
            ctx.resumeOffset = r.bidsArrayPos + 1;  // +1 to skip '['
            ctx.phase = PHASE_BIDS_PARSING;
        }

        // BIDS_PARSING (lines 878-923)
        if (ctx.phase === PHASE_BIDS_PARSING) {
            const maxBids = isSnapshot ? SNAPSHOT_HALF : MAX_DELTAS;

            while (ctx.phase === PHASE_BIDS_PARSING) {
                let remaining = maxBids - ctx.deltaBuf.length;
                if (remaining <= 0) {
                    if (isSnapshot) {
                        // Snapshot: skip remaining bids, find ']' then transition (lines 885-900)
                        let p = ctx.resumeOffset;
                        let depth = 0;
                        while (p < payload.length) {
                            if (payload[p] === '"') {
                                const np = skipString(payload, p);
                                if (np === -1) return;  // truncated
                                p = np; continue;
                            }
                            if (payload[p] === '[') { depth++; p++; continue; }
                            if (payload[p] === ']') { if (depth === 0) { p++; break; } depth--; p++; continue; }
                            p++;
                        }
                        if (p >= payload.length && depth >= 0) return;  // truncated mid-skip
                        ctx.resumeOffset = p;
                        ctx.snapshotBidCount = ctx.deltaBuf.length;
                        ctx.phase = PHASE_ASKS_PARSING;
                        break;
                    }
                    // Delta: flush current chunk and continue (line 903)
                    this.flushDeltaChunk(ctx, ci);
                    remaining = MAX_DELTAS;
                }

                const sr = parseLevelsStreaming(payload, ctx.resumeOffset, false, remaining);
                ctx.bidsCount += sr.newLevels.length;
                ctx.deltaBuf.push(...sr.newLevels);
                ctx.resumeOffset = sr.resumeOffset;

                if (sr.arrayDone) {
                    // Bids done, transition to asks
                    ctx.snapshotBidCount = ctx.deltaBuf.length;
                    ctx.phase = PHASE_ASKS_PARSING;
                    break;
                }
                if (sr.newLevels.length === 0) return;  // truncated, wait for more data
            }
        }

        // ASKS_PARSING (lines 926-990)
        if (ctx.phase === PHASE_ASKS_PARSING) {
            // Find "a":[ if needed (lines 928-940)
            let p = ctx.resumeOffset;
            while (p < payload.length && (payload[p] === ',' || payload[p] === ' ' || payload[p] === '\n' || payload[p] === '\r')) p++;
            if (p >= payload.length) return;
            if (payload[p] === '"') {
                // Skip "a" key and ':' to get to array, then skip outer '['
                p = toValue(payload, p);
                if (p === -1 || p >= payload.length) return;
                if (payload[p] === '[') p++;
                if (p >= payload.length) return;
                ctx.resumeOffset = p;
            }

            const maxAsks = isSnapshot ? SNAPSHOT_HALF : MAX_DELTAS;

            while (ctx.phase === PHASE_ASKS_PARSING) {
                let remainingAsks;
                if (isSnapshot) {
                    const currentAsks = ctx.deltaBuf.length - ctx.snapshotBidCount;
                    remainingAsks = currentAsks < SNAPSHOT_HALF ? SNAPSHOT_HALF - currentAsks : 0;
                } else {
                    remainingAsks = ctx.deltaBuf.length < MAX_DELTAS
                        ? MAX_DELTAS - ctx.deltaBuf.length : 0;
                }

                if (remainingAsks === 0) {
                    if (isSnapshot) {
                        // Snapshot full: publish immediately (line 960-962)
                        this.flushSnapshotChunk(ctx, ci, true);
                        ctx.phase = PHASE_DONE;
                        return;
                    }
                    // Delta: flush and continue (line 965)
                    this.flushDeltaChunk(ctx, ci);
                    continue;
                }

                const sr = parseLevelsStreaming(payload, ctx.resumeOffset, true, remainingAsks);
                ctx.asksCount += sr.newLevels.length;
                ctx.deltaBuf.push(...sr.newLevels);
                ctx.resumeOffset = sr.resumeOffset;

                if (sr.arrayDone) {
                    // Done parsing all asks (lines 977-986)
                    if (ctx.deltaBuf.length > 0) {
                        if (isSnapshot)
                            this.flushSnapshotChunk(ctx, ci, true);
                        else
                            this.flushDeltaChunk(ctx, ci, true);
                    }
                    ctx.phase = PHASE_DONE;
                    return;
                }
                if (sr.newLevels.length === 0) return;  // truncated, wait
            }
        }
    }

    // Flush accumulated delta_buf as BOOK_DELTA (lines 799-825)
    flushDeltaChunk(ctx, ci, isFinal = false) {
        if (ctx.deltaBuf.length === 0) return;
        const eventTsNs = ctx.eventTimeMs * 1000000n;
        // addBookDelta applies scale and chunks internally
        this.builder.emitBookDelta(ci, ctx.seq, eventTsNs, ctx.deltaBuf, ctx.flushCount, isFinal);
        ctx.flushCount++;
        ctx.deltaBuf = [];
    }

    // Flush accumulated delta_buf as BOOK_SNAPSHOT (lines 827-853)
    flushSnapshotChunk(ctx, ci, isFinal = false) {
        if (ctx.deltaBuf.length === 0) return;
        const eventTsNs = ctx.eventTimeMs * 1000000n;
        const bidN = ctx.snapshotBidCount;
        const bids = ctx.deltaBuf.slice(0, bidN);
        const asks = ctx.deltaBuf.slice(bidN);
        this.builder.emitBookSnapshot(ci, ctx.seq, eventTsNs, bids, asks, ctx.flushCount, isFinal);
        ctx.flushCount++;
        ctx.deltaBuf = [];
    }

    run(frames) {
        for (const frame of frames) {
            this.processFrame(frame);
        }
        // Final flush
        this.builder.flushPendingTrades();
    }
}

// ============================================================================
// Section 9: File I/O — Parse wsframes.txt and mktevents.txt
// ============================================================================

function unescapePayload(s) {
    let result = '';
    for (let i = 0; i < s.length; i++) {
        if (s[i] === '\\' && i + 1 < s.length) {
            switch (s[i + 1]) {
                case 't':  result += '\t'; i++; break;
                case 'n':  result += '\n'; i++; break;
                case 'r':  result += '\r'; i++; break;
                case '\\': result += '\\'; i++; break;
                case 'x':
                    if (i + 3 < s.length) {
                        result += String.fromCharCode(parseInt(s.substr(i + 2, 2), 16));
                        i += 3;
                    } else {
                        result += s[i];
                    }
                    break;
                default: result += s[i]; break;
            }
        } else {
            result += s[i];
        }
    }
    return result;
}

function parseFramesFile(path) {
    const lines = fs.readFileSync(path, 'utf8').split('\n').filter(l => l.length > 0);
    return lines.map((line, idx) => {
        const firstTab = line.indexOf('\t');
        const secondTab = line.indexOf('\t', firstTab + 1);
        const thirdTab = line.indexOf('\t', secondTab + 1);
        if (firstTab < 0 || secondTab < 0 || thirdTab < 0) {
            throw new Error(`Malformed line ${idx + 1}: ${line.slice(0, 60)}`);
        }
        return {
            conn_id: parseInt(line.slice(0, firstTab)),
            opcode:  parseInt(line.slice(firstTab + 1, secondTab)),
            flags:   parseInt(line.slice(secondTab + 1, thirdTab), 16),
            payload: unescapePayload(line.slice(thirdTab + 1)),
        };
    });
}

function parseEventLineBigInt(line) {
    // Quote known large-integer fields as strings before JSON.parse to avoid
    // double-precision loss (values > 2^53 lose low bits in IEEE 754).
    const safeLine = line.replace(
        /"(seq|event_ts_ns|trade_time_ns|trade_id|price|qty|bid_price|bid_qty|ask_price|ask_qty|event_time_ns|book_update_id)"\s*:\s*(-?\d+)/g,
        '"$1":"$2"'
    );
    const obj = JSON.parse(safeLine);
    function toBigInt(v) {
        if (v === undefined || v === null) return undefined;
        return BigInt(v);  // works for both string "123" and small numbers
    }
    if (obj.seq !== undefined) obj.seq = toBigInt(obj.seq);
    if (obj.event_ts_ns !== undefined) obj.event_ts_ns = toBigInt(obj.event_ts_ns);
    if (obj.trades) {
        for (const t of obj.trades) {
            t.price = toBigInt(t.price);
            t.qty = toBigInt(t.qty);
            t.trade_time_ns = toBigInt(t.trade_time_ns);
            t.trade_id = toBigInt(t.trade_id);
        }
    }
    if (obj.deltas) {
        for (const d of obj.deltas) {
            d.price = toBigInt(d.price);
            d.qty = toBigInt(d.qty);
        }
    }
    if (obj.bids) {
        for (const b of obj.bids) {
            b.price = toBigInt(b.price);
            b.qty = toBigInt(b.qty);
        }
    }
    if (obj.asks) {
        for (const a of obj.asks) {
            a.price = toBigInt(a.price);
            a.qty = toBigInt(a.qty);
        }
    }
    return obj;
}

function parseEventsFileBigInt(path) {
    const lines = fs.readFileSync(path, 'utf8').split('\n').filter(l => l.length > 0);
    return lines.map((line, idx) => {
        try {
            return parseEventLineBigInt(line);
        } catch (e) {
            throw new Error(`Failed to parse event line ${idx + 1}: ${e.message}`);
        }
    });
}

// ============================================================================
// Section 9b: formatEvent — verbose event formatter
// ============================================================================

function formatEvent(ev) {
    const f = ev.flags !== undefined ? ` flags=0x${ev.flags.toString(16)}` : '';
    switch (ev.type) {
        case 'TRADE_ARRAY': {
            const trades = ev.trades.map(t =>
                `${t.price}@${t.qty} id=${t.trade_id}`).join(', ');
            return `TRADE_ARRAY seq=${ev.seq} conn=${ev.conn_id} count=${ev.count}${f} [${trades}]`;
        }
        case 'BOOK_DELTA': {
            const acts = ['NEW','UPD','DEL'];
            const deltas = ev.deltas.map(d =>
                `${acts[d.action]}:${d.price}@${d.qty}`).join(', ');
            return `BOOK_DELTA seq=${ev.seq} conn=${ev.conn_id} count=${ev.count}${f} [${deltas}]`;
        }
        case 'BOOK_SNAPSHOT':
            return `BOOK_SNAPSHOT seq=${ev.seq} conn=${ev.conn_id} bids=${ev.count} asks=${ev.count2}${f}`;
        default:
            return `${ev.type} seq=${ev.seq}`;
    }
}

// ============================================================================
// Section 10: Comparison
// ============================================================================

function compareTrade(idx, tIdx, actual, expected) {
    const errors = [];
    if (actual.price !== BigInt(expected.price))
        errors.push(`  trade[${tIdx}].price: JS=${actual.price} C++=${expected.price}`);
    if (actual.qty !== BigInt(expected.qty))
        errors.push(`  trade[${tIdx}].qty: JS=${actual.qty} C++=${expected.qty}`);
    if (actual.trade_time_ns !== BigInt(expected.trade_time_ns))
        errors.push(`  trade[${tIdx}].trade_time_ns: JS=${actual.trade_time_ns} C++=${expected.trade_time_ns}`);
    if (actual.trade_id !== BigInt(expected.trade_id))
        errors.push(`  trade[${tIdx}].trade_id: JS=${actual.trade_id} C++=${expected.trade_id}`);
    if (actual.flags !== expected.flags)
        errors.push(`  trade[${tIdx}].flags: JS=${actual.flags} C++=${expected.flags}`);
    return errors;
}

function compareDelta(idx, dIdx, actual, expected) {
    const errors = [];
    if (actual.price !== BigInt(expected.price))
        errors.push(`  delta[${dIdx}].price: JS=${actual.price} C++=${expected.price}`);
    if (actual.qty !== BigInt(expected.qty))
        errors.push(`  delta[${dIdx}].qty: JS=${actual.qty} C++=${expected.qty}`);
    if (actual.action !== expected.action)
        errors.push(`  delta[${dIdx}].action: JS=${actual.action} C++=${expected.action}`);
    if (actual.flags !== expected.flags)
        errors.push(`  delta[${dIdx}].flags: JS=${actual.flags} C++=${expected.flags}`);
    return errors;
}

function compareLevel(idx, kind, lIdx, actual, expected) {
    const errors = [];
    if (actual.price !== BigInt(expected.price))
        errors.push(`  ${kind}[${lIdx}].price: JS=${actual.price} C++=${expected.price}`);
    if (actual.qty !== BigInt(expected.qty))
        errors.push(`  ${kind}[${lIdx}].qty: JS=${actual.qty} C++=${expected.qty}`);
    return errors;
}

function compareEvents(jsEvents, cppEvents) {
    let pass = 0;
    let fail = 0;
    let warn = 0;
    const failures = [];
    const warnings = [];

    const cppFiltered = cppEvents.filter(e => e.type !== 'SYSTEM_STATUS');

    // --- Book events: group by (seq, type) and compare aggregated content ---
    // JS and C++ may chunk differently but aggregated deltas/levels must match.
    const jsBooks = jsEvents.filter(e => e.type !== 'TRADE_ARRAY');
    const cppBooks = cppFiltered.filter(e => e.type !== 'TRADE_ARRAY');

    function buildGroups(events) {
        const groups = new Map();
        for (const e of events) {
            const k = `${e.seq}|${e.type}`;
            if (!groups.has(k)) groups.set(k, []);
            groups.get(k).push(e);
        }
        return groups;
    }

    const jsBookGroups = buildGroups(jsBooks);
    const cppBookGroups = buildGroups(cppBooks);

    const allBookKeys = [...new Set([...jsBookGroups.keys(), ...cppBookGroups.keys()])];
    allBookKeys.sort((a, b) => {
        const sa = BigInt(a.split('|')[0]), sb = BigInt(b.split('|')[0]);
        return sa < sb ? -1 : sa > sb ? 1 : 0;
    });

    for (const key of allBookKeys) {
        const jsGroup = jsBookGroups.get(key);
        const cppGroup = cppBookGroups.get(key);

        if (!jsGroup) continue;
        if (!cppGroup) {
            warnings.push(`seq=${key}: ${jsGroup.length} JS book events, no C++ match (sampling edge)`);
            warn++;
            continue;
        }

        const type = jsGroup[0].type;
        const errors = [];

        const jsTs = jsGroup[0].event_ts_ns;
        const cppTs = cppGroup[0].event_ts_ns;
        if (jsTs !== undefined && cppTs !== undefined && jsTs !== BigInt(cppTs))
            errors.push(`  event_ts_ns: JS=${jsTs} C++=${cppTs}`);

        if (type === 'BOOK_DELTA') {
            const jd = jsGroup.flatMap(e => e.deltas || []);
            const cd = cppGroup.flatMap(e => e.deltas || []);
            // Compare only the overlapping deltas
            const minLen = Math.min(jd.length, cd.length);
            for (let d = 0; d < minLen; d++) {
                errors.push(...compareDelta(0, d, jd[d], cd[d]));
            }
            // JS fewer than C++: sampling boundary truncation (warn, not fail)
            if (jd.length < cd.length && errors.length === 0) {
                warnings.push(`Book seq=${key}: JS truncated at sampling boundary (JS=${jd.length} C++=${cd.length} deltas)`);
                warn++;
                pass++;
                continue;
            }
            if (jd.length !== cd.length)
                errors.push(`  total_deltas: JS=${jd.length} C++=${cd.length}`);
            for (let d = minLen; d < jd.length; d++) {
                errors.push(`  delta[${d}]: EXTRA in JS`);
            }
        } else if (type === 'BOOK_SNAPSHOT') {
            const jb = jsGroup.flatMap(e => e.bids || []);
            const cb = cppGroup.flatMap(e => e.bids || []);
            const ja = jsGroup.flatMap(e => e.asks || []);
            const ca = cppGroup.flatMap(e => e.asks || []);
            if (jb.length !== cb.length)
                errors.push(`  total_bids: JS=${jb.length} C++=${cb.length}`);
            for (let b = 0; b < Math.max(jb.length, cb.length); b++) {
                if (b >= jb.length) { errors.push(`  bids[${b}]: MISSING from JS`); continue; }
                if (b >= cb.length) { errors.push(`  bids[${b}]: EXTRA in JS`); continue; }
                errors.push(...compareLevel(0, 'bids', b, jb[b], cb[b]));
            }
            if (ja.length !== ca.length)
                errors.push(`  total_asks: JS=${ja.length} C++=${ca.length}`);
            for (let a = 0; a < Math.max(ja.length, ca.length); a++) {
                if (a >= ja.length) { errors.push(`  asks[${a}]: MISSING from JS`); continue; }
                if (a >= ca.length) { errors.push(`  asks[${a}]: EXTRA in JS`); continue; }
                errors.push(...compareLevel(0, 'asks', a, ja[a], ca[a]));
            }
        }

        if (errors.length > 0) {
            failures.push(`Book seq=${key} (${type}, JS:${jsGroup.length} C++:${cppGroup.length} events):\n${errors.join('\n')}`);
            fail++;
        } else {
            pass++;
        }
    }

    // --- Trade events: match individual trades by trade_id ---
    // JS and C++ may batch trades differently (different batch boundaries),
    // so batch seq (= last trade_id) can differ. Compare individual trades instead.
    const jsTradeMap = new Map();   // trade_id → trade object
    for (const ev of jsEvents.filter(e => e.type === 'TRADE_ARRAY'))
        for (const t of ev.trades || [])
            jsTradeMap.set(t.trade_id, t);

    const cppTradeMap = new Map();
    for (const ev of cppFiltered.filter(e => e.type === 'TRADE_ARRAY'))
        for (const t of ev.trades || [])
            cppTradeMap.set(t.trade_id, t);

    const allTradeIds = [...new Set([...jsTradeMap.keys(), ...cppTradeMap.keys()])];
    allTradeIds.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    let tradeMatched = 0, tradeUnmatched = 0;
    for (const tid of allTradeIds) {
        const jt = jsTradeMap.get(tid);
        const ct = cppTradeMap.get(tid);
        if (!jt) continue;  // C++ only — already filtered
        if (!ct) {
            tradeUnmatched++;
            continue;  // sampling edge — JS has trade, C++ doesn't
        }
        const errors = [];
        if (jt.price !== BigInt(ct.price))
            errors.push(`  price: JS=${jt.price} C++=${ct.price}`);
        if (jt.qty !== BigInt(ct.qty))
            errors.push(`  qty: JS=${jt.qty} C++=${ct.qty}`);
        if (jt.trade_time_ns !== BigInt(ct.trade_time_ns))
            errors.push(`  trade_time_ns: JS=${jt.trade_time_ns} C++=${ct.trade_time_ns}`);
        if (jt.flags !== ct.flags)
            errors.push(`  flags: JS=${jt.flags} C++=${ct.flags}`);

        if (errors.length > 0) {
            failures.push(`Trade id=${tid}:\n${errors.join('\n')}`);
            fail++;
        } else {
            tradeMatched++;
        }
    }
    if (tradeMatched > 0) pass += tradeMatched;
    if (tradeUnmatched > 0)
        warnings.push(`${tradeUnmatched} JS trades with no C++ match (sampling edge)`);

    return { pass, fail, warn, failures, warnings };
}

// ============================================================================
// Section 11: Main
// ============================================================================

function formatFrameMeta(frame) {
    const flagNames = [];
    if (frame.flags & WS_FLAG_FIN) flagNames.push('FIN');
    if (frame.flags & WS_FLAG_FRAGMENTED) flagNames.push('FRAG');
    if (frame.flags & WS_FLAG_LAST_FRAGMENT) flagNames.push('LAST_FRAG');
    if (frame.flags & WS_FLAG_DISCARD_EARLY) flagNames.push('DISCARD');
    if (frame.flags & WS_FLAG_MERGED) flagNames.push('MERGED');
    if (frame.flags & WS_FLAG_LAST_IN_BATCH) flagNames.push('BATCH_END');
    const opNames = { 0: 'CONT', 1: 'TEXT', 2: 'BIN', 8: 'CLOSE', 9: 'PING', 10: 'PONG' };
    const opStr = opNames[frame.opcode] || `OP${frame.opcode}`;
    return `conn=${frame.conn_id} ${opStr} flags=[${flagNames.join(',')}] len=${frame.payload.length}`;
}

function main() {
    const args = process.argv.slice(2);
    const verbose = args.includes('--verbose');
    const positional = args.filter(a => a !== '--verbose');
    if (positional.length < 2) {
        console.error('Usage: node mkt_verifer_binance_usdm.js [--verbose] <wsframes.txt> <mktevents.txt>');
        process.exit(1);
    }

    const framesPath = positional[0];
    const eventsPath = positional[1];

    console.log(`Reading frames from ${framesPath}...`);
    const frames = parseFramesFile(framesPath);
    console.log(`  ${frames.length} frames loaded`);

    console.log(`Reading expected events from ${eventsPath}...`);
    const expectedEvents = parseEventsFileBigInt(eventsPath);
    console.log(`  ${expectedEvents.length} events loaded`);

    console.log('Running JS reference parser...');
    const verifier = new BinanceUSDMVerifier({ verbose: false });  // don't use inline callback

    if (verbose) {
        // Process frame-by-frame: one metadata line, then produced events
        for (const frame of frames) {
            const prevCount = verifier.events.length;
            verifier.processFrame(frame);
            const newCount = verifier.events.length;

            console.log(`[FRAME] ${formatFrameMeta(frame)} | ${frame.payload}`);
            for (let i = prevCount; i < newCount; i++) {
                console.log(`  [EVENT] ${formatEvent(verifier.events[i])}`);
            }
        }
        verifier.builder.flushPendingTrades();
    } else {
        verifier.run(frames);
    }

    const jsEvents = verifier.events;
    console.log(`\n  ${jsEvents.length} JS events produced`);

    // Filter C++ events: keep only those whose seq or trade_id overlaps JS events.
    // Book events match by seq; trade events match by individual trade_id overlap.
    const jsBookSeqs = new Set(jsEvents.filter(e => e.type !== 'TRADE_ARRAY').map(e => e.seq));
    const jsTradeIds = new Set();
    for (const ev of jsEvents.filter(e => e.type === 'TRADE_ARRAY'))
        for (const t of ev.trades || [])
            jsTradeIds.add(t.trade_id);

    const cppNonStatus = expectedEvents.filter(e => e.type !== 'SYSTEM_STATUS');
    const cppMatched = cppNonStatus.filter(e => {
        if (e.type === 'TRADE_ARRAY') {
            // Include if any trade_id in this C++ event is in the JS set
            return (e.trades || []).some(t => jsTradeIds.has(t.trade_id));
        }
        return e.seq !== undefined && jsBookSeqs.has(e.seq);
    });
    const cppSkipped = cppNonStatus.length - cppMatched.length;
    console.log(`  ${cppNonStatus.length} C++ events (excluding SYSTEM_STATUS)`);
    if (cppSkipped > 0)
        console.log(`  ${cppSkipped} C++ events skipped (outside sampled frames)`);
    console.log(`  ${cppMatched.length} C++ events matched`);

    console.log('\nComparing...');
    const { pass, fail, warn, failures, warnings } = compareEvents(jsEvents, cppMatched);

    if (warnings.length > 0) {
        console.log(`\nWARNINGS (${warnings.length}):`);
        for (const w of warnings) console.log(w);
    }
    if (failures.length > 0) {
        console.log(`\nFAILURES (showing first ${Math.min(failures.length, 20)}):`);
        for (let i = 0; i < Math.min(failures.length, 20); i++) {
            console.log(failures[i]);
        }
        if (failures.length > 20) {
            console.log(`  ... and ${failures.length - 20} more`);
        }
    }

    const warnStr = warn > 0 ? `, ${warn} WARN` : '';
    console.log(`\nResult: ${pass} PASS, ${fail} FAIL${warnStr} (${jsEvents.length} JS events, ${cppNonStatus.length} C++ events)`);
    if (fail > 0) {
        console.log('FAIL');
        process.exit(1);
    } else {
        console.log('PASS');
        process.exit(0);
    }
}

// ============================================================================
// Section 12: Exports / Main Guard
// ============================================================================

if (require.main === module) {
    main();
} else {
    module.exports = {
        // Constants
        PRICE_SCALE, QTY_SCALE, MAX_TRADES, MAX_DELTAS, MAX_BOOK_LEVELS, SNAPSHOT_HALF,
        EVENT_BOOK_DELTA, EVENT_BOOK_SNAPSHOT, EVENT_TRADE_ARRAY, EVENT_SYSTEM_STATUS,
        ACTION_NEW, ACTION_UPDATE, ACTION_DELETE,
        FLAG_SIDE_ASK, FLAG_IS_BUYER,
        WS_FLAG_FIN, WS_FLAG_FRAGMENTED, WS_FLAG_LAST_FRAGMENT,
        WS_FLAG_DISCARD_EARLY, WS_FLAG_MERGED, WS_FLAG_LAST_IN_BATCH,
        STREAM_UNKNOWN, STREAM_AGG_TRADE, STREAM_DEPTH_PARTIAL, STREAM_DEPTH_DIFF,
        PHASE_IDLE, PHASE_HEADER_PARSED, PHASE_BIDS_PARSING, PHASE_ASKS_PARSING, PHASE_DONE,
        // Scanning primitives
        skipString, skipNumber, skipValue, skipField, toValue, parseInt64, parseDecStr, parseBool,
        parseDecimal,
        // Stream classification
        classifyStream,
        // Parsers
        decodeEssential, parseAggTradeRemaining, parseDepthRemaining, parseLevelsStreaming,
        // Formatting
        formatEvent,
        // Comparison
        parseEventLineBigInt, compareEvents, compareTrade, compareDelta, compareLevel,
        // Classes
        ConnectionParseContext, MktEventBuilder, BinanceUSDMVerifier,
    };
}
