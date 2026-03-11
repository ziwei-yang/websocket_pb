#!/usr/bin/env node
// tools/mkt_verifer_binance_usdm.test.js
// Comprehensive unit tests for the Binance USDM JSON streaming verifier.
// Uses Node 18+ built-in test runner: node --test tools/mkt_verifer_binance_usdm.test.js

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const V = require('./mkt_verifer_binance_usdm.js');

// ============================================================================
// Test Helpers
// ============================================================================

// Build a complete aggTrade combined-stream JSON payload.
// Field order: e, E, s, a, p, q, nq, f, l, T, m
function makeAggTradeJSON(a, E, p, q, T, m, { s = 'BTCUSDT', nq = '0', f = 0, l = 0 } = {}) {
    return JSON.stringify({
        stream: 'btcusdt@aggTrade',
        data: { e: 'aggTrade', E, s, a, p: String(p), q: String(q), nq: String(nq), f, l, T, m }
    });
}

// Build a depthDiff combined-stream JSON payload.
// Field order in data: e, E, T, s, U, u, pu, b, a
function makeDepthDiffJSON(u, E, bids, asks, { T = E, s = 'BTCUSDT', U = u, pu = u - 1, stream = 'btcusdt@depth@100ms' } = {}) {
    return JSON.stringify({
        stream: stream,
        data: { e: 'depthUpdate', E, T, s, U, u, pu, b: bids, a: asks }
    });
}

// Build a depth5 (partial/snapshot) combined-stream JSON payload.
// Field order in data: e, E, T, s, U, u, pu, b, a (same as diff for USDM futures)
function makeDepthPartialJSON(u, E, bids, asks, { T = E, s = 'BTCUSDT', U = u, pu = u - 1 } = {}) {
    return JSON.stringify({
        stream: 'btcusdt@depth5',
        data: { e: 'depthUpdate', E, T, s, U, u, pu, b: bids, a: asks }
    });
}

// Create a frame object matching the format processFrame expects.
function makeFrame(connId, payload, flags = V.WS_FLAG_FIN) {
    return { conn_id: connId, opcode: 1, flags: flags, payload: payload };
}

// Create a pair of fragmented frames by splitting payload at splitPos.
// Returns [firstFragment, lastFragment].
function makeFragmentedFrames(connId, payload, splitPos) {
    const frag1 = {
        conn_id: connId,
        opcode: 1,  // TEXT start
        flags: V.WS_FLAG_FRAGMENTED,
        payload: payload.slice(0, splitPos),
    };
    const frag2 = {
        conn_id: connId,
        opcode: 0,  // CONTINUATION
        flags: V.WS_FLAG_FRAGMENTED | V.WS_FLAG_LAST_FRAGMENT,
        payload: payload.slice(splitPos),
    };
    return [frag1, frag2];
}

// ============================================================================
// Test Group 1: parseDecimal
// ============================================================================

describe('parseDecimal', () => {
    it('"50123.40" → 5012340n', () => {
        assert.equal(V.parseDecimal('"50123.40"'), 5012340n);
    });
    it('"0.001" → 1n', () => {
        assert.equal(V.parseDecimal('"0.001"'), 1n);
    });
    it('"-123.45" → -12345n', () => {
        assert.equal(V.parseDecimal('"-123.45"'), -12345n);
    });
    it('"100" → 100n (no decimal point)', () => {
        assert.equal(V.parseDecimal('"100"'), 100n);
    });
    it('"97403.89" → 9740389n', () => {
        assert.equal(V.parseDecimal('"97403.89"'), 9740389n);
    });
});

// ============================================================================
// Test Group 2: classifyStream
// ============================================================================

describe('classifyStream', () => {
    it('aggTrade', () => {
        assert.equal(V.classifyStream('btcusdt@aggTrade'), V.STREAM_AGG_TRADE);
    });
    it('depth5', () => {
        assert.equal(V.classifyStream('btcusdt@depth5'), V.STREAM_DEPTH_PARTIAL);
    });
    it('depth20', () => {
        assert.equal(V.classifyStream('btcusdt@depth20'), V.STREAM_DEPTH_PARTIAL);
    });
    it('depth@100ms', () => {
        assert.equal(V.classifyStream('btcusdt@depth@100ms'), V.STREAM_DEPTH_DIFF_1);
    });
    it('depth@250ms', () => {
        assert.equal(V.classifyStream('btcusdt@depth@250ms'), V.STREAM_DEPTH_DIFF_2);
    });
    it('depth (no suffix, 250ms default)', () => {
        assert.equal(V.classifyStream('btcusdt@depth'), V.STREAM_DEPTH_DIFF_2);
    });
    it('unknown stream', () => {
        assert.equal(V.classifyStream('btcusdt@ticker'), V.STREAM_UNKNOWN);
    });
});

// ============================================================================
// Test Group 3: Scanning primitives
// ============================================================================

describe('Scanning primitives', () => {
    it('skipString — normal string', () => {
        const s = '"hello" rest';
        assert.equal(V.skipString(s, 0), 7);
    });
    it('skipString — escaped quote', () => {
        const s = '"he\\"llo" rest';
        assert.equal(V.skipString(s, 0), 9);
    });
    it('skipString — truncated returns -1', () => {
        assert.equal(V.skipString('"hello', 0), -1);
    });

    it('skipNumber — integer', () => {
        assert.equal(V.skipNumber('12345,', 0), 5);
    });
    it('skipNumber — decimal', () => {
        assert.equal(V.skipNumber('123.45,', 0), 6);
    });
    it('skipNumber — negative', () => {
        assert.equal(V.skipNumber('-99,', 0), 3);
    });

    it('skipField — simple field', () => {
        const s = '"key":123, "next"';
        const pos = V.skipField(s, 0);
        // Should be past "key":123, and any trailing comma/space
        assert.equal(s[pos], '"');  // at "next"
    });

    it('toValue — positions at value', () => {
        const s = '"key": 42';
        const pos = V.toValue(s, 0);
        assert.equal(s[pos], '4');
    });

    it('parseInt64 — positive', () => {
        const r = V.parseInt64('12345,', 0);
        assert.equal(r.value, 12345n);
        assert.equal(r.endPos, 5);
    });
    it('parseInt64 — negative', () => {
        const r = V.parseInt64('-999,', 0);
        assert.equal(r.value, -999n);
        assert.equal(r.endPos, 4);
    });
    it('parseInt64 — large timestamp', () => {
        const r = V.parseInt64('1700000000000,', 0);
        assert.equal(r.value, 1700000000000n);
    });

    it('parseDecStr — "50123.40"', () => {
        const r = V.parseDecStr('"50123.40"', 0);
        assert.equal(r.value, 5012340n);
        assert.equal(r.endPos, 10);
    });
    it('parseDecStr — truncated returns null', () => {
        assert.equal(V.parseDecStr('"50123.4', 0), null);
    });

    it('skipValue — string', () => {
        assert.equal(V.skipValue('"test", x', 0), 6);
    });
    it('skipValue — object', () => {
        const s = '{"a":1}, x';
        assert.equal(V.skipValue(s, 0), 7);
    });
    it('skipValue — array', () => {
        const s = '[1,2,3], x';
        assert.equal(V.skipValue(s, 0), 7);
    });
    it('skipValue — bool true', () => {
        assert.equal(V.skipValue('true, x', 0), 4);
    });
    it('skipValue — number', () => {
        assert.equal(V.skipValue('42, x', 0), 2);
    });
});

// ============================================================================
// Test Group 4: decodeEssential — aggTrade
// ============================================================================

describe('decodeEssential: aggTrade', () => {
    it('full message valid', () => {
        const payload = makeAggTradeJSON(5001, 1700000000000, '97403.89', '0.100', 1700000000001, true);
        const e = V.decodeEssential(payload);
        assert.equal(e.valid, true);
        assert.equal(e.msgType, V.STREAM_AGG_TRADE);
        assert.equal(e.seq, 5001n);
        assert.equal(e.eventTimeMs, 1700000000000n);
        assert.ok(e.resumePos > 0);
    });

    it('truncated before "a" field returns invalid', () => {
        const payload = makeAggTradeJSON(5001, 1700000000000, '97403.89', '0.100', 1700000000001, true);
        // Truncate before the "a" field value
        const aIdx = payload.indexOf('"a"');
        const truncated = payload.slice(0, aIdx);
        const e = V.decodeEssential(truncated);
        assert.equal(e.valid, false);
    });

    it('extracts correct resume position', () => {
        const payload = makeAggTradeJSON(5001, 1700000000000, '97403.89', '0.100', 1700000000001, true);
        const e = V.decodeEssential(payload);
        assert.equal(e.valid, true);
        // Resume pos should be after "a":5001, — at the "p" field
        assert.equal(payload[e.resumePos], '"');
    });
});

// ============================================================================
// Test Group 5: decodeEssential — depth
// ============================================================================

describe('decodeEssential: depth', () => {
    it('depthDiff extracts E and u', () => {
        const payload = makeDepthDiffJSON(9999, 1700000000000, [['97000.00','1.000']], [['97001.00','2.000']]);
        const e = V.decodeEssential(payload);
        assert.equal(e.valid, true);
        assert.equal(e.msgType, V.STREAM_DEPTH_DIFF_1);
        assert.equal(e.seq, 9999n);
        assert.equal(e.eventTimeMs, 1700000000000n);
    });

    it('depth5 (partial) extracts E and u', () => {
        const payload = makeDepthPartialJSON(8888, 1700000000000, [['97000.00','1.000']], [['97001.00','2.000']]);
        const e = V.decodeEssential(payload);
        assert.equal(e.valid, true);
        assert.equal(e.msgType, V.STREAM_DEPTH_PARTIAL);
        assert.equal(e.seq, 8888n);
        assert.equal(e.eventTimeMs, 1700000000000n);
    });
});

// ============================================================================
// Test Group 6: Single complete aggTrade → TRADE_ARRAY
// ============================================================================

describe('Single complete aggTrade', () => {
    it('produces TRADE_ARRAY with correct scaled price/qty and flags', () => {
        const payload = makeAggTradeJSON(100, 1700000000000, '97403.89', '0.100', 1700000000001, true);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const events = v.events;
        assert.equal(events.length, 1);
        assert.equal(events[0].type, 'TRADE_ARRAY');
        assert.equal(events[0].count, 1);
        assert.equal(events[0].seq, 100n);

        const t = events[0].trades[0];
        // 9740389 * 1000000 = 9740389000000
        assert.equal(t.price, 9740389n * V.PRICE_SCALE);
        // 100 * 100000 = 10000000 (0.100 → mantissa 100)
        assert.equal(t.qty, 100n * V.QTY_SCALE);
        assert.equal(t.trade_time_ns, 1700000000001n * 1000000n);
        // m=true → buyer_is_maker → flags=0 (NOT IS_BUYER)
        assert.equal(t.flags, 0);
    });

    it('m=false → IS_BUYER flag set', () => {
        const payload = makeAggTradeJSON(101, 1700000000000, '97403.89', '0.100', 1700000000001, false);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        assert.equal(v.events[0].trades[0].flags, V.FLAG_IS_BUYER);
    });
});

// ============================================================================
// Test Group 7: Single complete depth5 → BOOK_SNAPSHOT
// ============================================================================

describe('Single complete depth5', () => {
    it('produces BOOK_SNAPSHOT with count/count2 and scaled levels', () => {
        const bids = [['97000.00', '1.000'], ['96999.00', '2.500']];
        const asks = [['97001.00', '0.500'], ['97002.00', '3.000']];
        const payload = makeDepthPartialJSON(5000, 1700000000000, bids, asks);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const events = v.events;
        assert.equal(events.length, 1);
        assert.equal(events[0].type, 'BOOK_SNAPSHOT');
        assert.equal(events[0].count, 2);   // bid count
        assert.equal(events[0].count2, 2);  // ask count
        assert.equal(events[0].seq, 5000n);
        // Verify first bid: 9700000 * 1000000 = 9700000000000
        assert.equal(events[0].bids[0].price, 9700000n * V.PRICE_SCALE);
        assert.equal(events[0].bids[0].qty, 1000n * V.QTY_SCALE);
        // First ask
        assert.equal(events[0].asks[0].price, 9700100n * V.PRICE_SCALE);
    });
});

// ============================================================================
// Test Group 8: Single complete depthDiff → BOOK_DELTA
// ============================================================================

describe('Single complete depthDiff', () => {
    it('produces BOOK_DELTA with DELETE (qty=0) and UPDATE entries', () => {
        const bids = [['97000.00', '1.000'], ['96999.00', '0.000']];  // second is DELETE
        const asks = [['97001.00', '0.500']];
        const payload = makeDepthDiffJSON(6000, 1700000000000, bids, asks);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const events = v.events;
        assert.equal(events.length, 1);
        assert.equal(events[0].type, 'BOOK_DELTA');
        assert.equal(events[0].count, 3);

        const d = events[0].deltas;
        // First bid: UPDATE, flags=0 (bid)
        assert.equal(d[0].action, V.ACTION_UPDATE);
        assert.equal(d[0].flags, 0);
        // Second bid: DELETE (qty=0)
        assert.equal(d[1].action, V.ACTION_DELETE);
        assert.equal(d[1].qty, 0n);
        // Ask: SIDE_ASK flag
        assert.equal(d[2].flags, V.FLAG_SIDE_ASK);
        assert.equal(d[2].action, V.ACTION_UPDATE);
    });
});

// ============================================================================
// Test Group 9: Partial aggTrade across 2 fragments
// ============================================================================

describe('Partial aggTrade across 2 fragments', () => {
    it('phase=HEADER_PARSED after frag1, event after frag2', () => {
        const payload = makeAggTradeJSON(200, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        // Split in the middle of the "p" field value
        const pIdx = payload.indexOf('"p"');
        const splitPos = pIdx + 5;  // after "p":"
        const [frag1, frag2] = makeFragmentedFrames(0, payload, splitPos);
        // Add LAST_IN_BATCH to frag2
        frag2.flags |= V.WS_FLAG_LAST_IN_BATCH;

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(frag1);
        // After first fragment, no events yet (trade not fully parsed)
        assert.equal(v.events.length, 0);

        v.processFrame(frag2);
        // After second fragment, trade should be flushed (LAST_IN_BATCH)
        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].type, 'TRADE_ARRAY');
        assert.equal(v.events[0].trades[0].trade_id, 200n);
    });
});

// ============================================================================
// Test Group 10: Two connections interleaved
// ============================================================================

describe('Two connections interleaved', () => {
    it('conn0 partial superseded by conn1 → conn0 resume discarded', () => {
        const payload0 = makeAggTradeJSON(300, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const payload1 = makeAggTradeJSON(301, 1700000000002, '51000.00', '2.000', 1700000000003, true);

        // Fragment payload0
        const pIdx = payload0.indexOf('"p"');
        const [frag0a, frag0b] = makeFragmentedFrames(0, payload0, pIdx + 5);

        // Complete payload1 on conn 1
        const frame1 = makeFrame(1, payload1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(frag0a);           // conn 0 partial
        assert.equal(v.events.length, 0);

        v.processFrame(frame1);           // conn 1 complete → lastTradeSeq=301
        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].trades[0].trade_id, 301n);

        frag0b.flags |= V.WS_FLAG_LAST_IN_BATCH;
        v.processFrame(frag0b);           // conn 0 resumes: id=300 <= 301 → deduped
        // Both connections receive the same stream: conn 1 having id=301
        // means it already processed id=300 too, so conn 0's id=300 is stale.
        assert.equal(v.events.length, 1);  // no new event from conn 0
    });
});

// ============================================================================
// Test Group 11: Dedup — duplicate sequences
// ============================================================================

describe('Dedup: duplicate sequences', () => {
    it('same trade_id from 2 connections → only first emits', () => {
        const payload1 = makeAggTradeJSON(500, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const payload2 = makeAggTradeJSON(500, 1700000000002, '50000.00', '1.000', 1700000000003, false);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        v.processFrame(makeFrame(1, payload2, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].trades[0].trade_id, 500n);
    });

    it('duplicate book seq from 2 connections → only first emits', () => {
        const bids = [['97000.00', '1.000']];
        const asks = [['97001.00', '0.500']];
        const payload1 = makeDepthDiffJSON(7000, 1700000000000, bids, asks);
        const payload2 = makeDepthDiffJSON(7000, 1700000000002, bids, asks);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        v.processFrame(makeFrame(1, payload2, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 1);
    });
});

// ============================================================================
// Test Group 12: Dedup domains — book seq shared, trade seq independent
// ============================================================================

describe('Dedup domains', () => {
    it('book seq shared between snapshot and delta', () => {
        const bids = [['97000.00', '1.000']];
        const asks = [['97001.00', '0.500']];
        // Snapshot with seq 8000
        const snap = makeDepthPartialJSON(8000, 1700000000000, bids, asks);
        // Delta with same seq 8000 — should be deduped
        const diff = makeDepthDiffJSON(8000, 1700000000002, bids, asks);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, snap, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, diff, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        // Only snapshot should emit
        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].type, 'BOOK_SNAPSHOT');
    });

    it('trade seq independent from book seq', () => {
        const bids = [['97000.00', '1.000']];
        const asks = [['97001.00', '0.500']];
        const diff = makeDepthDiffJSON(1000, 1700000000000, bids, asks);
        const trade = makeAggTradeJSON(1000, 1700000000002, '50000.00', '1.000', 1700000000003, false);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, diff, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, trade, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        // Both should emit — different domains
        assert.equal(v.events.length, 2);
        assert.equal(v.events[0].type, 'BOOK_DELTA');
        assert.equal(v.events[1].type, 'TRADE_ARRAY');
    });
});

// ============================================================================
// Test Group 13: Trade merging — 3 consecutive trades → single TRADE_ARRAY
// ============================================================================

describe('Trade merging', () => {
    it('3 consecutive trades → single TRADE_ARRAY count=3', () => {
        const t1 = makeAggTradeJSON(100, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const t2 = makeAggTradeJSON(101, 1700000000000, '50001.00', '2.000', 1700000000001, false);
        const t3 = makeAggTradeJSON(102, 1700000000000, '50002.00', '3.000', 1700000000001, false);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, t1, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, t2, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, t3, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].type, 'TRADE_ARRAY');
        assert.equal(v.events[0].count, 3);
        assert.equal(v.events[0].seq, 102n);  // last trade's id
        assert.equal(v.events[0].trades[0].trade_id, 100n);
        assert.equal(v.events[0].trades[1].trade_id, 101n);
        assert.equal(v.events[0].trades[2].trade_id, 102n);
    });
});

// ============================================================================
// Test Group 14: Trade flush on depth
// ============================================================================

describe('Trade flush on depth', () => {
    it('2 trades then depth → trades flushed before depth event', () => {
        const t1 = makeAggTradeJSON(200, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const t2 = makeAggTradeJSON(201, 1700000000000, '50001.00', '2.000', 1700000000001, false);
        const bids = [['97000.00', '1.000']];
        const asks = [['97001.00', '0.500']];
        const depth = makeDepthDiffJSON(9000, 1700000000002, bids, asks);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, t1, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, t2, V.WS_FLAG_FIN));
        v.processFrame(makeFrame(0, depth, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 2);
        // Trades flushed first
        assert.equal(v.events[0].type, 'TRADE_ARRAY');
        assert.equal(v.events[0].count, 2);
        // Then depth
        assert.equal(v.events[1].type, 'BOOK_DELTA');
    });
});

// ============================================================================
// Test Group 15: Trade flush on batch end
// ============================================================================

describe('Trade flush on batch end', () => {
    it('single aggTrade with LAST_IN_BATCH → immediate flush', () => {
        const payload = makeAggTradeJSON(300, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].type, 'TRADE_ARRAY');
    });

    it('aggTrade without LAST_IN_BATCH → no flush until batch end', () => {
        const payload = makeAggTradeJSON(301, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN));  // no LAST_IN_BATCH

        // Not flushed yet (still in pending buffer)
        assert.equal(v.events.length, 0);

        // Trigger flush via run() which does final flush
        v.builder.flushPendingTrades();
        assert.equal(v.events.length, 1);
    });
});

// ============================================================================
// Test Group 16: Delta chunking
// ============================================================================

describe('Delta chunking', () => {
    it('25 bid levels → BOOK_DELTA(20) + BOOK_DELTA(5)', () => {
        // Generate 25 bid levels, 0 asks
        const bids = [];
        for (let i = 0; i < 25; i++) {
            bids.push([`${97000 + i}.00`, `${i + 1}.000`]);
        }
        const asks = [];
        const payload = makeDepthDiffJSON(10000, 1700000000000, bids, asks);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 2);
        assert.equal(v.events[0].type, 'BOOK_DELTA');
        assert.equal(v.events[0].count, V.MAX_DELTAS);  // 20
        assert.equal(v.events[0].count2, 0);  // first chunk: flush_index=0
        assert.equal(v.events[1].type, 'BOOK_DELTA');
        assert.equal(v.events[1].count, 5);
        assert.equal(v.events[1].count2, 1);  // second chunk: flush_index=1
    });
});

// ============================================================================
// Test Group 17: Scale factor exact values
// ============================================================================

describe('Scale factor exact values', () => {
    it('parseDecimal("97403.89") * PRICE_SCALE = 9740389000000n', () => {
        const mantissa = V.parseDecimal('"97403.89"');
        assert.equal(mantissa, 9740389n);
        assert.equal(mantissa * V.PRICE_SCALE, 9740389000000n);
    });

    it('parseDecimal("0.100") * QTY_SCALE = 10000000n', () => {
        const mantissa = V.parseDecimal('"0.100"');
        assert.equal(mantissa, 100n);
        assert.equal(mantissa * V.QTY_SCALE, 10000000n);
    });

    it('PRICE_SCALE = 1000000n, QTY_SCALE = 100000n', () => {
        assert.equal(V.PRICE_SCALE, 1000000n);
        assert.equal(V.QTY_SCALE, 100000n);
    });

    it('MAX constants match C++', () => {
        assert.equal(V.MAX_TRADES, 12);
        assert.equal(V.MAX_DELTAS, 20);
        assert.equal(V.MAX_BOOK_LEVELS, 30);
        assert.equal(V.SNAPSHOT_HALF, 15);
    });
});

// ============================================================================
// Test Group 18: Snapshot level cap
// ============================================================================

describe('Snapshot level cap', () => {
    it('depth5 with 20 bids + 20 asks → max 15+15', () => {
        const bids = [];
        const asks = [];
        for (let i = 0; i < 20; i++) {
            bids.push([`${97000 - i}.00`, `${i + 1}.000`]);
            asks.push([`${97001 + i}.00`, `${i + 1}.000`]);
        }
        const payload = makeDepthPartialJSON(11000, 1700000000000, bids, asks);

        const v = new V.BinanceUSDMVerifier();
        v.processFrame(makeFrame(0, payload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].type, 'BOOK_SNAPSHOT');
        assert.equal(v.events[0].count, V.SNAPSHOT_HALF);   // 15
        assert.equal(v.events[0].count2, V.SNAPSHOT_HALF);  // 15
        assert.equal(v.events[0].bids.length, V.SNAPSHOT_HALF);
        assert.equal(v.events[0].asks.length, V.SNAPSHOT_HALF);
    });
});

// ============================================================================
// parseEventLineBigInt — BigInt precision
// ============================================================================

describe('parseEventLineBigInt precision', () => {
    it('preserves large event_ts_ns without double-precision loss', () => {
        // 1772739519295000064 is the nearest IEEE 754 double to 1772739519295000000.
        // Before the fix, JSON.parse would produce 1772739519295000064.
        const line = '{"type":"BOOK_SNAPSHOT","seq":100,"event_ts_ns":1772739519295000000,"count":5}';
        const obj = V.parseEventLineBigInt(line);
        assert.equal(obj.event_ts_ns, 1772739519295000000n);
        assert.equal(obj.seq, 100n);
    });

    it('preserves large trade_id and trade_time_ns', () => {
        const line = '{"type":"TRADE_ARRAY","seq":3181640622,"event_ts_ns":1772740508845000000,"trades":[{"trade_id":3181640622,"price":7093560000000,"qty":17000000,"trade_time_ns":1772740508845000000,"flags":0}]}';
        const obj = V.parseEventLineBigInt(line);
        assert.equal(obj.trades[0].trade_id, 3181640622n);
        assert.equal(obj.trades[0].price, 7093560000000n);
        assert.equal(obj.trades[0].trade_time_ns, 1772740508845000000n);
    });

    it('handles negative values', () => {
        const line = '{"type":"TEST","seq":-12345,"event_ts_ns":-9999999999999999999}';
        const obj = V.parseEventLineBigInt(line);
        assert.equal(obj.seq, -12345n);
        assert.equal(obj.event_ts_ns, -9999999999999999999n);
    });
});

// ============================================================================
// compareEvents — seq-grouped and trade_id-based comparison
// ============================================================================

describe('compareEvents: seq-grouped book comparison', () => {
    it('matches book events by seq, aggregating across chunks', () => {
        // JS produces 2 BOOK_DELTA chunks, C++ produces 1 combined chunk — same seq
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 2,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 },
                       { price: 3n, qty: 4n, action: 1, flags: 0 }] },
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 5n, qty: 6n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 3,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 },
                       { price: 3n, qty: 4n, action: 1, flags: 0 },
                       { price: 5n, qty: 6n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0);
        assert.equal(r.pass, 1);
    });

    it('detects delta data mismatch', () => {
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 1n, qty: 999n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 1);
    });

    it('unmatched book events are warnings not failures', () => {
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [];  // no C++ match
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0);
        assert.equal(r.warn, 1);
    });

    it('JS fewer deltas with all matching is a warning (sampling boundary truncation)', () => {
        // JS parsed 2 deltas, C++ parsed 4 — depth update straddles frame window boundary
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 200n, event_ts_ns: 6000n, count: 2,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 },
                       { price: 3n, qty: 4n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 200n, event_ts_ns: 6000n, count: 4,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 },
                       { price: 3n, qty: 4n, action: 1, flags: 0 },
                       { price: 5n, qty: 6n, action: 1, flags: 0 },
                       { price: 7n, qty: 8n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0, 'should not be a failure');
        assert.equal(r.warn, 1, 'should be a warning');
        assert.equal(r.pass, 1, 'truncated group counts as pass');
    });

    it('C++ fewer deltas as suffix of JS is a warning (accumulated payload truncation)', () => {
        // JS sees accumulated payload from message start, C++ only produced events
        // from the non-discarded fragment onwards. C++ deltas are a suffix of JS.
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 300n, event_ts_ns: 7000n, count: 4,
              deltas: [{ price: 100n, qty: 1n, action: 1, flags: 0 },
                       { price: 200n, qty: 2n, action: 1, flags: 0 },
                       { price: 300n, qty: 3n, action: 1, flags: 0 },
                       { price: 400n, qty: 4n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 300n, event_ts_ns: 7000n, count: 2,
              deltas: [{ price: 300n, qty: 3n, action: 1, flags: 0 },
                       { price: 400n, qty: 4n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0, 'suffix match should not be a failure');
        assert.equal(r.warn, 1, 'should be a warning');
        assert.equal(r.pass, 1, 'suffix-matched group counts as pass');
    });

    it('C++ fewer deltas as prefix of JS is a warning (sampling ended mid-message)', () => {
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 350n, event_ts_ns: 7500n, count: 4,
              deltas: [{ price: 100n, qty: 1n, action: 1, flags: 0 },
                       { price: 200n, qty: 2n, action: 1, flags: 0 },
                       { price: 300n, qty: 3n, action: 1, flags: 0 },
                       { price: 400n, qty: 4n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 350n, event_ts_ns: 7500n, count: 2,
              deltas: [{ price: 100n, qty: 1n, action: 1, flags: 0 },
                       { price: 200n, qty: 2n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0, 'prefix match should not be a failure');
        assert.equal(r.warn, 1, 'should be a warning');
        assert.equal(r.pass, 1, 'prefix-matched group counts as pass');
    });

    it('C++ fewer deltas NOT a contiguous subset of JS is a failure', () => {
        // C++ has fewer deltas but they don't match the tail of JS
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 400n, event_ts_ns: 8000n, count: 3,
              deltas: [{ price: 100n, qty: 1n, action: 1, flags: 0 },
                       { price: 200n, qty: 2n, action: 1, flags: 0 },
                       { price: 300n, qty: 3n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 400n, event_ts_ns: 8000n, count: 2,
              deltas: [{ price: 999n, qty: 9n, action: 1, flags: 0 },
                       { price: 300n, qty: 3n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 1, 'non-suffix mismatch should be a failure');
    });

    it('JS fewer deltas with data mismatch is still a failure', () => {
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 200n, event_ts_ns: 6000n, count: 1,
              deltas: [{ price: 999n, qty: 2n, action: 1, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'BOOK_DELTA', seq: 200n, event_ts_ns: 6000n, count: 2,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 },
                       { price: 3n, qty: 4n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 1, 'data mismatch should be failure');
    });
});

describe('compareEvents: trade_id-based trade comparison', () => {
    it('matches trades by trade_id across different batch boundaries', () => {
        // JS batches trades [1,2] and [3], C++ batches [1] and [2,3]
        // Same individual trades, different batch seqs
        const jsEvents = [
            { type: 'TRADE_ARRAY', seq: 2n, event_ts_ns: 5000n, count: 2,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 },
                       { trade_id: 2n, price: 20n, qty: 2n, trade_time_ns: 5000n, flags: 0 }] },
            { type: 'TRADE_ARRAY', seq: 3n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 3n, price: 30n, qty: 3n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
            { type: 'TRADE_ARRAY', seq: 3n, event_ts_ns: 5000n, count: 2,
              trades: [{ trade_id: 2n, price: 20n, qty: 2n, trade_time_ns: 5000n, flags: 0 },
                       { trade_id: 3n, price: 30n, qty: 3n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0);
        assert.equal(r.pass, 3);  // 3 individual trades matched
    });

    it('detects trade data mismatch by trade_id', () => {
        const jsEvents = [
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 99n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 1);
        assert.ok(r.failures[0].includes('price'));
    });

    it('unmatched trades at sampling edge are warnings', () => {
        const jsEvents = [
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const cppEvents = [];  // C++ didn't capture this trade
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0);
        assert.ok(r.warnings.length > 0);
    });

    it('mixed book and trade events compared correctly', () => {
        const jsEvents = [
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 }] },
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
        ];
        const cppEvents = [
            { type: 'TRADE_ARRAY', seq: 1n, event_ts_ns: 5000n, count: 1,
              trades: [{ trade_id: 1n, price: 10n, qty: 1n, trade_time_ns: 5000n, flags: 0 }] },
            { type: 'BOOK_DELTA', seq: 100n, event_ts_ns: 5000n, count: 1,
              deltas: [{ price: 1n, qty: 2n, action: 1, flags: 0 }] },
        ];
        const r = V.compareEvents(jsEvents, cppEvents);
        assert.equal(r.fail, 0);
        assert.equal(r.pass, 2);  // 1 book group + 1 trade
    });
});

// ============================================================================
// Test Group: Streaming dedup re-check
// ============================================================================

describe('Streaming depth superseded by other connection', () => {
    it('no stale depth events after supersede', () => {
        // Build a large depth diff (seq=5000, 25 bids) from conn 0
        const bids = [];
        for (let i = 0; i < 25; i++) {
            bids.push([`${97000 + i}.00`, `${i + 1}.000`]);
        }
        const asks = [['97100.00', '1.000']];
        const payload0 = makeDepthDiffJSON(5000, 1700000000000, bids, asks);

        // Split into fragments at a position after stream/seq/bids header but before all bids
        const bIdx = payload0.indexOf('"b"');
        const splitPos = bIdx + 30;  // inside the bids array
        const [frag1, frag2] = makeFragmentedFrames(0, payload0, splitPos);

        const v = new V.BinanceUSDMVerifier();

        // Step 1: Feed first fragment from conn 0 → starts streaming
        v.processFrame(frag1);
        const eventsAfterFrag = v.events.length;

        // Step 2: Feed complete depth diff (seq=6000) from conn 1 → supersedes
        const payload1 = makeDepthDiffJSON(6000, 1700000000002,
            [['97050.00', '5.000']], [['97060.00', '6.000']]);
        v.processFrame(makeFrame(1, payload1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        const eventsAfterSupersede = v.events.length;
        // conn 1's depth should have been emitted
        assert.ok(eventsAfterSupersede > eventsAfterFrag);

        // Step 3: Feed second fragment from conn 0 → should NOT publish stale deltas
        frag2.flags |= V.WS_FLAG_LAST_IN_BATCH;
        v.processFrame(frag2);

        const eventsAfterResume = v.events.length;
        // No new events from stale conn 0 resume
        assert.equal(eventsAfterResume, eventsAfterSupersede,
            'stale conn 0 depth should not produce new events after supersede');
    });
});

describe('Streaming trade superseded by other connection', () => {
    it('no stale trade events after supersede', () => {
        // Build aggTrade (id=100) from conn 0, split into fragments
        const payload0 = makeAggTradeJSON(100, 1700000000000, '50000.00', '1.000', 1700000000001, false);
        const pIdx = payload0.indexOf('"p"');
        const splitPos = pIdx + 5;  // in the middle of price field
        const [frag1, frag2] = makeFragmentedFrames(0, payload0, splitPos);

        const v = new V.BinanceUSDMVerifier();

        // Step 1: Feed first fragment from conn 0 → incomplete, no event yet
        v.processFrame(frag1);
        assert.equal(v.events.length, 0);

        // Step 2: Feed complete aggTrade (id=200) from conn 1 → lastTradeSeq=200
        const payload1 = makeAggTradeJSON(200, 1700000000002, '51000.00', '2.000', 1700000000003, true);
        v.processFrame(makeFrame(1, payload1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        assert.equal(v.events.length, 1);
        assert.equal(v.events[0].trades[0].trade_id, 200n);

        // Step 3: Feed second fragment from conn 0 → should NOT publish stale trade id=100
        frag2.flags |= V.WS_FLAG_LAST_IN_BATCH;
        v.processFrame(frag2);

        // No trade event with id=100 should be emitted
        const trade100 = v.events.find(e =>
            e.type === 'TRADE_ARRAY' &&
            e.trades.some(t => t.trade_id === 100n));
        assert.equal(trade100, undefined,
            'stale trade id=100 should not be emitted after id=200 supersedes');
    });
});

// ============================================================================
// Test Group: Snapshot dedup with last_snapshot_seq guard
// ============================================================================

describe('Snapshot dedup across connections', () => {
    it('depth20 snapshot with seq == depth_diff seq is accepted', () => {
        // depth_diff on channel 1 (100ms) sets lastBookSeq[1] = 100
        // depth20 snapshot with seq=100 should still be accepted (seq < maxSeq is false)
        const v = new V.BinanceUSDMVerifier();
        const bids = [['50000.00', '1.0'], ['49999.00', '2.0']];
        const asks = [['50001.00', '1.5'], ['50002.00', '0.5']];
        const diffPayload = makeDepthDiffJSON(100, 1700000000000, [['49000.00', '1.0']], [['51000.00', '2.0']]);
        v.processFrame(makeFrame(0, diffPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        assert.equal(v.events.length, 1, 'depth_diff should produce 1 event');
        assert.equal(v.builder.lastBookSeq[1], 100n);

        const snapPayload = makeDepthPartialJSON(100, 1700000000001, bids, asks);
        v.processFrame(makeFrame(1, snapPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const snapEvents = v.events.filter(e => e.type === 'BOOK_SNAPSHOT');
        assert.equal(snapEvents.length, 1, 'snapshot with seq == lastBookSeq should be accepted');
    });

    it('duplicate depth20 snapshots from different connections are deduped', () => {
        const v = new V.BinanceUSDMVerifier();
        const bids = [['50000.00', '1.0']];
        const asks = [['50001.00', '1.5']];
        const snapPayload = makeDepthPartialJSON(100, 1700000000000, bids, asks);
        // First snapshot: accepted
        v.processFrame(makeFrame(0, snapPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        // Second snapshot from different conn: should be deduped
        v.processFrame(makeFrame(1, snapPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        // Third snapshot from yet another conn: also deduped
        v.processFrame(makeFrame(2, snapPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const snapEvents = v.events.filter(e => e.type === 'BOOK_SNAPSHOT');
        assert.equal(snapEvents.length, 1, 'only first snapshot should be accepted');
    });

    it('snapshot with seq < maxBookSeq is rejected', () => {
        const v = new V.BinanceUSDMVerifier();
        // Advance channel 1 (100ms) to seq=200
        const diffPayload = makeDepthDiffJSON(200, 1700000000000, [['49000.00', '1.0']], [['51000.00', '2.0']]);
        v.processFrame(makeFrame(0, diffPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        // Snapshot with seq=100 (stale): should be rejected
        const snapPayload = makeDepthPartialJSON(100, 1700000000001, [['50000.00', '1.0']], [['50001.00', '1.5']]);
        v.processFrame(makeFrame(1, snapPayload, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));
        const snapEvents = v.events.filter(e => e.type === 'BOOK_SNAPSHOT');
        assert.equal(snapEvents.length, 0, 'stale snapshot should be rejected');
    });
});

// ============================================================================
// Test Group: Per-channel comparison grouping
// ============================================================================

describe('Per-channel BOOK_DELTA comparison', () => {
    it('depth@100ms and depth@500ms with same seq produce separate groups', () => {
        const v = new V.BinanceUSDMVerifier();
        // depth@100ms (channel 1) with seq=100
        const ch1bids = [['50000.00', '1.0']];
        const ch1asks = [['50001.00', '1.5']];
        const ch1 = makeDepthDiffJSON(100, 1700000000000, ch1bids, ch1asks, { stream: 'btcusdt@depth@100ms' });
        v.processFrame(makeFrame(0, ch1, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        // depth@500ms (channel 3) with same seq=100, different content
        const ch3bids = [['49000.00', '3.0'], ['48000.00', '5.0']];
        const ch3asks = [['51000.00', '2.0']];
        const ch3 = makeDepthDiffJSON(100, 1700000000000, ch3bids, ch3asks, { stream: 'btcusdt@depth@500ms' });
        v.processFrame(makeFrame(0, ch3, V.WS_FLAG_FIN | V.WS_FLAG_LAST_IN_BATCH));

        // Should produce 2 events on different channels
        const deltas = v.events.filter(e => e.type === 'BOOK_DELTA');
        assert.equal(deltas.length, 2, 'should have 2 delta events');
        assert.equal(deltas[0].depth_channel, 1);
        assert.equal(deltas[1].depth_channel, 3);

        // compareEvents should group them separately (not mix deltas)
        const result = V.compareEvents(deltas, deltas);
        assert.equal(result.fail, 0, 'per-channel comparison should pass');
        assert.equal(result.pass, 2, 'should have 2 passing groups');
    });
});
