// test/traffic_simulator.cpp
// Replay debug_traffic.dat through WebSocket frame parser to detect issues
//
// Build: make test-traffic-sim
// Usage: ./build/traffic_simulator [debug_traffic.dat]
//
// This simulates the exact sequence of SSL_read data that was recorded,
// feeding it through the same frame parsing logic to detect:
// - Frame misalignment
// - Payload length corruption
// - Parser state machine bugs

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// Include the frame parser
#include "../src/core/http.hpp"
#include "../src/ringbuffer.hpp"

using websocket::http::WebSocketFrame;
using websocket::http::parse_websocket_frame;

// Debug traffic record header (32 bytes)
// Use manual byte array to avoid alignment issues
struct DebugTrafficHeader {
    uint8_t data[32];

    bool is_rx() const { return memcmp(data, "SSLR", 4) == 0; }
    bool is_tx() const { return memcmp(data, "SSLT", 4) == 0; }
    bool is_valid() const { return is_rx() || is_tx(); }

    uint32_t ssl_bytes() const {
        uint32_t val;
        memcpy(&val, data + 12, 4);
        return val;
    }

    uint32_t accum_before() const {
        uint32_t val;
        memcpy(&val, data + 16, 4);
        return val;
    }

    uint8_t frag_state() const { return data[24]; }
};

// Simulated parser state (mirrors WebSocketClient state)
struct SimulatorState {
    // Ring buffer simulation
    std::vector<uint8_t> buffer;
    size_t capacity;
    size_t batch_start_pos;
    size_t data_written;

    // Parser state
    size_t persistent_parse_offset;
    bool persistent_accumulating;
    uint8_t persistent_opcode;
    size_t persistent_accum_len;
    uint8_t persistent_frame_count;

    // Stats
    uint64_t total_frames;
    uint64_t total_bytes;
    uint64_t error_count;
    uint64_t misalign_count;

    SimulatorState(size_t cap = 4 * 1024 * 1024)
        : buffer(cap), capacity(cap), batch_start_pos(0), data_written(0),
          persistent_parse_offset(0), persistent_accumulating(false),
          persistent_opcode(0), persistent_accum_len(0), persistent_frame_count(0),
          total_frames(0), total_bytes(0), error_count(0), misalign_count(0) {}

    void reset_batch() {
        data_written = 0;
        persistent_parse_offset = 0;
        persistent_frame_count = 0;
        persistent_accumulating = false;
        persistent_opcode = 0;
        persistent_accum_len = 0;
    }
};

// Process frames from simulated buffer (simplified version of WebSocketClient::process_frames)
bool process_frames_sim(SimulatorState& state, uint64_t ssl_read_num) {
    constexpr size_t HDR_SIZE = 64;  // ShmBatchHeader size

    uint8_t* buffer = state.buffer.data();
    size_t capacity = state.capacity;
    size_t batch_pos = state.batch_start_pos;
    size_t ssl_data_pos = (batch_pos + HDR_SIZE) % capacity;
    size_t ssl_data_len = state.data_written;

    // Resume parsing from where we left off
    size_t parse_offset = state.persistent_parse_offset;
    bool local_accumulating = state.persistent_accumulating;
    uint8_t frame_count = state.persistent_frame_count;

    while (parse_offset + 2 <= ssl_data_len && frame_count < 255) {
        // Read frame header (max 14 bytes)
        uint8_t header_bytes[14];
        size_t header_pos = (ssl_data_pos + parse_offset) % capacity;
        size_t remaining = ssl_data_len - parse_offset;
        size_t peek_len = std::min(size_t(14), remaining);
        circular_read(buffer, capacity, header_pos, header_bytes, peek_len);

        WebSocketFrame frame;
        if (!parse_websocket_frame(header_bytes, remaining, frame)) {
            // Incomplete frame - show why
            uint64_t peek_payload_len = header_bytes[1] & 0x7F;
            size_t expected_hdr = 2;
            if (peek_payload_len == 126 && peek_len >= 4) {
                expected_hdr = 4;
                peek_payload_len = (header_bytes[2] << 8) | header_bytes[3];
            } else if (peek_payload_len == 127) {
                expected_hdr = 10;
            }
            printf("[SIM-INCOMPLETE] SSL#%lu @%zu/%zu: need hdr=%zu+payload=%lu, have %zu | hdr=[%02x %02x %02x %02x]\n",
                   ssl_read_num, parse_offset, ssl_data_len, expected_hdr,
                   (unsigned long)peek_payload_len, remaining,
                   header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]);
            break;
        }

        size_t frame_len = frame.header_len + frame.payload_len;
        if (parse_offset + frame_len > ssl_data_len) {
            printf("[SIM-INCOMPLETE] SSL#%lu @%zu/%zu: frame_len=%zu exceeds remaining=%zu\n",
                   ssl_read_num, parse_offset, ssl_data_len, frame_len, ssl_data_len - parse_offset);
            break;
        }

        // Log frame
        printf("[SIM-FRAME#%u] op=%02x fin=%d hdr=%zu payload=%zu total=%zu @%zu | raw=[%02x %02x %02x %02x]\n",
               frame_count, frame.opcode, frame.fin, frame.header_len, frame.payload_len,
               frame_len, parse_offset,
               header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]);

        // Check for misalignment: leftover looks like ASCII instead of frame header
        if (frame_count == 0 && frame_len < ssl_data_len) {
            size_t leftover = ssl_data_len - frame_len;
            size_t leftover_pos = (ssl_data_pos + frame_len) % capacity;
            uint8_t lb0 = buffer[leftover_pos];
            uint8_t lb1 = buffer[(leftover_pos + 1) % capacity];

            // Real frame headers start with 0x8X (fin=1) or 0x0X (continuation)
            // ASCII text (JSON) starts with 0x20-0x7E
            if (lb0 >= 0x20 && lb0 < 0x80 && lb0 != 0x00) {
                printf("[SIM-MISALIGN!] SSL#%lu: Frame#0 ends at %zu but %zu bytes remain; "
                       "leftover=[%02x %02x] looks like ASCII '%c%c'\n",
                       ssl_read_num, frame_len, leftover, lb0, lb1,
                       (lb0 >= 32 && lb0 < 127) ? lb0 : '.',
                       (lb1 >= 32 && lb1 < 127) ? lb1 : '.');
                state.misalign_count++;
            }
        }

        // Handle control frames
        if (frame.opcode >= 0x08) {
            bool is_reserved = (frame.opcode >= 0x0B && frame.opcode <= 0x0F);
            bool is_suspicious = is_reserved || (frame.opcode == 0x0A); // Unsolicited PONG

            printf("[SIM-CTRL] op=0x%02x len=%zu @%zu%s\n",
                   frame.opcode, frame.payload_len, parse_offset,
                   is_suspicious ? " [SUSPICIOUS]" : "");

            if (is_suspicious) {
                state.error_count++;
            }

            // CLOSE frame (op=0x08) with fin=0 is very suspicious
            if (frame.opcode == 0x08 && !frame.fin) {
                printf("[SIM-ERROR!] SSL#%lu: CLOSE frame with fin=0 is invalid!\n", ssl_read_num);
                state.error_count++;
            }
        }

        // Handle fragmentation
        if (!frame.fin) {
            if (!local_accumulating) {
                local_accumulating = true;
                state.persistent_opcode = frame.opcode;
            }
        } else if (local_accumulating) {
            local_accumulating = false;
        }

        parse_offset += frame_len;
        frame_count++;
        state.total_frames++;
    }

    // Update persistent state
    state.persistent_parse_offset = parse_offset;
    state.persistent_accumulating = local_accumulating;
    state.persistent_frame_count = frame_count;

    // Check if all consumed
    bool all_consumed = (parse_offset == ssl_data_len) && !local_accumulating;

    if (all_consumed && frame_count > 0) {
        printf("[SIM-COMMIT] %u frames, %zu bytes\n", frame_count, parse_offset);
        state.reset_batch();
        return true;
    } else {
        printf("[SIM-DEFER] %u frames, %zu/%zu bytes, accum=%d\n",
               frame_count, parse_offset, ssl_data_len, local_accumulating ? 1 : 0);
        return false;
    }
}

int main(int argc, char* argv[]) {
    const char* filename = "debug_traffic.dat";
    if (argc > 1) {
        filename = argv[1];
    }

    printf("=== WebSocket Traffic Simulator ===\n");
    printf("Input: %s\n\n", filename);

    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s\n", filename);
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("File size: %ld bytes\n\n", file_size);

    SimulatorState state(4 * 1024 * 1024);  // 4MB buffer like production

    DebugTrafficHeader hdr;
    uint64_t ssl_read_num = 0;
    uint64_t tx_count = 0;

    while (fread(&hdr, sizeof(hdr), 1, fp) == 1) {
        if (hdr.is_tx()) {
            // TX record - skip the data
            fseek(fp, hdr.ssl_bytes(), SEEK_CUR);
            tx_count++;
            continue;
        }

        if (!hdr.is_rx()) {
            fprintf(stderr, "Error: Invalid magic at offset %ld: %02x %02x %02x %02x\n",
                    ftell(fp) - 32, hdr.data[0], hdr.data[1], hdr.data[2], hdr.data[3]);
            break;
        }

        ssl_read_num++;
        uint32_t ssl_bytes = hdr.ssl_bytes();
        uint32_t accum_before = hdr.accum_before();

        // Read SSL data
        std::vector<uint8_t> ssl_data(ssl_bytes);
        if (fread(ssl_data.data(), 1, ssl_bytes, fp) != ssl_bytes) {
            fprintf(stderr, "Error: Short read at SSL#%lu\n", ssl_read_num);
            break;
        }

        // Determine if FRESH or ACCUM
        bool is_fresh = (accum_before == 0);
        const char* state_str = is_fresh ? "FRESH" : "ACCUM";

        // Calculate write position
        size_t ssl_write_pos;
        if (is_fresh) {
            // Start new batch
            state.batch_start_pos = (state.batch_start_pos + 64 + state.data_written + 63) & ~63ULL;
            state.batch_start_pos %= state.capacity;
            state.data_written = 0;
            state.persistent_parse_offset = 0;
            state.persistent_frame_count = 0;
            ssl_write_pos = (state.batch_start_pos + 64) % state.capacity;
        } else {
            ssl_write_pos = (state.batch_start_pos + 64 + state.data_written) % state.capacity;
        }

        // Copy data to simulated buffer
        size_t to_end = state.capacity - ssl_write_pos;
        if (ssl_bytes <= to_end) {
            memcpy(state.buffer.data() + ssl_write_pos, ssl_data.data(), ssl_bytes);
        } else {
            memcpy(state.buffer.data() + ssl_write_pos, ssl_data.data(), to_end);
            memcpy(state.buffer.data(), ssl_data.data() + to_end, ssl_bytes - to_end);
        }
        state.data_written += ssl_bytes;
        state.total_bytes += ssl_bytes;

        // Peek first 4 bytes
        uint8_t b0 = ssl_data[0], b1 = ssl_data.size() > 1 ? ssl_data[1] : 0;
        uint8_t b2 = ssl_data.size() > 2 ? ssl_data[2] : 0, b3 = ssl_data.size() > 3 ? ssl_data[3] : 0;

        printf("\n[SIM-SSL#%lu] %s +%u bytes @%zu, total=%zu | [%02x %02x %02x %02x]\n",
               ssl_read_num, state_str, ssl_bytes, ssl_write_pos, state.data_written,
               b0, b1, b2, b3);

        // Process frames
        process_frames_sim(state, ssl_read_num);
    }

    fclose(fp);

    printf("\n=== Simulation Complete ===\n");
    printf("SSL reads: %lu\n", ssl_read_num);
    printf("TX records: %lu\n", tx_count);
    printf("Total frames: %lu\n", state.total_frames);
    printf("Total bytes: %lu\n", state.total_bytes);
    printf("Errors: %lu\n", state.error_count);
    printf("Misalignments: %lu\n", state.misalign_count);

    if (state.error_count > 0 || state.misalign_count > 0) {
        printf("\n*** ISSUES DETECTED! ***\n");
        return 1;
    }

    return 0;
}
