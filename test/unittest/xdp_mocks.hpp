// test/unittest/xdp_mocks.hpp
// Mock XDP/AF_XDP structures for unit testing without XDP installation
//
// This header provides mock/stub versions of XDP types so that unit tests
// can compile and run without requiring actual XDP/libxdp installation.

#pragma once

#define XDP_MOCKS_HPP  // Signal to other headers that we're using mocks

#include <cstdint>
#include <cstring>
#include <sys/socket.h>

// Mock XDP constants
#ifndef AF_XDP
#define AF_XDP 44
#endif
#define XDP_ZEROCOPY (1 << 2)
#define XDP_COPY (1 << 3)
#define XSK_RING_PROD__DEFAULT_NUM_DESCS 2048
#define XSK_RING_CONS__DEFAULT_NUM_DESCS 2048

// Mock XDP structures
struct xsk_ring_prod {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t* producer;
    uint32_t* consumer;
    void* ring;
    uint32_t* flags;
};

struct xsk_ring_cons {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t* producer;
    uint32_t* consumer;
    void* ring;
    uint32_t* flags;
};

struct xsk_umem {
    void* umem_area;
    size_t size;
};

struct xsk_socket {
    int fd;
};

struct xsk_umem_config {
    uint32_t fill_size;
    uint32_t comp_size;
    uint32_t frame_size;
    uint32_t frame_headroom;
    uint32_t flags;
};

struct xsk_socket_config {
    uint32_t rx_size;
    uint32_t tx_size;
    uint32_t libbpf_flags;
    uint32_t xdp_flags;
    uint16_t bind_flags;
};

struct sockaddr_xdp {
    uint16_t sxdp_family;
    uint16_t sxdp_flags;
    uint32_t sxdp_ifindex;
    uint32_t sxdp_queue_id;
    uint32_t sxdp_shared_umem_fd;
};

// Mock XDP functions (return success)
inline int xsk_umem__create(struct xsk_umem** umem,
                            void* umem_area,
                            uint64_t size,
                            struct xsk_ring_prod* fill,
                            struct xsk_ring_cons* comp,
                            const struct xsk_umem_config* config) {
    (void)umem_area;
    (void)size;
    (void)fill;
    (void)comp;
    (void)config;
    *umem = new xsk_umem();
    return 0;  // Success
}

inline int xsk_socket__create(struct xsk_socket** xsk,
                               const char* ifname,
                               uint32_t queue_id,
                               struct xsk_umem* umem,
                               struct xsk_ring_cons* rx,
                               struct xsk_ring_prod* tx,
                               const struct xsk_socket_config* config) {
    (void)ifname;
    (void)queue_id;
    (void)umem;
    (void)rx;
    (void)tx;
    (void)config;
    *xsk = new xsk_socket();
    (*xsk)->fd = 42;  // Mock FD
    return 0;  // Success
}

inline void xsk_umem__delete(struct xsk_umem* umem) {
    delete umem;
}

inline void xsk_socket__delete(struct xsk_socket* xsk) {
    delete xsk;
}

inline int xsk_socket__fd(const struct xsk_socket* xsk) {
    return xsk->fd;
}

inline uint32_t xsk_ring_prod__reserve(struct xsk_ring_prod* prod, uint32_t nb, uint32_t* idx) {
    *idx = 0;
    return nb;  // Mock: always succeed
}

inline void xsk_ring_prod__submit(struct xsk_ring_prod* prod, uint32_t nb) {
    (void)prod;
    (void)nb;
}

inline uint64_t* xsk_ring_prod__fill_addr(struct xsk_ring_prod* fill, uint32_t idx) {
    static uint64_t addr;
    (void)fill;
    (void)idx;
    return &addr;
}

inline uint32_t xsk_ring_cons__peek(struct xsk_ring_cons* cons, uint32_t nb, uint32_t* idx) {
    (void)cons;
    (void)nb;
    *idx = 0;
    return 0;  // No packets available
}

inline void xsk_ring_cons__release(struct xsk_ring_cons* cons, uint32_t nb) {
    (void)cons;
    (void)nb;
}

// Default config initializers
inline void xsk_umem_config__default(struct xsk_umem_config* config) {
    config->fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    config->comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    config->frame_size = 2048;
    config->frame_headroom = 0;
    config->flags = 0;
}

inline void xsk_socket_config__default(struct xsk_socket_config* config) {
    config->rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    config->tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    config->libbpf_flags = 0;
    config->xdp_flags = 0;
    config->bind_flags = 0;
}
