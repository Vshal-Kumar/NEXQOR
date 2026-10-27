/*
 * classical/crypto/replay_window.h — 64-Packet Sliding Replay Window
 *
 * Implements anti-replay protection based on RFC 6479 / IPsec specifications.
 * Enforces:
 *   - Duplicate packet rejection
 *   - Out-of-order packet acceptance within a 64-packet sliding window
 *   - Stale packet rejection (> 64 packets behind highest accepted sequence)
 *   - Pre-auth check (does not commit state) and post-auth commit separation
 *   - Thread-safe operations
 */

#ifndef REPLAY_WINDOW_H
#define REPLAY_WINDOW_H

#include <stdint.h>
#include <pthread.h>

#define REPLAY_WINDOW_SIZE 64

typedef struct {
    uint32_t        base_seq;     /* Highest accepted sequence number */
    uint64_t        bitmap;       /* 64-bit mask: bit i set => (base_seq - i) accepted */
    int             initialized;  /* 1 after first packet accepted */
    pthread_mutex_t lock;         /* Mutex for concurrent worker safety */
} replay_window_t;

/* Initialize window state and mutex */
void replay_window_init(replay_window_t *w);

/* Destroy mutex */
void replay_window_destroy(replay_window_t *w);

/* Reset window state */
void replay_window_reset(replay_window_t *w);

/*
 * replay_window_check():
 *   Pre-authentication verification.
 *   Returns 0 if sequence number is fresh / accepted candidate.
 *   Returns -1 if packet is a duplicate or stale.
 *   DOES NOT modify window state (safe to invoke before AEAD tag verification).
 */
int replay_window_check(replay_window_t *w, uint32_t seq);

/*
 * replay_window_update():
 *   Post-authentication commit.
 *   Must be invoked ONLY AFTER cryptographic AEAD authentication succeeds.
 *   Updates the sliding window state and records the sequence number.
 *   Returns 0 on successful state advance, -1 if duplicate/stale.
 */
int replay_window_update(replay_window_t *w, uint32_t seq);

#endif /* REPLAY_WINDOW_H */
