#ifndef UNC_POWMETAL_H
#define UNC_POWMETAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool metal_pow_is_available(void);

bool metal_pow_gpu_properties(
    unsigned int *thread_execution_width,
    unsigned int *max_threads_per_threadgroup
);

bool metal_mine_pow(
    const char *prefix,
    size_t prefix_length,
    int difficulty_bits,
    unsigned long long start_nonce,
    unsigned long long progress_interval,
    unsigned long long batch_size,
    unsigned long long nonce_step,
    unsigned long long nonces_per_thread,
    unsigned long long threads_per_group,
    unsigned long long *out_nonce,
    char out_hex[65],
    int *out_cancelled,
    char *error_message,
    size_t error_message_length
);

bool metal_mine_pow_range(
    const char *prefix,
    size_t prefix_length,
    int difficulty_bits,
    unsigned long long start_nonce,
    unsigned long long max_attempts,
    unsigned long long progress_interval,
    unsigned long long batch_size,
    unsigned long long nonce_step,
    unsigned long long nonces_per_thread,
    unsigned long long threads_per_group,
    unsigned long long *out_nonce,
    char out_hex[65],
    unsigned long long *out_attempts,
    int *out_found,
    int *out_cancelled,
    char *error_message,
    size_t error_message_length
);

#endif
