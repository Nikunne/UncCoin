#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER) && !defined(__clang__)
#include <windows.h>
#else
#include <stdatomic.h>
#endif

#if defined(__clang__) && defined(__aarch64__)
#include <arm_neon.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#if defined(__has_include)
#if __has_include(<asm/hwcap.h>)
#include <asm/hwcap.h>
#endif
#endif
#endif
#define UNCCOIN_HAS_ARM_SHA2_INTRINSICS 1
#define UNCCOIN_ARM_SHA2_TARGET __attribute__((target("sha2,neon")))
#else
#define UNCCOIN_HAS_ARM_SHA2_INTRINSICS 0
#define UNCCOIN_ARM_SHA2_TARGET
#endif

#ifdef __APPLE__
#include "powmetal.h"
#endif

#define SHA256_HEX_LENGTH 64
#define SHA256_BINARY_LENGTH 32
#define NONCE_BUFFER_LENGTH 32
#define CANCEL_CHECK_INTERVAL 1024
#define DEFAULT_GPU_BATCH_SIZE 262144

#if defined(_MSC_VER) && !defined(__clang__)
static volatile LONG cancel_requested = 0;
#define LOAD_CANCEL_REQUESTED() InterlockedCompareExchange(&cancel_requested, 0, 0)
#define STORE_CANCEL_REQUESTED(value) InterlockedExchange(&cancel_requested, (LONG)(value))
#else
static atomic_int cancel_requested = 0;
#define LOAD_CANCEL_REQUESTED() atomic_load_explicit(&cancel_requested, memory_order_relaxed)
#define STORE_CANCEL_REQUESTED(value) atomic_store_explicit(&cancel_requested, (value), memory_order_relaxed)
#endif

typedef struct {
    uint8_t data[64];
    uint32_t state[8];
    uint64_t bit_length;
    size_t data_length;
} sha256_context;

typedef struct {
    int nonce_length;
    size_t first_nonce_offset;
    size_t first_nonce_length;
    size_t second_nonce_length;
    int uses_second_block;
    uint8_t first_block[64];
    uint8_t second_block[64];
} prepared_nonce_blocks;

static const uint32_t SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

#define SHA256_RIGHT_ROTATE(value, bits) (((value) >> (bits)) | ((value) << (32U - (bits))))

static int cpu_sha256_acceleration_available = 0;

static void sha256_transform_scalar(sha256_context *context, const uint8_t data[64]) {
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (size_t index = 0; index < 16; index++) {
        schedule[index] = ((uint32_t)data[index * 4] << 24) |
                          ((uint32_t)data[index * 4 + 1] << 16) |
                          ((uint32_t)data[index * 4 + 2] << 8) |
                          ((uint32_t)data[index * 4 + 3]);
    }

    for (size_t index = 16; index < 64; index++) {
        uint32_t sigma0 = SHA256_RIGHT_ROTATE(schedule[index - 15], 7) ^
                          SHA256_RIGHT_ROTATE(schedule[index - 15], 18) ^
                          (schedule[index - 15] >> 3);
        uint32_t sigma1 = SHA256_RIGHT_ROTATE(schedule[index - 2], 17) ^
                          SHA256_RIGHT_ROTATE(schedule[index - 2], 19) ^
                          (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16] + sigma0 + schedule[index - 7] + sigma1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (size_t index = 0; index < 64; index++) {
        uint32_t sum1 = SHA256_RIGHT_ROTATE(e, 6) ^
                        SHA256_RIGHT_ROTATE(e, 11) ^
                        SHA256_RIGHT_ROTATE(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choose + SHA256_K[index] + schedule[index];
        uint32_t sum0 = SHA256_RIGHT_ROTATE(a, 2) ^
                        SHA256_RIGHT_ROTATE(a, 13) ^
                        SHA256_RIGHT_ROTATE(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

#if UNCCOIN_HAS_ARM_SHA2_INTRINSICS
static int detect_cpu_sha256_acceleration(void) {
#if defined(__APPLE__)
    int available = 0;
    size_t available_size = sizeof(available);

    if (
        sysctlbyname(
            "hw.optional.arm.FEAT_SHA256",
            &available,
            &available_size,
            NULL,
            0
        ) == 0
        && available_size == sizeof(available)
    ) {
        return available != 0;
    }

    return 0;
#elif defined(__linux__) && defined(HWCAP_SHA2)
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#else
    return 0;
#endif
}

UNCCOIN_ARM_SHA2_TARGET
static void sha256_transform_arm_sha2(sha256_context *context, const uint8_t data[64]) {
    uint32x4_t abcd = vld1q_u32(context->state);
    uint32x4_t efgh = vld1q_u32(context->state + 4);
    uint32x4_t abcd_save = abcd;
    uint32x4_t efgh_save = efgh;
    uint32x4_t message_schedule[4];

    message_schedule[0] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data)));
    message_schedule[1] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16)));
    message_schedule[2] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 32)));
    message_schedule[3] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 48)));

    /* Process rounds in 4-word groups and refresh the group that was just consumed. */
    for (int round_group = 0; round_group < 16; round_group++) {
        int schedule_index = round_group & 3;
        uint32x4_t rounds = vaddq_u32(
            message_schedule[schedule_index],
            vld1q_u32(SHA256_K + (round_group * 4))
        );
        uint32x4_t abcd_previous = abcd;

        abcd = vsha256hq_u32(abcd, efgh, rounds);
        efgh = vsha256h2q_u32(efgh, abcd_previous, rounds);

        if (round_group < 12) {
            message_schedule[schedule_index] = vsha256su1q_u32(
                vsha256su0q_u32(
                    message_schedule[schedule_index],
                    message_schedule[(schedule_index + 1) & 3]
                ),
                message_schedule[(schedule_index + 2) & 3],
                message_schedule[(schedule_index + 3) & 3]
            );
        }
    }

    abcd = vaddq_u32(abcd, abcd_save);
    efgh = vaddq_u32(efgh, efgh_save);
    vst1q_u32(context->state, abcd);
    vst1q_u32(context->state + 4, efgh);
}
#endif

static void sha256_transform(sha256_context *context, const uint8_t data[64]) {
#if UNCCOIN_HAS_ARM_SHA2_INTRINSICS
    if (cpu_sha256_acceleration_available) {
        sha256_transform_arm_sha2(context, data);
        return;
    }
#endif
    sha256_transform_scalar(context, data);
}

static void sha256_init(sha256_context *context) {
    context->data_length = 0;
    context->bit_length = 0;
    context->state[0] = 0x6a09e667U;
    context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U;
    context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU;
    context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU;
    context->state[7] = 0x5be0cd19U;
}

static void sha256_update(sha256_context *context, const uint8_t *data, size_t length) {
    for (size_t index = 0; index < length; index++) {
        context->data[context->data_length] = data[index];
        context->data_length += 1;

        if (context->data_length == 64) {
            sha256_transform(context, context->data);
            context->bit_length += 512;
            context->data_length = 0;
        }
    }
}

static int u64_to_ascii(unsigned long long value, char buffer[NONCE_BUFFER_LENGTH]) {
    char reversed[NONCE_BUFFER_LENGTH];
    int length = 0;

    do {
        reversed[length++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    for (int index = 0; index < length; index++) {
        buffer[index] = reversed[length - index - 1];
    }

    return length;
}

static int increment_ascii_decimal(
    char buffer[NONCE_BUFFER_LENGTH],
    int *length,
    unsigned long long increment
) {
    int index = *length - 1;
    int changed_index = *length;
    unsigned long long carry = increment;

    while (index >= 0 && carry > 0) {
        unsigned long long sum = (unsigned long long)(buffer[index] - '0') + (carry % 10);
        carry /= 10;
        if (sum >= 10) {
            sum -= 10;
            carry += 1;
        }
        buffer[index] = (char)('0' + sum);
        changed_index = index;
        index -= 1;
    }

    if (carry == 0) {
        return changed_index < *length ? changed_index : *length - 1;
    }

    char prefix[NONCE_BUFFER_LENGTH];
    int prefix_length = 0;
    while (carry > 0) {
        prefix[prefix_length++] = (char)('0' + (carry % 10));
        carry /= 10;
    }

    if (*length + prefix_length >= NONCE_BUFFER_LENGTH) {
        return -1;
    }

    memmove(buffer + prefix_length, buffer, (size_t)(*length));
    for (int prefix_index = 0; prefix_index < prefix_length; prefix_index++) {
        buffer[prefix_index] = prefix[prefix_length - prefix_index - 1];
    }
    *length += prefix_length;

    return 0;
}

static int increment_ascii_decimal_one(
    char buffer[NONCE_BUFFER_LENGTH],
    int *length
) {
    int index = *length - 1;

    while (index >= 0 && buffer[index] == '9') {
        buffer[index] = '0';
        index -= 1;
    }

    if (index >= 0) {
        buffer[index] = (char)(buffer[index] + 1);
        return index;
    }

    if (*length + 1 >= NONCE_BUFFER_LENGTH) {
        return -1;
    }

    memmove(buffer + 1, buffer, (size_t)(*length));
    buffer[0] = '1';
    *length += 1;
    return 0;
}

static void write_sha256_length(uint8_t block[64], uint64_t total_bit_length) {
    block[63] = (uint8_t)(total_bit_length);
    block[62] = (uint8_t)(total_bit_length >> 8);
    block[61] = (uint8_t)(total_bit_length >> 16);
    block[60] = (uint8_t)(total_bit_length >> 24);
    block[59] = (uint8_t)(total_bit_length >> 32);
    block[58] = (uint8_t)(total_bit_length >> 40);
    block[57] = (uint8_t)(total_bit_length >> 48);
    block[56] = (uint8_t)(total_bit_length >> 56);
}

static void prepare_nonce_blocks(
    const sha256_context *prefix_context,
    const char *nonce_buffer,
    int nonce_length,
    prepared_nonce_blocks *prepared
) {
    size_t prefix_remainder = prefix_context->data_length;
    size_t first_available = 64 - prefix_remainder;
    size_t first_nonce_length = (size_t)nonce_length;
    uint64_t total_bit_length =
        prefix_context->bit_length + ((uint64_t)(prefix_remainder + (size_t)nonce_length) * 8);

    memset(prepared, 0, sizeof(*prepared));
    prepared->nonce_length = nonce_length;
    prepared->first_nonce_offset = prefix_remainder;

    memcpy(prepared->first_block, prefix_context->data, prefix_remainder);

    if (first_nonce_length > first_available) {
        first_nonce_length = first_available;
    }
    prepared->first_nonce_length = first_nonce_length;
    prepared->second_nonce_length = (size_t)nonce_length - first_nonce_length;
    prepared->uses_second_block = prepared->second_nonce_length > 0;

    if (prepared->first_nonce_length > 0) {
        memcpy(
            prepared->first_block + prepared->first_nonce_offset,
            nonce_buffer,
            prepared->first_nonce_length
        );
    }
    if (prepared->second_nonce_length > 0) {
        memcpy(
            prepared->second_block,
            nonce_buffer + prepared->first_nonce_length,
            prepared->second_nonce_length
        );
    }

    if (prepared->uses_second_block) {
        prepared->second_block[prepared->second_nonce_length] = 0x80;
        write_sha256_length(prepared->second_block, total_bit_length);
        return;
    }

    size_t total_suffix_offset = prefix_remainder + prepared->first_nonce_length;
    if (total_suffix_offset < 56) {
        prepared->first_block[total_suffix_offset] = 0x80;
        write_sha256_length(prepared->first_block, total_bit_length);
        return;
    }

    prepared->uses_second_block = 1;
    if (total_suffix_offset < 64) {
        prepared->first_block[total_suffix_offset] = 0x80;
    } else {
        prepared->second_block[0] = 0x80;
    }
    write_sha256_length(prepared->second_block, total_bit_length);
}

static void update_prepared_nonce_blocks(
    prepared_nonce_blocks *prepared,
    const char *nonce_buffer,
    int changed_index
) {
    if (changed_index < 0) {
        changed_index = 0;
    }

    if ((size_t)changed_index < prepared->first_nonce_length) {
        memcpy(
            prepared->first_block + prepared->first_nonce_offset + (size_t)changed_index,
            nonce_buffer + changed_index,
            prepared->first_nonce_length - (size_t)changed_index
        );
        if (prepared->second_nonce_length > 0) {
            memcpy(
                prepared->second_block,
                nonce_buffer + prepared->first_nonce_length,
                prepared->second_nonce_length
            );
        }
        return;
    }

    if (prepared->second_nonce_length > 0) {
        size_t second_changed_index = (size_t)changed_index - prepared->first_nonce_length;
        if (second_changed_index < prepared->second_nonce_length) {
            memcpy(
                prepared->second_block + second_changed_index,
                nonce_buffer + changed_index,
                prepared->second_nonce_length - second_changed_index
            );
        }
    }
}

static void sha256_digest_prepared_state(
    const sha256_context *prefix_context,
    const prepared_nonce_blocks *prepared,
    uint32_t state[8]
) {
    sha256_context context;
    memcpy(context.state, prefix_context->state, sizeof(context.state));

    sha256_transform(&context, prepared->first_block);
    if (prepared->uses_second_block) {
        sha256_transform(&context, prepared->second_block);
    }

    memcpy(state, context.state, sizeof(context.state));
}

static void sha256_state_to_digest(
    const uint32_t state[8],
    uint8_t hash[SHA256_BINARY_LENGTH]
) {
    for (size_t index = 0; index < 4; index++) {
        hash[index]      = (uint8_t)((state[0] >> (24 - index * 8)) & 0xFF);
        hash[index + 4]  = (uint8_t)((state[1] >> (24 - index * 8)) & 0xFF);
        hash[index + 8]  = (uint8_t)((state[2] >> (24 - index * 8)) & 0xFF);
        hash[index + 12] = (uint8_t)((state[3] >> (24 - index * 8)) & 0xFF);
        hash[index + 16] = (uint8_t)((state[4] >> (24 - index * 8)) & 0xFF);
        hash[index + 20] = (uint8_t)((state[5] >> (24 - index * 8)) & 0xFF);
        hash[index + 24] = (uint8_t)((state[6] >> (24 - index * 8)) & 0xFF);
        hash[index + 28] = (uint8_t)((state[7] >> (24 - index * 8)) & 0xFF);
    }
}

static bool has_leading_zero_bits_state(const uint32_t state[8], int difficulty_bits) {
    int full_zero_words = difficulty_bits / 32;
    int remaining_bits = difficulty_bits % 32;

    for (int index = 0; index < full_zero_words; index++) {
        if (state[index] != 0) {
            return false;
        }
    }

    if (remaining_bits == 0) {
        return true;
    }

    return (
        state[full_zero_words] &
        (uint32_t)(0xFFFFFFFFU << (32 - remaining_bits))
    ) == 0;
}

static void digest_to_hex(const unsigned char *digest, char *hex_output) {
    static const char hex_chars[] = "0123456789abcdef";

    for (int index = 0; index < SHA256_BINARY_LENGTH; index++) {
        hex_output[index * 2] = hex_chars[(digest[index] >> 4) & 0xF];
        hex_output[index * 2 + 1] = hex_chars[digest[index] & 0xF];
    }

    hex_output[SHA256_HEX_LENGTH] = '\0';
}

int pow_cancel_requested(void) {
    return LOAD_CANCEL_REQUESTED();
}

typedef struct {
    unsigned long long nonce;
    unsigned long long attempts;
    int found;
    int cancelled;
    int nonce_error;
    unsigned char digest[SHA256_BINARY_LENGTH];
} pow_search_result;

static void search_pow_range(
    const sha256_context *prefix_context,
    int difficulty_bits,
    unsigned long long start_nonce,
    unsigned long long max_attempts,
    unsigned long long progress_interval,
    unsigned long long nonce_step,
    pow_search_result *result
) {
    prepared_nonce_blocks prepared_blocks;
    uint32_t digest_state[8];
    char nonce_buffer[NONCE_BUFFER_LENGTH];
    unsigned long long nonce = start_nonce;
    unsigned long long attempts = 0;
    int nonce_length = 0;
    const int step_is_one = nonce_step == 1;

    memset(result, 0, sizeof(*result));
    memset(digest_state, 0, sizeof(digest_state));

    nonce_length = u64_to_ascii(nonce, nonce_buffer);
    prepare_nonce_blocks(prefix_context, nonce_buffer, nonce_length, &prepared_blocks);

    while (max_attempts == 0 || attempts < max_attempts) {
        if (
            attempts % CANCEL_CHECK_INTERVAL == 0
            && LOAD_CANCEL_REQUESTED()
        ) {
            result->cancelled = 1;
            break;
        }

        sha256_digest_prepared_state(prefix_context, &prepared_blocks, digest_state);
        attempts += 1;

        if (has_leading_zero_bits_state(digest_state, difficulty_bits)) {
            result->found = 1;
            sha256_state_to_digest(digest_state, result->digest);
            break;
        }

        if (max_attempts != 0 && attempts >= max_attempts) {
            break;
        }

        int previous_nonce_length = nonce_length;
        int changed_index = 0;
        if (step_is_one) {
            nonce += 1;
            changed_index = increment_ascii_decimal_one(nonce_buffer, &nonce_length);
        } else {
            nonce += nonce_step;
            changed_index = increment_ascii_decimal(
                nonce_buffer,
                &nonce_length,
                nonce_step
            );
        }
        if (changed_index < 0 || nonce_length >= NONCE_BUFFER_LENGTH) {
            result->nonce_error = 1;
            break;
        }
        if (nonce_length != previous_nonce_length) {
            prepare_nonce_blocks(prefix_context, nonce_buffer, nonce_length, &prepared_blocks);
        } else {
            update_prepared_nonce_blocks(&prepared_blocks, nonce_buffer, changed_index);
        }

        if (progress_interval > 0 && attempts > 0 && attempts % progress_interval == 0) {
            printf("\rTried %llu nonces...", nonce);
            fflush(stdout);
        }
    }

    result->attempts = attempts;
    result->nonce = nonce;
}

static PyObject *mine_pow(PyObject *Py_UNUSED(self), PyObject *args) {
    const char *prefix = NULL;
    Py_ssize_t prefix_length = 0;
    int difficulty_bits = 0;
    unsigned long long start_nonce = 0;
    unsigned long long progress_interval = 0;
    unsigned long long nonce_step = 1;

    if (!PyArg_ParseTuple(
            args,
            "s#i|KKK",
            &prefix,
            &prefix_length,
            &difficulty_bits,
            &start_nonce,
            &progress_interval,
            &nonce_step)) {
        return NULL;
    }

    if (difficulty_bits < 0 || difficulty_bits > 256) {
        PyErr_SetString(PyExc_ValueError, "difficulty_bits must be between 0 and 256.");
        return NULL;
    }
    if (nonce_step == 0) {
        PyErr_SetString(PyExc_ValueError, "nonce_step must be at least 1.");
        return NULL;
    }

    sha256_context prefix_context;
    char hex_digest[SHA256_HEX_LENGTH + 1];
    pow_search_result result;

    sha256_init(&prefix_context);
    sha256_update(&prefix_context, (const uint8_t *)prefix, (size_t)prefix_length);

    Py_BEGIN_ALLOW_THREADS
    search_pow_range(
        &prefix_context,
        difficulty_bits,
        start_nonce,
        0,
        progress_interval,
        nonce_step,
        &result
    );
    Py_END_ALLOW_THREADS

    if (result.nonce_error) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to serialize nonce.");
        return NULL;
    }

    if (result.found) {
        digest_to_hex(result.digest, hex_digest);
    } else {
        hex_digest[0] = '\0';
    }

    return Py_BuildValue("Ksi", result.nonce, hex_digest, result.cancelled);
}

static PyObject *mine_pow_chunk(PyObject *Py_UNUSED(self), PyObject *args) {
    const char *prefix = NULL;
    Py_ssize_t prefix_length = 0;
    int difficulty_bits = 0;
    unsigned long long start_nonce = 0;
    unsigned long long max_attempts = 0;
    unsigned long long progress_interval = 0;
    unsigned long long nonce_step = 1;
    sha256_context prefix_context;
    char hex_digest[SHA256_HEX_LENGTH + 1];
    pow_search_result result;

    if (!PyArg_ParseTuple(
            args,
            "s#iKK|KK",
            &prefix,
            &prefix_length,
            &difficulty_bits,
            &start_nonce,
            &max_attempts,
            &progress_interval,
            &nonce_step)) {
        return NULL;
    }

    if (difficulty_bits < 0 || difficulty_bits > 256) {
        PyErr_SetString(PyExc_ValueError, "difficulty_bits must be between 0 and 256.");
        return NULL;
    }
    if (max_attempts == 0) {
        PyErr_SetString(PyExc_ValueError, "max_attempts must be at least 1.");
        return NULL;
    }
    if (nonce_step == 0) {
        PyErr_SetString(PyExc_ValueError, "nonce_step must be at least 1.");
        return NULL;
    }

    sha256_init(&prefix_context);
    sha256_update(&prefix_context, (const uint8_t *)prefix, (size_t)prefix_length);

    Py_BEGIN_ALLOW_THREADS
    search_pow_range(
        &prefix_context,
        difficulty_bits,
        start_nonce,
        max_attempts,
        progress_interval,
        nonce_step,
        &result
    );
    Py_END_ALLOW_THREADS

    if (result.nonce_error) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to serialize nonce.");
        return NULL;
    }

    if (result.found) {
        digest_to_hex(result.digest, hex_digest);
    } else {
        hex_digest[0] = '\0';
    }

    return Py_BuildValue(
        "KsiiK",
        result.nonce,
        hex_digest,
        result.found,
        result.cancelled,
        result.attempts
    );
}

static PyObject *request_cancel(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
    STORE_CANCEL_REQUESTED(1);
    Py_RETURN_NONE;
}

static PyObject *reset_cancel(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
    STORE_CANCEL_REQUESTED(0);
    Py_RETURN_NONE;
}

static PyObject *gpu_available(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
#ifdef __APPLE__
    if (metal_pow_is_available()) {
        Py_RETURN_TRUE;
    }
#endif
    Py_RETURN_FALSE;
}

static PyObject *gpu_properties(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
#ifdef __APPLE__
    unsigned int thread_execution_width = 0;
    unsigned int max_threads_per_threadgroup = 0;

    if (
        metal_pow_gpu_properties(
            &thread_execution_width,
            &max_threads_per_threadgroup
        )
    ) {
        return Py_BuildValue("II", thread_execution_width, max_threads_per_threadgroup);
    }
#endif
    Py_RETURN_NONE;
}

static PyObject *mine_pow_gpu(PyObject *Py_UNUSED(self), PyObject *args) {
    const char *prefix = NULL;
    Py_ssize_t prefix_length = 0;
    int difficulty_bits = 0;
    unsigned long long start_nonce = 0;
    unsigned long long progress_interval = 0;
    unsigned long long batch_size = DEFAULT_GPU_BATCH_SIZE;
    unsigned long long nonce_step = 1;
    unsigned long long nonces_per_thread = 0;
    unsigned long long threads_per_group = 0;
    unsigned long long nonce = 0;
    char hex_digest[SHA256_HEX_LENGTH + 1];
    char error_message[256];
    int cancelled = 0;
    bool success = false;

    if (!PyArg_ParseTuple(
            args,
            "s#i|KKKKKK",
            &prefix,
            &prefix_length,
            &difficulty_bits,
            &start_nonce,
            &progress_interval,
            &batch_size,
            &nonce_step,
            &nonces_per_thread,
            &threads_per_group)) {
        return NULL;
    }

#ifdef __APPLE__
    Py_BEGIN_ALLOW_THREADS
    success = metal_mine_pow(
        prefix,
        (size_t)prefix_length,
        difficulty_bits,
        start_nonce,
        progress_interval,
        batch_size,
        nonce_step,
        nonces_per_thread,
        threads_per_group,
        &nonce,
        hex_digest,
        &cancelled,
        error_message,
        sizeof(error_message));
    Py_END_ALLOW_THREADS

    if (!success) {
        PyErr_SetString(PyExc_RuntimeError, error_message);
        return NULL;
    }

    return Py_BuildValue("Ksi", nonce, hex_digest, cancelled);
#else
    PyErr_SetString(PyExc_RuntimeError, "GPU proof-of-work is only supported on macOS Metal.");
    return NULL;
#endif
}

static PyObject *mine_pow_gpu_chunk(PyObject *Py_UNUSED(self), PyObject *args) {
    const char *prefix = NULL;
    Py_ssize_t prefix_length = 0;
    int difficulty_bits = 0;
    unsigned long long start_nonce = 0;
    unsigned long long max_attempts = 0;
    unsigned long long nonce_step = 1;
    unsigned long long nonces_per_thread = 0;
    unsigned long long threads_per_group = 0;
    unsigned long long batch_size = 0;
    unsigned long long nonce = 0;
    unsigned long long attempts = 0;
    char hex_digest[SHA256_HEX_LENGTH + 1];
    char error_message[256];
    int found = 0;
    int cancelled = 0;
    bool success = false;

    if (!PyArg_ParseTuple(
            args,
            "s#iKK|KKKK",
            &prefix,
            &prefix_length,
            &difficulty_bits,
            &start_nonce,
            &max_attempts,
            &nonce_step,
            &nonces_per_thread,
            &threads_per_group,
            &batch_size)) {
        return NULL;
    }

    if (difficulty_bits < 0 || difficulty_bits > 256) {
        PyErr_SetString(PyExc_ValueError, "difficulty_bits must be between 0 and 256.");
        return NULL;
    }
    if (max_attempts == 0) {
        PyErr_SetString(PyExc_ValueError, "max_attempts must be at least 1.");
        return NULL;
    }
    if (nonce_step == 0) {
        PyErr_SetString(PyExc_ValueError, "nonce_step must be at least 1.");
        return NULL;
    }

#ifdef __APPLE__
    Py_BEGIN_ALLOW_THREADS
    success = metal_mine_pow_range(
        prefix,
        (size_t)prefix_length,
        difficulty_bits,
        start_nonce,
        max_attempts,
        0,
        batch_size == 0 ? max_attempts : batch_size,
        nonce_step,
        nonces_per_thread,
        threads_per_group,
        &nonce,
        hex_digest,
        &attempts,
        &found,
        &cancelled,
        error_message,
        sizeof(error_message));
    Py_END_ALLOW_THREADS

    if (!success) {
        PyErr_SetString(PyExc_RuntimeError, error_message);
        return NULL;
    }

    return Py_BuildValue("KsiiK", nonce, hex_digest, found, cancelled, attempts);
#else
    PyErr_SetString(PyExc_RuntimeError, "GPU proof-of-work is only supported on macOS Metal.");
    return NULL;
#endif
}

static PyMethodDef NativePowMethods[] = {
    {
        "mine_pow",
        mine_pow,
        METH_VARARGS,
        "Run proof of work and return the winning nonce and SHA-256 hash."
    },
    {
        "mine_pow_chunk",
        mine_pow_chunk,
        METH_VARARGS,
        "Run proof of work for a bounded nonce range."
    },
    {
        "request_cancel",
        request_cancel,
        METH_NOARGS,
        "Request cancellation of the current proof-of-work loop."
    },
    {
        "reset_cancel",
        reset_cancel,
        METH_NOARGS,
        "Reset the proof-of-work cancellation flag."
    },
    {
        "gpu_available",
        gpu_available,
        METH_NOARGS,
        "Return whether the Metal proof-of-work backend is available."
    },
    {
        "gpu_properties",
        gpu_properties,
        METH_NOARGS,
        "Return the Metal pipeline thread execution width and max threads per threadgroup."
    },
    {
        "mine_pow_gpu",
        mine_pow_gpu,
        METH_VARARGS,
        "Run proof of work on the GPU and return the winning nonce and SHA-256 hash."
    },
    {
        "mine_pow_gpu_chunk",
        mine_pow_gpu_chunk,
        METH_VARARGS,
        "Run GPU proof of work for a bounded nonce range."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_pow_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "native_pow",
    .m_doc = "Native proof-of-work module for UncCoin.",
    .m_size = -1,
    .m_methods = NativePowMethods,
};

PyMODINIT_FUNC PyInit_native_pow(void) {
#if UNCCOIN_HAS_ARM_SHA2_INTRINSICS
    cpu_sha256_acceleration_available = detect_cpu_sha256_acceleration();
#endif
    return PyModule_Create(&native_pow_module);
}
