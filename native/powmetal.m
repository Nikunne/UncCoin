#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "powmetal.h"

extern int pow_cancel_requested(void);

#define SHA256_HEX_LENGTH 64
#define SHA256_BINARY_LENGTH 32
#define NONCE_BUFFER_LENGTH 32
#define MAX_FIXED_DIGIT_LENGTH 20
#define DEFAULT_GPU_BATCH_SIZE 262144
#define DEFAULT_GPU_NONCES_PER_THREAD 8U
#define METAL_PERSISTENT_GROUP_MULTIPLIER 128

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint32_t data_length;
    uint8_t data[64];
} sha256_context;

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint32_t data_length;
    uint8_t data[64];
} metal_prefix_context;

typedef struct {
    size_t first_nonce_offset;
    size_t first_nonce_length;
    size_t second_nonce_length;
    bool uses_second_block;
    uint8_t first_block[64];
    uint8_t second_block[64];
} host_prepared_nonce_blocks;

typedef struct {
    uint32_t difficulty_bits;
    uint32_t nonce_count;
    uint32_t nonces_per_thread;
    uint32_t reserved;
    uint64_t start_nonce;
    uint64_t nonce_step;
} metal_mining_params;

typedef struct {
    uint32_t found;
    uint32_t padding;
    uint64_t nonce;
    uint8_t digest[SHA256_BINARY_LENGTH];
} metal_mining_result;

typedef struct {
    uint32_t next_candidate_index;
    uint32_t padding[3];
} metal_mining_queue;

typedef struct {
    uint32_t digit_word_index[MAX_FIXED_DIGIT_LENGTH];
    uint32_t digit_shift[MAX_FIXED_DIGIT_LENGTH];
    uint32_t block_words[16];
} metal_fixed_one_block_template;

typedef struct {
    uint32_t first_digit_count;
    uint32_t second_digit_count;
    uint32_t first_digit_word_index[MAX_FIXED_DIGIT_LENGTH];
    uint32_t first_digit_shift[MAX_FIXED_DIGIT_LENGTH];
    uint32_t second_digit_word_index[MAX_FIXED_DIGIT_LENGTH];
    uint32_t second_digit_shift[MAX_FIXED_DIGIT_LENGTH];
    uint32_t first_block_words[16];
    uint32_t second_block_words[16];
} metal_fixed_two_block_template;

static const unsigned long long DECIMAL_DIGIT_BOUNDARIES[MAX_FIXED_DIGIT_LENGTH] = {
    9ULL,
    99ULL,
    999ULL,
    9999ULL,
    99999ULL,
    999999ULL,
    9999999ULL,
    99999999ULL,
    999999999ULL,
    9999999999ULL,
    99999999999ULL,
    999999999999ULL,
    9999999999999ULL,
    99999999999999ULL,
    999999999999999ULL,
    9999999999999999ULL,
    99999999999999999ULL,
    999999999999999999ULL,
    9999999999999999999ULL,
    ULLONG_MAX
};

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

static NSString *const POW_METAL_SOURCE =
    @"#include <metal_stdlib>\n"
    "using namespace metal;\n"
    "#define SHA256_BINARY_LENGTH 32\n"
    "#define NONCE_BUFFER_LENGTH 32\n"
    "struct SHA256Context {\n"
    "    uint state[8];\n"
    "    ulong bit_length;\n"
    "    uint data_length;\n"
    "    uchar data[64];\n"
    "};\n"
    "struct MiningParams {\n"
    "    uint difficulty_bits;\n"
    "    uint nonce_count;\n"
    "    uint nonces_per_thread;\n"
    "    uint reserved;\n"
    "    ulong start_nonce;\n"
    "    ulong nonce_step;\n"
    "};\n"
    "struct MiningResult {\n"
    "    atomic_uint found;\n"
    "    uint padding;\n"
    "    ulong nonce;\n"
    "    uchar digest[SHA256_BINARY_LENGTH];\n"
    "};\n"
    "struct MiningQueue {\n"
    "    atomic_uint next_candidate_index;\n"
    "    uint padding0;\n"
    "    uint padding1;\n"
    "    uint padding2;\n"
    "};\n"
    "struct FixedDigitOneBlockTemplate {\n"
    "    uint digit_word_index[20];\n"
    "    uint digit_shift[20];\n"
    "    uint block_words[16];\n"
    "};\n"
    "struct FixedDigitTwoBlockTemplate {\n"
    "    uint first_digit_count;\n"
    "    uint second_digit_count;\n"
    "    uint first_digit_word_index[20];\n"
    "    uint first_digit_shift[20];\n"
    "    uint second_digit_word_index[20];\n"
    "    uint second_digit_shift[20];\n"
    "    uint first_block_words[16];\n"
    "    uint second_block_words[16];\n"
    "};\n"
    "constant uint FIXED_DIGIT_COUNT [[function_constant(0)]];\n"
    "constant uint SHA256_K[64] = {\n"
    "0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,\n"
    "0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,\n"
    "0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,\n"
    "0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,\n"
    "0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,\n"
    "0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,\n"
    "0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,\n"
    "0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,\n"
    "0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,\n"
    "0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,\n"
    "0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,\n"
    "0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,\n"
    "0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,\n"
    "0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,\n"
    "0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,\n"
    "0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};\n"
    "inline uint rotr(uint value, uint bits) { return (value >> bits) | (value << (32u - bits)); }\n"
    "inline uint sha256_schedule_sigma0(uint value) { return rotr(value, 7u) ^ rotr(value, 18u) ^ (value >> 3u); }\n"
    "inline uint sha256_schedule_sigma1(uint value) { return rotr(value, 17u) ^ rotr(value, 19u) ^ (value >> 10u); }\n"
    "inline uint sha256_big_sigma0(uint value) { return rotr(value, 2u) ^ rotr(value, 13u) ^ rotr(value, 22u); }\n"
    "inline uint sha256_big_sigma1(uint value) { return rotr(value, 6u) ^ rotr(value, 11u) ^ rotr(value, 25u); }\n"
    "inline void sha256_round(thread uint &a,\n"
    "                         thread uint &b,\n"
    "                         thread uint &c,\n"
    "                         thread uint &d,\n"
    "                         thread uint &e,\n"
    "                         thread uint &f,\n"
    "                         thread uint &g,\n"
    "                         thread uint &h,\n"
    "                         uint word,\n"
    "                         uint round_constant) {\n"
    "    uint temp1 = h + sha256_big_sigma1(e) + ((e & f) ^ ((~e) & g)) + round_constant + word;\n"
    "    uint temp2 = sha256_big_sigma0(a) + ((a & b) ^ (a & c) ^ (b & c));\n"
    "    h = g;\n"
    "    g = f;\n"
    "    f = e;\n"
    "    e = d + temp1;\n"
    "    d = c;\n"
    "    c = b;\n"
    "    b = a;\n"
    "    a = temp1 + temp2;\n"
    "}\n"
    "inline void sha256_transform_words(thread SHA256Context &context, thread const uint input_words[16]) {\n"
    "    uint schedule[16];\n"
    "    for (uint i = 0; i < 16; ++i) {\n"
    "        schedule[i] = input_words[i];\n"
    "    }\n"
    "    uint a = context.state[0]; uint b = context.state[1]; uint c = context.state[2]; uint d = context.state[3];\n"
    "    uint e = context.state[4]; uint f = context.state[5]; uint g = context.state[6]; uint h = context.state[7];\n"
    "    for (uint i = 0; i < 16; ++i) {\n"
    "        sha256_round(a, b, c, d, e, f, g, h, schedule[i], SHA256_K[i]);\n"
    "    }\n"
    "    for (uint i = 16; i < 64; ++i) {\n"
    "        uint slot = i & 15u;\n"
    "        uint word = schedule[slot] +\n"
    "                    sha256_schedule_sigma0(schedule[(slot + 1u) & 15u]) +\n"
    "                    schedule[(slot + 9u) & 15u] +\n"
    "                    sha256_schedule_sigma1(schedule[(slot + 14u) & 15u]);\n"
    "        schedule[slot] = word;\n"
    "        sha256_round(a, b, c, d, e, f, g, h, word, SHA256_K[i]);\n"
    "    }\n"
    "    context.state[0] += a; context.state[1] += b; context.state[2] += c; context.state[3] += d;\n"
    "    context.state[4] += e; context.state[5] += f; context.state[6] += g; context.state[7] += h;\n"
    "}\n"
    "inline void sha256_transform(thread SHA256Context &context, thread const uchar data[64]) {\n"
    "    uint words[16];\n"
    "    for (uint i = 0; i < 16; ++i) {\n"
    "        words[i] = ((uint)data[i * 4] << 24) | ((uint)data[i * 4 + 1] << 16) |\n"
    "                   ((uint)data[i * 4 + 2] << 8) | ((uint)data[i * 4 + 3]);\n"
    "    }\n"
    "    sha256_transform_words(context, words);\n"
    "}\n"
    "struct PreparedNonceBlocks {\n"
    "    uint first_nonce_offset;\n"
    "    uint first_nonce_length;\n"
    "    uint second_nonce_length;\n"
    "    uint uses_second_block;\n"
    "    uchar first_block[64];\n"
    "    uchar second_block[64];\n"
    "};\n"
    "struct PreparedSingleBlock {\n"
    "    uint nonce_offset;\n"
    "    uint nonce_length;\n"
    "    uchar block[64];\n"
    "};\n"
    "inline void write_sha256_length(thread uchar block[64], ulong total_bit_length) {\n"
    "    block[63] = (uchar)(total_bit_length);\n"
    "    block[62] = (uchar)(total_bit_length >> 8);\n"
    "    block[61] = (uchar)(total_bit_length >> 16);\n"
    "    block[60] = (uchar)(total_bit_length >> 24);\n"
    "    block[59] = (uchar)(total_bit_length >> 32);\n"
    "    block[58] = (uchar)(total_bit_length >> 40);\n"
    "    block[57] = (uchar)(total_bit_length >> 48);\n"
    "    block[56] = (uchar)(total_bit_length >> 56);\n"
    "}\n"
    "inline void prepare_nonce_blocks(thread const SHA256Context &prefix_context,\n"
    "                                 thread const uchar *nonce_buffer,\n"
    "                                 uint nonce_length,\n"
    "                                 thread PreparedNonceBlocks &prepared) {\n"
    "    uint prefix_remainder = prefix_context.data_length;\n"
    "    uint first_available = 64u - prefix_remainder;\n"
    "    uint first_nonce_length = nonce_length;\n"
    "    ulong total_bit_length = prefix_context.bit_length + ((ulong)(prefix_remainder + nonce_length) * 8ul);\n"
    "    prepared.first_nonce_offset = prefix_remainder;\n"
    "    prepared.first_nonce_length = 0u;\n"
    "    prepared.second_nonce_length = 0u;\n"
    "    prepared.uses_second_block = 0u;\n"
    "    for (uint i = 0; i < 64u; ++i) {\n"
    "        prepared.first_block[i] = 0u;\n"
    "        prepared.second_block[i] = 0u;\n"
    "    }\n"
    "    for (uint i = 0; i < prefix_remainder; ++i) { prepared.first_block[i] = prefix_context.data[i]; }\n"
    "    if (first_nonce_length > first_available) { first_nonce_length = first_available; }\n"
    "    prepared.first_nonce_length = first_nonce_length;\n"
    "    prepared.second_nonce_length = nonce_length - first_nonce_length;\n"
    "    if (prepared.second_nonce_length > 0u) { prepared.uses_second_block = 1u; }\n"
    "    for (uint i = 0; i < prepared.first_nonce_length; ++i) {\n"
    "        prepared.first_block[prepared.first_nonce_offset + i] = nonce_buffer[i];\n"
    "    }\n"
    "    for (uint i = 0; i < prepared.second_nonce_length; ++i) {\n"
    "        prepared.second_block[i] = nonce_buffer[prepared.first_nonce_length + i];\n"
    "    }\n"
    "    if (prepared.uses_second_block != 0u) {\n"
    "        prepared.second_block[prepared.second_nonce_length] = 0x80u;\n"
    "        write_sha256_length(prepared.second_block, total_bit_length);\n"
    "        return;\n"
    "    }\n"
    "    uint total_suffix_offset = prefix_remainder + prepared.first_nonce_length;\n"
    "    if (total_suffix_offset < 56u) {\n"
    "        prepared.first_block[total_suffix_offset] = 0x80u;\n"
    "        write_sha256_length(prepared.first_block, total_bit_length);\n"
    "        return;\n"
    "    }\n"
    "    prepared.uses_second_block = 1u;\n"
    "    if (total_suffix_offset < 64u) {\n"
    "        prepared.first_block[total_suffix_offset] = 0x80u;\n"
    "    } else {\n"
    "        prepared.second_block[0] = 0x80u;\n"
    "    }\n"
    "    write_sha256_length(prepared.second_block, total_bit_length);\n"
    "}\n"
    "inline void prepare_single_block(thread const SHA256Context &prefix_context,\n"
    "                                 thread const uchar *nonce_buffer,\n"
    "                                 uint nonce_length,\n"
    "                                 thread PreparedSingleBlock &prepared) {\n"
    "    uint prefix_remainder = prefix_context.data_length;\n"
    "    ulong total_bit_length = prefix_context.bit_length + ((ulong)(prefix_remainder + nonce_length) * 8ul);\n"
    "    prepared.nonce_offset = prefix_remainder;\n"
    "    prepared.nonce_length = nonce_length;\n"
    "    for (uint i = 0; i < 64u; ++i) { prepared.block[i] = 0u; }\n"
    "    for (uint i = 0; i < prefix_remainder; ++i) { prepared.block[i] = prefix_context.data[i]; }\n"
    "    for (uint i = 0; i < nonce_length; ++i) {\n"
    "        prepared.block[prefix_remainder + i] = nonce_buffer[i];\n"
    "    }\n"
    "    prepared.block[prefix_remainder + nonce_length] = 0x80u;\n"
    "    write_sha256_length(prepared.block, total_bit_length);\n"
    "}\n"
    "inline void sha256_digest_prepared_state(thread const SHA256Context &prefix_context,\n"
    "                                         thread const PreparedNonceBlocks &prepared,\n"
    "                                         thread uint state[8]) {\n"
    "    SHA256Context context;\n"
    "    for (uint i = 0; i < 8u; ++i) { context.state[i] = prefix_context.state[i]; }\n"
    "    sha256_transform(context, prepared.first_block);\n"
    "    if (prepared.uses_second_block != 0u) { sha256_transform(context, prepared.second_block); }\n"
    "    for (uint i = 0; i < 8u; ++i) { state[i] = context.state[i]; }\n"
    "}\n"
    "inline void sha256_digest_single_block_state(thread const SHA256Context &prefix_context,\n"
    "                                             thread const PreparedSingleBlock &prepared,\n"
    "                                             thread uint state[8]) {\n"
    "    SHA256Context context;\n"
    "    for (uint i = 0; i < 8u; ++i) { context.state[i] = prefix_context.state[i]; }\n"
    "    sha256_transform(context, prepared.block);\n"
    "    for (uint i = 0; i < 8u; ++i) { state[i] = context.state[i]; }\n"
    "}\n"
    "inline void sha256_digest_single_block_words_state(thread const SHA256Context &prefix_context,\n"
    "                                                   thread const uint block_words[16],\n"
    "                                                   thread uint state[8]) {\n"
    "    SHA256Context context;\n"
    "    for (uint i = 0; i < 8u; ++i) { context.state[i] = prefix_context.state[i]; }\n"
    "    sha256_transform_words(context, block_words);\n"
    "    for (uint i = 0; i < 8u; ++i) { state[i] = context.state[i]; }\n"
    "}\n"
    "inline void sha256_digest_two_block_words_state(thread const SHA256Context &prefix_context,\n"
    "                                                thread const uint first_block_words[16],\n"
    "                                                thread const uint second_block_words[16],\n"
    "                                                thread uint state[8]) {\n"
    "    SHA256Context context;\n"
    "    for (uint i = 0; i < 8u; ++i) { context.state[i] = prefix_context.state[i]; }\n"
    "    sha256_transform_words(context, first_block_words);\n"
    "    sha256_transform_words(context, second_block_words);\n"
    "    for (uint i = 0; i < 8u; ++i) { state[i] = context.state[i]; }\n"
    "}\n"
    "inline void sha256_state_to_digest(thread const uint state[8],\n"
    "                                   device uchar *hash) {\n"
    "    for (uint i = 0; i < 4u; ++i) {\n"
    "        hash[i] = (uchar)((state[0] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 4u] = (uchar)((state[1] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 8u] = (uchar)((state[2] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 12u] = (uchar)((state[3] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 16u] = (uchar)((state[4] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 20u] = (uchar)((state[5] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 24u] = (uchar)((state[6] >> (24u - i * 8u)) & 0xFFu);\n"
    "        hash[i + 28u] = (uchar)((state[7] >> (24u - i * 8u)) & 0xFFu);\n"
    "    }\n"
    "}\n"
    "inline bool has_leading_zero_bits_state(thread const uint state[8], uint difficulty_bits) {\n"
    "    uint full_zero_words = difficulty_bits / 32u;\n"
    "    uint remaining_bits = difficulty_bits % 32u;\n"
    "    for (uint i = 0; i < full_zero_words; ++i) {\n"
    "        if (state[i] != 0u) { return false; }\n"
    "    }\n"
    "    if (remaining_bits == 0u) { return true; }\n"
    "    return (state[full_zero_words] & (0xFFFFFFFFu << (32u - remaining_bits))) == 0u;\n"
    "}\n"
    "inline uint nonce_to_ascii(ulong nonce, thread uchar out_chars[NONCE_BUFFER_LENGTH]) {\n"
    "    if (nonce == 0ul) { out_chars[0] = '0'; return 1u; }\n"
    "    uchar reversed[NONCE_BUFFER_LENGTH];\n"
    "    uint length = 0u;\n"
    "    while (nonce > 0ul) {\n"
    "        reversed[length++] = (uchar)('0' + (nonce % 10ul));\n"
    "        nonce /= 10ul;\n"
    "    }\n"
    "    for (uint i = 0; i < length; ++i) { out_chars[i] = reversed[length - i - 1u]; }\n"
    "    return length;\n"
    "}\n"
    "inline int increment_ascii_decimal(thread uchar buffer[NONCE_BUFFER_LENGTH],\n"
    "                                   thread uint &length,\n"
    "                                   ulong increment) {\n"
    "    int index = (int)length - 1;\n"
    "    int changed_index = (int)length;\n"
    "    ulong carry = increment;\n"
    "    while (index >= 0 && carry > 0ul) {\n"
    "        ulong sum = (ulong)(buffer[index] - '0') + (carry % 10ul);\n"
    "        carry /= 10ul;\n"
    "        if (sum >= 10ul) {\n"
    "            sum -= 10ul;\n"
    "            carry += 1ul;\n"
    "        }\n"
    "        buffer[index] = (uchar)('0' + sum);\n"
    "        changed_index = index;\n"
    "        index -= 1;\n"
    "    }\n"
    "    if (carry == 0ul) {\n"
    "        return changed_index < (int)length ? changed_index : (int)length - 1;\n"
    "    }\n"
    "    uchar prefix[NONCE_BUFFER_LENGTH];\n"
    "    uint prefix_length = 0u;\n"
    "    while (carry > 0ul) {\n"
    "        prefix[prefix_length++] = (uchar)('0' + (carry % 10ul));\n"
    "        carry /= 10ul;\n"
    "    }\n"
    "    if (length + prefix_length >= NONCE_BUFFER_LENGTH) { return -1; }\n"
    "    for (int move_index = (int)length - 1; move_index >= 0; --move_index) {\n"
    "        buffer[(uint)move_index + prefix_length] = buffer[move_index];\n"
    "    }\n"
    "    for (uint prefix_index = 0u; prefix_index < prefix_length; ++prefix_index) {\n"
    "        buffer[prefix_index] = prefix[prefix_length - prefix_index - 1u];\n"
    "    }\n"
    "    length += prefix_length;\n"
    "    return 0;\n"
    "}\n"
    "inline int increment_ascii_decimal_one(thread uchar buffer[NONCE_BUFFER_LENGTH],\n"
    "                                       thread uint &length) {\n"
    "    int index = (int)length - 1;\n"
    "    while (index >= 0 && buffer[index] == '9') {\n"
    "        buffer[index] = '0';\n"
    "        index -= 1;\n"
    "    }\n"
    "    if (index >= 0) {\n"
    "        buffer[index] = (uchar)(buffer[index] + 1);\n"
    "        return index;\n"
    "    }\n"
    "    if (length + 1u >= NONCE_BUFFER_LENGTH) { return -1; }\n"
    "    for (int move_index = (int)length - 1; move_index >= 0; --move_index) {\n"
    "        buffer[(uint)move_index + 1u] = buffer[move_index];\n"
    "    }\n"
    "    buffer[0] = '1';\n"
    "    length += 1u;\n"
    "    return 0;\n"
    "}\n"
    "inline void nonce_to_ascii_fixed_digits(ulong nonce, thread uchar out_chars[NONCE_BUFFER_LENGTH]) {\n"
    "    for (int index = (int)FIXED_DIGIT_COUNT - 1; index >= 0; --index) {\n"
    "        out_chars[index] = (uchar)('0' + (nonce % 10ul));\n"
    "        nonce /= 10ul;\n"
    "    }\n"
    "}\n"
    "inline int increment_ascii_fixed_digits_one(thread uchar buffer[NONCE_BUFFER_LENGTH]) {\n"
    "    int index = (int)FIXED_DIGIT_COUNT - 1;\n"
    "    while (index >= 0 && buffer[index] == '9') {\n"
    "        buffer[index] = '0';\n"
    "        index -= 1;\n"
    "    }\n"
    "    if (index < 0) { return -1; }\n"
    "    buffer[index] = (uchar)(buffer[index] + 1);\n"
    "    return index;\n"
    "}\n"
    "inline void initialize_fixed_one_block_words(thread uint block_words[16],\n"
    "                                            device const FixedDigitOneBlockTemplate *prepared,\n"
    "                                            thread const uchar *nonce_buffer) {\n"
    "    for (uint i = 0; i < 16u; ++i) {\n"
    "        block_words[i] = prepared->block_words[i];\n"
    "    }\n"
    "    for (uint i = 0; i < FIXED_DIGIT_COUNT; ++i) {\n"
    "        uint shift = prepared->digit_shift[i];\n"
    "        uint word_index = prepared->digit_word_index[i];\n"
    "        block_words[word_index] =\n"
    "            (block_words[word_index] & ~(0xFFu << shift)) |\n"
    "            ((uint)nonce_buffer[i] << shift);\n"
    "    }\n"
    "}\n"
    "inline void update_fixed_one_block_words(thread uint block_words[16],\n"
    "                                        device const FixedDigitOneBlockTemplate *prepared,\n"
    "                                        thread const uchar *nonce_buffer,\n"
    "                                        int changed_index) {\n"
    "    if (changed_index < 0) { changed_index = 0; }\n"
    "    for (uint i = (uint)changed_index; i < FIXED_DIGIT_COUNT; ++i) {\n"
    "        uint shift = prepared->digit_shift[i];\n"
    "        uint word_index = prepared->digit_word_index[i];\n"
    "        block_words[word_index] =\n"
    "            (block_words[word_index] & ~(0xFFu << shift)) |\n"
    "            ((uint)nonce_buffer[i] << shift);\n"
    "    }\n"
    "}\n"
    "inline void initialize_fixed_two_block_words(thread uint first_block_words[16],\n"
    "                                            thread uint second_block_words[16],\n"
    "                                            device const FixedDigitTwoBlockTemplate *prepared,\n"
    "                                            thread const uchar *nonce_buffer) {\n"
    "    for (uint i = 0; i < 16u; ++i) {\n"
    "        first_block_words[i] = prepared->first_block_words[i];\n"
    "        second_block_words[i] = prepared->second_block_words[i];\n"
    "    }\n"
    "    for (uint i = 0; i < prepared->first_digit_count; ++i) {\n"
    "        uint shift = prepared->first_digit_shift[i];\n"
    "        uint word_index = prepared->first_digit_word_index[i];\n"
    "        first_block_words[word_index] =\n"
    "            (first_block_words[word_index] & ~(0xFFu << shift)) |\n"
    "            ((uint)nonce_buffer[i] << shift);\n"
    "    }\n"
    "    for (uint i = 0; i < prepared->second_digit_count; ++i) {\n"
    "        uint shift = prepared->second_digit_shift[i];\n"
    "        uint word_index = prepared->second_digit_word_index[i];\n"
    "        second_block_words[word_index] =\n"
    "            (second_block_words[word_index] & ~(0xFFu << shift)) |\n"
    "            ((uint)nonce_buffer[prepared->first_digit_count + i] << shift);\n"
    "    }\n"
    "}\n"
    "inline void update_fixed_two_block_words(thread uint first_block_words[16],\n"
    "                                        thread uint second_block_words[16],\n"
    "                                        device const FixedDigitTwoBlockTemplate *prepared,\n"
    "                                        thread const uchar *nonce_buffer,\n"
    "                                        int changed_index) {\n"
    "    if (changed_index < 0) { changed_index = 0; }\n"
    "    if ((uint)changed_index < prepared->first_digit_count) {\n"
    "        for (uint i = (uint)changed_index; i < prepared->first_digit_count; ++i) {\n"
    "            uint shift = prepared->first_digit_shift[i];\n"
    "            uint word_index = prepared->first_digit_word_index[i];\n"
    "            first_block_words[word_index] =\n"
    "                (first_block_words[word_index] & ~(0xFFu << shift)) |\n"
    "                ((uint)nonce_buffer[i] << shift);\n"
    "        }\n"
    "        for (uint i = 0; i < prepared->second_digit_count; ++i) {\n"
    "            uint shift = prepared->second_digit_shift[i];\n"
    "            uint word_index = prepared->second_digit_word_index[i];\n"
    "            second_block_words[word_index] =\n"
    "                (second_block_words[word_index] & ~(0xFFu << shift)) |\n"
    "                ((uint)nonce_buffer[prepared->first_digit_count + i] << shift);\n"
    "        }\n"
    "        return;\n"
    "    }\n"
    "    uint second_changed_index = (uint)changed_index - prepared->first_digit_count;\n"
    "    for (uint i = second_changed_index; i < prepared->second_digit_count; ++i) {\n"
    "        uint shift = prepared->second_digit_shift[i];\n"
    "        uint word_index = prepared->second_digit_word_index[i];\n"
    "        second_block_words[word_index] =\n"
    "            (second_block_words[word_index] & ~(0xFFu << shift)) |\n"
    "            ((uint)nonce_buffer[prepared->first_digit_count + i] << shift);\n"
    "    }\n"
    "}\n"
    "inline void update_prepared_nonce_blocks(thread PreparedNonceBlocks &prepared,\n"
    "                                        thread const uchar *nonce_buffer,\n"
    "                                        int changed_index) {\n"
    "    if (changed_index < 0) { changed_index = 0; }\n"
    "    if ((uint)changed_index < prepared.first_nonce_length) {\n"
    "        for (uint i = (uint)changed_index; i < prepared.first_nonce_length; ++i) {\n"
    "            prepared.first_block[prepared.first_nonce_offset + i] = nonce_buffer[i];\n"
    "        }\n"
    "        if (prepared.second_nonce_length > 0u) {\n"
    "            for (uint i = 0u; i < prepared.second_nonce_length; ++i) {\n"
    "                prepared.second_block[i] = nonce_buffer[prepared.first_nonce_length + i];\n"
    "            }\n"
    "        }\n"
    "        return;\n"
    "    }\n"
    "    if (prepared.second_nonce_length > 0u) {\n"
    "        uint second_changed_index = (uint)changed_index - prepared.first_nonce_length;\n"
    "        if (second_changed_index < prepared.second_nonce_length) {\n"
    "            for (uint i = second_changed_index; i < prepared.second_nonce_length; ++i) {\n"
    "                prepared.second_block[i] = nonce_buffer[prepared.first_nonce_length + i];\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "}\n"
    "inline void update_single_block(thread PreparedSingleBlock &prepared,\n"
    "                                thread const uchar *nonce_buffer,\n"
    "                                int changed_index) {\n"
    "    if (changed_index < 0) { changed_index = 0; }\n"
    "    for (uint i = (uint)changed_index; i < prepared.nonce_length; ++i) {\n"
    "        prepared.block[prepared.nonce_offset + i] = nonce_buffer[i];\n"
    "    }\n"
    "}\n"
    "kernel void minePow(device const SHA256Context *prefix_context [[buffer(0)]],\n"
    "                    device const MiningParams *params [[buffer(1)]],\n"
    "                    device MiningResult *result [[buffer(2)]],\n"
    "                    device MiningQueue *queue [[buffer(3)]],\n"
    "                    uint gid [[thread_position_in_grid]]) {\n"
    "    (void)gid;\n"
    "    if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    SHA256Context prefix = prefix_context[0];\n"
    "    uchar nonce_chars[NONCE_BUFFER_LENGTH];\n"
    "    PreparedNonceBlocks prepared;\n"
    "    uint digest_state[8];\n"
    "    while (true) {\n"
    "        uint candidate_index = atomic_fetch_add_explicit(\n"
    "            &queue->next_candidate_index,\n"
    "            params->nonces_per_thread,\n"
    "            memory_order_relaxed\n"
    "        );\n"
    "        if ((ulong)candidate_index >= (ulong)params->nonce_count) { return; }\n"
    "        ulong nonce = params->start_nonce + ((ulong)candidate_index * params->nonce_step);\n"
    "        uint nonce_length = nonce_to_ascii(nonce, nonce_chars);\n"
    "        prepare_nonce_blocks(prefix, nonce_chars, nonce_length, prepared);\n"
    "        uint checked = 0u;\n"
    "        uint max_checks = params->nonces_per_thread;\n"
    "        ulong remaining = (ulong)params->nonce_count - (ulong)candidate_index;\n"
    "        if (remaining < (ulong)max_checks) { max_checks = (uint)remaining; }\n"
    "        while (checked < max_checks) {\n"
    "            if (checked > 0u) {\n"
    "                uint previous_nonce_length = nonce_length;\n"
    "                int changed_index = params->nonce_step == 1ul\n"
    "                    ? increment_ascii_decimal_one(nonce_chars, nonce_length)\n"
    "                    : increment_ascii_decimal(nonce_chars, nonce_length, params->nonce_step);\n"
    "                if (changed_index < 0) { return; }\n"
    "                nonce += params->nonce_step;\n"
    "                if (nonce_length != previous_nonce_length) {\n"
    "                    prepare_nonce_blocks(prefix, nonce_chars, nonce_length, prepared);\n"
    "                } else {\n"
    "                    update_prepared_nonce_blocks(prepared, nonce_chars, changed_index);\n"
    "                }\n"
    "            }\n"
    "            sha256_digest_prepared_state(prefix, prepared, digest_state);\n"
    "            if (has_leading_zero_bits_state(digest_state, params->difficulty_bits)) {\n"
    "                if (atomic_exchange_explicit(&result->found, 1u, memory_order_relaxed) == 0u) {\n"
    "                    result->nonce = nonce;\n"
    "                    sha256_state_to_digest(digest_state, result->digest);\n"
    "                }\n"
    "                return;\n"
    "            }\n"
    "            checked += 1u;\n"
    "            if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "        }\n"
    "        if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    }\n"
    "}\n"
    "kernel void minePowOneBlockStep1(device const SHA256Context *prefix_context [[buffer(0)]],\n"
    "                                 device const MiningParams *params [[buffer(1)]],\n"
    "                                 device MiningResult *result [[buffer(2)]],\n"
    "                                 device MiningQueue *queue [[buffer(3)]],\n"
    "                                 uint gid [[thread_position_in_grid]]) {\n"
    "    (void)gid;\n"
    "    if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    SHA256Context prefix = prefix_context[0];\n"
    "    uchar nonce_chars[NONCE_BUFFER_LENGTH];\n"
    "    PreparedSingleBlock prepared;\n"
    "    uint digest_state[8];\n"
    "    while (true) {\n"
    "        uint candidate_index = atomic_fetch_add_explicit(\n"
    "            &queue->next_candidate_index,\n"
    "            params->nonces_per_thread,\n"
    "            memory_order_relaxed\n"
    "        );\n"
    "        if ((ulong)candidate_index >= (ulong)params->nonce_count) { return; }\n"
    "        ulong nonce = params->start_nonce + (ulong)candidate_index;\n"
    "        uint nonce_length = nonce_to_ascii(nonce, nonce_chars);\n"
    "        prepare_single_block(prefix, nonce_chars, nonce_length, prepared);\n"
    "        uint checked = 0u;\n"
    "        uint max_checks = params->nonces_per_thread;\n"
    "        ulong remaining = (ulong)params->nonce_count - (ulong)candidate_index;\n"
    "        if (remaining < (ulong)max_checks) { max_checks = (uint)remaining; }\n"
    "        while (checked < max_checks) {\n"
    "            if (checked > 0u) {\n"
    "                uint previous_nonce_length = nonce_length;\n"
    "                int changed_index = increment_ascii_decimal_one(nonce_chars, nonce_length);\n"
    "                if (changed_index < 0) { return; }\n"
    "                nonce += 1ul;\n"
    "                if (nonce_length != previous_nonce_length) {\n"
    "                    prepare_single_block(prefix, nonce_chars, nonce_length, prepared);\n"
    "                } else {\n"
    "                    update_single_block(prepared, nonce_chars, changed_index);\n"
    "                }\n"
    "            }\n"
    "            sha256_digest_single_block_state(prefix, prepared, digest_state);\n"
    "            if (has_leading_zero_bits_state(digest_state, params->difficulty_bits)) {\n"
    "                if (atomic_exchange_explicit(&result->found, 1u, memory_order_relaxed) == 0u) {\n"
    "                    result->nonce = nonce;\n"
    "                    sha256_state_to_digest(digest_state, result->digest);\n"
    "                }\n"
    "                return;\n"
    "            }\n"
    "            checked += 1u;\n"
    "            if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "        }\n"
    "        if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    }\n"
    "}\n"
    "kernel void minePowFixedDigitsOneBlock(device const SHA256Context *prefix_context [[buffer(0)]],\n"
    "                                       device const MiningParams *params [[buffer(1)]],\n"
    "                                       device MiningResult *result [[buffer(2)]],\n"
    "                                       device MiningQueue *queue [[buffer(3)]],\n"
    "                                       device const FixedDigitOneBlockTemplate *prepared [[buffer(4)]],\n"
    "                                       uint gid [[thread_position_in_grid]]) {\n"
    "    (void)gid;\n"
    "    if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    SHA256Context prefix = prefix_context[0];\n"
    "    uchar nonce_chars[NONCE_BUFFER_LENGTH];\n"
    "    uint block_words[16];\n"
    "    uint digest_state[8];\n"
    "    while (true) {\n"
    "        uint candidate_index = atomic_fetch_add_explicit(\n"
    "            &queue->next_candidate_index,\n"
    "            params->nonces_per_thread,\n"
    "            memory_order_relaxed\n"
    "        );\n"
    "        if ((ulong)candidate_index >= (ulong)params->nonce_count) { return; }\n"
    "        ulong nonce = params->start_nonce + (ulong)candidate_index;\n"
    "        nonce_to_ascii_fixed_digits(nonce, nonce_chars);\n"
    "        initialize_fixed_one_block_words(block_words, prepared, nonce_chars);\n"
    "        uint checked = 0u;\n"
    "        uint max_checks = params->nonces_per_thread;\n"
    "        ulong remaining = (ulong)params->nonce_count - (ulong)candidate_index;\n"
    "        if (remaining < (ulong)max_checks) { max_checks = (uint)remaining; }\n"
    "        while (checked < max_checks) {\n"
    "            sha256_digest_single_block_words_state(prefix, block_words, digest_state);\n"
    "            if (has_leading_zero_bits_state(digest_state, params->difficulty_bits)) {\n"
    "                if (atomic_exchange_explicit(&result->found, 1u, memory_order_relaxed) == 0u) {\n"
    "                    result->nonce = nonce;\n"
    "                    sha256_state_to_digest(digest_state, result->digest);\n"
    "                }\n"
    "                return;\n"
    "            }\n"
    "            checked += 1u;\n"
    "            if (checked >= max_checks) { break; }\n"
    "            int changed_index = increment_ascii_fixed_digits_one(nonce_chars);\n"
    "            if (changed_index < 0) { return; }\n"
    "            nonce += 1ul;\n"
    "            update_fixed_one_block_words(block_words, prepared, nonce_chars, changed_index);\n"
    "            if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "        }\n"
    "        if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    }\n"
    "}\n"
    "kernel void minePowFixedDigitsTwoBlock(device const SHA256Context *prefix_context [[buffer(0)]],\n"
    "                                       device const MiningParams *params [[buffer(1)]],\n"
    "                                       device MiningResult *result [[buffer(2)]],\n"
    "                                       device MiningQueue *queue [[buffer(3)]],\n"
    "                                       device const FixedDigitTwoBlockTemplate *prepared [[buffer(4)]],\n"
    "                                       uint gid [[thread_position_in_grid]]) {\n"
    "    (void)gid;\n"
    "    if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    SHA256Context prefix = prefix_context[0];\n"
    "    uchar nonce_chars[NONCE_BUFFER_LENGTH];\n"
    "    uint first_block_words[16];\n"
    "    uint second_block_words[16];\n"
    "    uint digest_state[8];\n"
    "    while (true) {\n"
    "        uint candidate_index = atomic_fetch_add_explicit(\n"
    "            &queue->next_candidate_index,\n"
    "            params->nonces_per_thread,\n"
    "            memory_order_relaxed\n"
    "        );\n"
    "        if ((ulong)candidate_index >= (ulong)params->nonce_count) { return; }\n"
    "        ulong nonce = params->start_nonce + (ulong)candidate_index;\n"
    "        nonce_to_ascii_fixed_digits(nonce, nonce_chars);\n"
    "        initialize_fixed_two_block_words(first_block_words, second_block_words, prepared, nonce_chars);\n"
    "        uint checked = 0u;\n"
    "        uint max_checks = params->nonces_per_thread;\n"
    "        ulong remaining = (ulong)params->nonce_count - (ulong)candidate_index;\n"
    "        if (remaining < (ulong)max_checks) { max_checks = (uint)remaining; }\n"
    "        while (checked < max_checks) {\n"
    "            sha256_digest_two_block_words_state(prefix, first_block_words, second_block_words, digest_state);\n"
    "            if (has_leading_zero_bits_state(digest_state, params->difficulty_bits)) {\n"
    "                if (atomic_exchange_explicit(&result->found, 1u, memory_order_relaxed) == 0u) {\n"
    "                    result->nonce = nonce;\n"
    "                    sha256_state_to_digest(digest_state, result->digest);\n"
    "                }\n"
    "                return;\n"
    "            }\n"
    "            checked += 1u;\n"
    "            if (checked >= max_checks) { break; }\n"
    "            int changed_index = increment_ascii_fixed_digits_one(nonce_chars);\n"
    "            if (changed_index < 0) { return; }\n"
    "            nonce += 1ul;\n"
    "            update_fixed_two_block_words(first_block_words, second_block_words, prepared, nonce_chars, changed_index);\n"
    "            if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "        }\n"
    "        if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    }\n"
    "}\n";

static id<MTLDevice> metal_device = nil;
static id<MTLComputePipelineState> metal_pipeline = nil;
static id<MTLComputePipelineState> metal_pipeline_one_block_step1 = nil;
static id<MTLComputePipelineState> metal_pipeline_fixed_one_block[MAX_FIXED_DIGIT_LENGTH];
static id<MTLComputePipelineState> metal_pipeline_fixed_two_block[MAX_FIXED_DIGIT_LENGTH];
static dispatch_once_t metal_init_once;
static bool metal_available = false;
static NSString *const METAL_THREAD_QUEUE_KEY = @"unccoin.powmetal.thread_queue";

static inline uint32_t right_rotate(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32U - bits));
}

static void sha256_transform(sha256_context *context, const uint8_t data[64]) {
    uint32_t schedule[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    for (size_t index = 0; index < 16; index++) {
        schedule[index] = ((uint32_t)data[index * 4] << 24) |
                          ((uint32_t)data[index * 4 + 1] << 16) |
                          ((uint32_t)data[index * 4 + 2] << 8) |
                          ((uint32_t)data[index * 4 + 3]);
    }

    for (size_t index = 16; index < 64; index++) {
        uint32_t sigma0 = right_rotate(schedule[index - 15], 7) ^
                          right_rotate(schedule[index - 15], 18) ^
                          (schedule[index - 15] >> 3);
        uint32_t sigma1 = right_rotate(schedule[index - 2], 17) ^
                          right_rotate(schedule[index - 2], 19) ^
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
        uint32_t sum1 = right_rotate(e, 6) ^
                        right_rotate(e, 11) ^
                        right_rotate(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choose + SHA256_K[index] + schedule[index];
        uint32_t sum0 = right_rotate(a, 2) ^
                        right_rotate(a, 13) ^
                        right_rotate(a, 22);
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

static void digest_to_hex(const uint8_t *digest, char *hex_output) {
    static const char hex_chars[] = "0123456789abcdef";

    for (int index = 0; index < SHA256_BINARY_LENGTH; index++) {
        hex_output[index * 2] = hex_chars[(digest[index] >> 4) & 0xF];
        hex_output[index * 2 + 1] = hex_chars[digest[index] & 0xF];
    }

    hex_output[SHA256_HEX_LENGTH] = '\0';
}

static void copy_error_message(char *buffer, size_t buffer_length, NSString *message) {
    if (buffer == NULL || buffer_length == 0) {
        return;
    }

    const char *utf8_message = message != nil ? message.UTF8String : "Unknown Metal error.";
    if (utf8_message == NULL) {
        utf8_message = "Unknown Metal error.";
    }

    snprintf(buffer, buffer_length, "%s", utf8_message);
}

static unsigned int decimal_length_u64(unsigned long long value) {
    unsigned int length = 1;

    while (value >= 10ULL) {
        value /= 10ULL;
        length += 1U;
    }

    return length;
}

static void block_bytes_to_words(const uint8_t block[64], uint32_t words[16]) {
    for (size_t index = 0; index < 16; index++) {
        words[index] = ((uint32_t)block[index * 4] << 24) |
                       ((uint32_t)block[index * 4 + 1] << 16) |
                       ((uint32_t)block[index * 4 + 2] << 8) |
                       ((uint32_t)block[index * 4 + 3]);
    }
}

static void write_sha256_length_bytes(uint8_t block[64], uint64_t total_bit_length) {
    block[63] = (uint8_t)(total_bit_length);
    block[62] = (uint8_t)(total_bit_length >> 8);
    block[61] = (uint8_t)(total_bit_length >> 16);
    block[60] = (uint8_t)(total_bit_length >> 24);
    block[59] = (uint8_t)(total_bit_length >> 32);
    block[58] = (uint8_t)(total_bit_length >> 40);
    block[57] = (uint8_t)(total_bit_length >> 48);
    block[56] = (uint8_t)(total_bit_length >> 56);
}

static void prepare_host_fixed_digit_blocks(
    const sha256_context *prefix_context,
    unsigned int digit_length,
    host_prepared_nonce_blocks *prepared
) {
    size_t prefix_remainder = prefix_context->data_length;
    size_t first_available = 64U - prefix_remainder;
    size_t first_nonce_length = digit_length;
    uint64_t total_bit_length =
        prefix_context->bit_length + ((uint64_t)(prefix_remainder + digit_length) * 8ULL);

    memset(prepared, 0, sizeof(*prepared));
    prepared->first_nonce_offset = prefix_remainder;

    memcpy(prepared->first_block, prefix_context->data, prefix_remainder);

    if (first_nonce_length > first_available) {
        first_nonce_length = first_available;
    }
    prepared->first_nonce_length = first_nonce_length;
    prepared->second_nonce_length = (size_t)digit_length - first_nonce_length;
    prepared->uses_second_block = prepared->second_nonce_length > 0;

    memset(
        prepared->first_block + prepared->first_nonce_offset,
        '0',
        prepared->first_nonce_length
    );
    if (prepared->second_nonce_length > 0) {
        memset(prepared->second_block, '0', prepared->second_nonce_length);
    }

    if (prepared->uses_second_block) {
        prepared->second_block[prepared->second_nonce_length] = 0x80U;
        write_sha256_length_bytes(prepared->second_block, total_bit_length);
        return;
    }

    size_t total_suffix_offset = prefix_remainder + prepared->first_nonce_length;
    if (total_suffix_offset < 56U) {
        prepared->first_block[total_suffix_offset] = 0x80U;
        write_sha256_length_bytes(prepared->first_block, total_bit_length);
        return;
    }

    prepared->uses_second_block = true;
    if (total_suffix_offset < 64U) {
        prepared->first_block[total_suffix_offset] = 0x80U;
    } else {
        prepared->second_block[0] = 0x80U;
    }
    write_sha256_length_bytes(prepared->second_block, total_bit_length);
}

static void build_fixed_digit_templates(
    const sha256_context *prefix_context,
    unsigned int digit_length,
    metal_fixed_one_block_template *one_block_template,
    bool *one_block_valid,
    metal_fixed_two_block_template *two_block_template,
    bool *two_block_valid
) {
    host_prepared_nonce_blocks prepared;

    memset(one_block_template, 0, sizeof(*one_block_template));
    memset(two_block_template, 0, sizeof(*two_block_template));
    *one_block_valid = false;
    *two_block_valid = false;

    prepare_host_fixed_digit_blocks(prefix_context, digit_length, &prepared);

    if (!prepared.uses_second_block) {
        block_bytes_to_words(prepared.first_block, one_block_template->block_words);
        for (unsigned int digit_index = 0; digit_index < digit_length; digit_index++) {
            size_t byte_offset = prefix_context->data_length + digit_index;
            one_block_template->digit_word_index[digit_index] = (uint32_t)(byte_offset / 4U);
            one_block_template->digit_shift[digit_index] =
                (uint32_t)(24U - ((byte_offset % 4U) * 8U));
        }
        *one_block_valid = true;
        return;
    }

    two_block_template->first_digit_count = (uint32_t)prepared.first_nonce_length;
    two_block_template->second_digit_count = (uint32_t)prepared.second_nonce_length;
    block_bytes_to_words(prepared.first_block, two_block_template->first_block_words);
    block_bytes_to_words(prepared.second_block, two_block_template->second_block_words);

    for (size_t digit_index = 0; digit_index < prepared.first_nonce_length; digit_index++) {
        size_t byte_offset = prepared.first_nonce_offset + digit_index;
        two_block_template->first_digit_word_index[digit_index] = (uint32_t)(byte_offset / 4U);
        two_block_template->first_digit_shift[digit_index] =
            (uint32_t)(24U - ((byte_offset % 4U) * 8U));
    }
    for (size_t digit_index = 0; digit_index < prepared.second_nonce_length; digit_index++) {
        two_block_template->second_digit_word_index[digit_index] = (uint32_t)(digit_index / 4U);
        two_block_template->second_digit_shift[digit_index] =
            (uint32_t)(24U - ((digit_index % 4U) * 8U));
    }

    *two_block_valid = true;
}

static bool batch_fits_one_block_step1(
    const sha256_context *prefix_context,
    unsigned long long start_nonce,
    unsigned long long nonce_count
) {
    unsigned long long last_nonce = start_nonce;

    if (nonce_count == 0 || prefix_context->data_length >= 56) {
        return false;
    }

    if (nonce_count > 1) {
        unsigned long long nonce_span = nonce_count - 1ULL;
        if (start_nonce > ULLONG_MAX - nonce_span) {
            return false;
        }
        last_nonce = start_nonce + nonce_span;
    }

    return prefix_context->data_length + decimal_length_u64(last_nonce) < 56;
}

static void initialize_metal_backend(void) {
    @autoreleasepool {
        metal_device = MTLCreateSystemDefaultDevice();
        if (metal_device == nil) {
            return;
        }

        NSError *error = nil;
        id<MTLLibrary> library = [metal_device newLibraryWithSource:POW_METAL_SOURCE
                                                            options:nil
                                                              error:&error];
        if (library == nil) {
            return;
        }

        id<MTLFunction> function = [library newFunctionWithName:@"minePow"];
        if (function == nil) {
            return;
        }

        metal_pipeline = [metal_device newComputePipelineStateWithFunction:function error:&error];
        if (metal_pipeline == nil) {
            return;
        }

        id<MTLFunction> one_block_function = [library newFunctionWithName:@"minePowOneBlockStep1"];
        if (one_block_function != nil) {
            metal_pipeline_one_block_step1 = [metal_device newComputePipelineStateWithFunction:one_block_function error:&error];
        }

        for (unsigned int digit_index = 0; digit_index < MAX_FIXED_DIGIT_LENGTH; digit_index++) {
            uint32_t fixed_digit_count = digit_index + 1U;
            NSError *fixed_error = nil;
            MTLFunctionConstantValues *constant_values = [[MTLFunctionConstantValues alloc] init];

            [constant_values setConstantValue:&fixed_digit_count
                                         type:MTLDataTypeUInt
                                      atIndex:0];

            id<MTLFunction> fixed_one_block_function = [library
                newFunctionWithName:@"minePowFixedDigitsOneBlock"
                     constantValues:constant_values
                              error:&fixed_error];
            if (fixed_one_block_function != nil) {
                metal_pipeline_fixed_one_block[digit_index] = [metal_device
                    newComputePipelineStateWithFunction:fixed_one_block_function
                                                   error:&fixed_error];
            }

            fixed_error = nil;
            id<MTLFunction> fixed_two_block_function = [library
                newFunctionWithName:@"minePowFixedDigitsTwoBlock"
                     constantValues:constant_values
                              error:&fixed_error];
            if (fixed_two_block_function != nil) {
                metal_pipeline_fixed_two_block[digit_index] = [metal_device
                    newComputePipelineStateWithFunction:fixed_two_block_function
                                                   error:&fixed_error];
            }
        }

        metal_available = true;
    }
}

static id<MTLCommandQueue> current_thread_metal_queue(void) {
    if (metal_device == nil) {
        return nil;
    }

    NSMutableDictionary *thread_dictionary = [[NSThread currentThread] threadDictionary];
    id thread_queue_object = thread_dictionary[METAL_THREAD_QUEUE_KEY];
    if ([thread_queue_object conformsToProtocol:@protocol(MTLCommandQueue)]) {
        return (id<MTLCommandQueue>)thread_queue_object;
    }

    id<MTLCommandQueue> thread_queue = [metal_device newCommandQueue];
    if (thread_queue != nil) {
        thread_dictionary[METAL_THREAD_QUEUE_KEY] = thread_queue;
    }
    return thread_queue;
}

bool metal_pow_is_available(void) {
    dispatch_once(&metal_init_once, ^{
        initialize_metal_backend();
    });
    return metal_available;
}

bool metal_pow_gpu_properties(
    unsigned int *thread_execution_width,
    unsigned int *max_threads_per_threadgroup
) {
    if (!metal_pow_is_available()) {
        return false;
    }

    if (thread_execution_width != NULL) {
        NSUInteger width = metal_pipeline.threadExecutionWidth;
        if (metal_pipeline_one_block_step1 != nil
            && metal_pipeline_one_block_step1.threadExecutionWidth > width) {
            width = metal_pipeline_one_block_step1.threadExecutionWidth;
        }
        for (unsigned int digit_index = 0; digit_index < MAX_FIXED_DIGIT_LENGTH; digit_index++) {
            if (metal_pipeline_fixed_one_block[digit_index] != nil
                && metal_pipeline_fixed_one_block[digit_index].threadExecutionWidth > width) {
                width = metal_pipeline_fixed_one_block[digit_index].threadExecutionWidth;
            }
            if (metal_pipeline_fixed_two_block[digit_index] != nil
                && metal_pipeline_fixed_two_block[digit_index].threadExecutionWidth > width) {
                width = metal_pipeline_fixed_two_block[digit_index].threadExecutionWidth;
            }
        }
        *thread_execution_width = (unsigned int)width;
    }
    if (max_threads_per_threadgroup != NULL) {
        NSUInteger max_threads = metal_pipeline.maxTotalThreadsPerThreadgroup;
        if (metal_pipeline_one_block_step1 != nil
            && metal_pipeline_one_block_step1.maxTotalThreadsPerThreadgroup > max_threads) {
            max_threads = metal_pipeline_one_block_step1.maxTotalThreadsPerThreadgroup;
        }
        for (unsigned int digit_index = 0; digit_index < MAX_FIXED_DIGIT_LENGTH; digit_index++) {
            if (metal_pipeline_fixed_one_block[digit_index] != nil
                && metal_pipeline_fixed_one_block[digit_index].maxTotalThreadsPerThreadgroup > max_threads) {
                max_threads = metal_pipeline_fixed_one_block[digit_index].maxTotalThreadsPerThreadgroup;
            }
            if (metal_pipeline_fixed_two_block[digit_index] != nil
                && metal_pipeline_fixed_two_block[digit_index].maxTotalThreadsPerThreadgroup > max_threads) {
                max_threads = metal_pipeline_fixed_two_block[digit_index].maxTotalThreadsPerThreadgroup;
            }
        }
        *max_threads_per_threadgroup = (unsigned int)max_threads;
    }
    return true;
}

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
) {
    @autoreleasepool {
        if (
            out_nonce == NULL
            || out_hex == NULL
            || out_attempts == NULL
            || out_found == NULL
            || out_cancelled == NULL
        ) {
            copy_error_message(error_message, error_message_length, @"Metal PoW received null output pointers.");
            return false;
        }

        *out_found = 0;
        *out_cancelled = 0;
        *out_attempts = 0;
        out_hex[0] = '\0';

        if (!metal_pow_is_available()) {
            copy_error_message(error_message, error_message_length, @"Metal backend is unavailable.");
            return false;
        }

        if (batch_size == 0) {
            batch_size = DEFAULT_GPU_BATCH_SIZE;
        }

        if (batch_size > UINT32_MAX) {
            batch_size = UINT32_MAX;
        }
        if (nonce_step == 0) {
            copy_error_message(error_message, error_message_length, @"GPU nonce_step must be at least 1.");
            return false;
        }
        if (nonces_per_thread == 0) {
            nonces_per_thread = DEFAULT_GPU_NONCES_PER_THREAD;
        }
        if (nonces_per_thread > UINT32_MAX) {
            nonces_per_thread = UINT32_MAX;
        }

        sha256_context prefix_context;
        metal_fixed_one_block_template fixed_one_block_templates[MAX_FIXED_DIGIT_LENGTH];
        metal_fixed_two_block_template fixed_two_block_templates[MAX_FIXED_DIGIT_LENGTH];
        bool fixed_one_block_valid[MAX_FIXED_DIGIT_LENGTH];
        bool fixed_two_block_valid[MAX_FIXED_DIGIT_LENGTH];

        sha256_init(&prefix_context);
        sha256_update(&prefix_context, (const uint8_t *)prefix, prefix_length);
        for (unsigned int digit_length = 1; digit_length <= MAX_FIXED_DIGIT_LENGTH; digit_length++) {
            build_fixed_digit_templates(
                &prefix_context,
                digit_length,
                &fixed_one_block_templates[digit_length - 1U],
                &fixed_one_block_valid[digit_length - 1U],
                &fixed_two_block_templates[digit_length - 1U],
                &fixed_two_block_valid[digit_length - 1U]
            );
        }

        metal_prefix_context gpu_prefix_context;
        memcpy(&gpu_prefix_context, &prefix_context, sizeof(gpu_prefix_context));

        id<MTLBuffer> prefix_buffer = [metal_device newBufferWithBytes:&gpu_prefix_context
                                                                length:sizeof(gpu_prefix_context)
                                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> params_buffer = [metal_device newBufferWithLength:sizeof(metal_mining_params)
                                                                options:MTLResourceStorageModeShared];
        id<MTLBuffer> result_buffer = [metal_device newBufferWithLength:sizeof(metal_mining_result)
                                                                options:MTLResourceStorageModeShared];
        id<MTLBuffer> queue_buffer = [metal_device newBufferWithLength:sizeof(metal_mining_queue)
                                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> template_buffer = [metal_device newBufferWithLength:sizeof(metal_fixed_two_block_template)
                                                                  options:MTLResourceStorageModeShared];
        unsigned char found_digest[SHA256_BINARY_LENGTH];
        unsigned long long attempts = 0;

        if (
            prefix_buffer == nil
            || params_buffer == nil
            || result_buffer == nil
            || queue_buffer == nil
            || template_buffer == nil
        ) {
            copy_error_message(error_message, error_message_length, @"Failed to allocate Metal buffers.");
            return false;
        }

        metal_mining_params *params = (metal_mining_params *)params_buffer.contents;
        metal_mining_result *result = (metal_mining_result *)result_buffer.contents;
        metal_mining_queue *queue = (metal_mining_queue *)queue_buffer.contents;
        id<MTLCommandQueue> thread_metal_queue = current_thread_metal_queue();

        memset(found_digest, 0, sizeof(found_digest));
        unsigned long long next_progress_mark = progress_interval;
        unsigned long long current_nonce = start_nonce;

        if (thread_metal_queue == nil) {
            copy_error_message(error_message, error_message_length, @"Failed to create Metal command queue.");
            return false;
        }

        while (max_attempts == 0 || attempts < max_attempts) {
            if (pow_cancel_requested()) {
                *out_nonce = attempts == 0 ? current_nonce : current_nonce - nonce_step;
                *out_attempts = attempts;
                *out_cancelled = 1;
                return true;
            }

            unsigned long long current_chunk_size = batch_size;
            unsigned long long segment_nonce_count = 0;
            unsigned int digit_length = 0;
            if (max_attempts != 0) {
                current_chunk_size = max_attempts - attempts;
            }
            if (current_chunk_size > UINT32_MAX) {
                current_chunk_size = UINT32_MAX;
            }
            if (current_chunk_size == 0) {
                break;
            }

            segment_nonce_count = current_chunk_size;
            digit_length = decimal_length_u64(current_nonce);
            if (nonce_step == 1 && digit_length <= MAX_FIXED_DIGIT_LENGTH) {
                unsigned long long digit_boundary = DECIMAL_DIGIT_BOUNDARIES[digit_length - 1U];
                if (digit_boundary != ULLONG_MAX) {
                    unsigned long long boundary_remaining = digit_boundary - current_nonce + 1ULL;
                    if (segment_nonce_count > boundary_remaining) {
                        segment_nonce_count = boundary_remaining;
                    }
                }
            }

            memset(result, 0, sizeof(*result));
            memset(queue, 0, sizeof(*queue));
            params->difficulty_bits = (uint32_t)difficulty_bits;
            params->nonce_count = (uint32_t)segment_nonce_count;
            params->nonces_per_thread = (uint32_t)nonces_per_thread;
            params->reserved = 0;
            params->start_nonce = current_nonce;
            params->nonce_step = nonce_step;

            id<MTLComputePipelineState> active_pipeline = metal_pipeline;
            bool use_fixed_template = false;
            if (nonce_step == 1 && digit_length <= MAX_FIXED_DIGIT_LENGTH) {
                unsigned int digit_index = digit_length - 1U;
                if (fixed_one_block_valid[digit_index] && metal_pipeline_fixed_one_block[digit_index] != nil) {
                    memcpy(
                        template_buffer.contents,
                        &fixed_one_block_templates[digit_index],
                        sizeof(fixed_one_block_templates[digit_index])
                    );
                    active_pipeline = metal_pipeline_fixed_one_block[digit_index];
                    use_fixed_template = true;
                } else if (fixed_two_block_valid[digit_index] && metal_pipeline_fixed_two_block[digit_index] != nil) {
                    memcpy(
                        template_buffer.contents,
                        &fixed_two_block_templates[digit_index],
                        sizeof(fixed_two_block_templates[digit_index])
                    );
                    active_pipeline = metal_pipeline_fixed_two_block[digit_index];
                    use_fixed_template = true;
                } else if (
                    metal_pipeline_one_block_step1 != nil
                    && batch_fits_one_block_step1(&prefix_context, current_nonce, segment_nonce_count)
                ) {
                    active_pipeline = metal_pipeline_one_block_step1;
                }
            } else if (
                nonce_step == 1
                && metal_pipeline_one_block_step1 != nil
                && batch_fits_one_block_step1(&prefix_context, current_nonce, segment_nonce_count)
            ) {
                active_pipeline = metal_pipeline_one_block_step1;
            }

            id<MTLCommandBuffer> command_buffer = [thread_metal_queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (command_buffer == nil || encoder == nil) {
                copy_error_message(error_message, error_message_length, @"Failed to create Metal command buffer.");
                return false;
            }

            [encoder setComputePipelineState:active_pipeline];
            [encoder setBuffer:prefix_buffer offset:0 atIndex:0];
            [encoder setBuffer:params_buffer offset:0 atIndex:1];
            [encoder setBuffer:result_buffer offset:0 atIndex:2];
            [encoder setBuffer:queue_buffer offset:0 atIndex:3];
            if (use_fixed_template) {
                [encoder setBuffer:template_buffer offset:0 atIndex:4];
            }

            NSUInteger width = active_pipeline.threadExecutionWidth;
            NSUInteger max_threads_per_group = active_pipeline.maxTotalThreadsPerThreadgroup;
            if (width == 0) {
                width = 1;
            }
            NSUInteger dispatch_threads_per_group = width;
            if (threads_per_group > 0) {
                dispatch_threads_per_group = (NSUInteger)threads_per_group;
            }
            if (max_threads_per_group < dispatch_threads_per_group) {
                dispatch_threads_per_group = max_threads_per_group;
            }
            if (dispatch_threads_per_group > width) {
                dispatch_threads_per_group =
                    (dispatch_threads_per_group / width) * width;
            }
            if (dispatch_threads_per_group == 0) {
                dispatch_threads_per_group = width <= max_threads_per_group
                    ? width
                    : max_threads_per_group;
            }
            if (dispatch_threads_per_group == 0) {
                dispatch_threads_per_group = 1;
            }

            unsigned long long total_work_items =
                (segment_nonce_count + nonces_per_thread - 1ULL) / nonces_per_thread;
            unsigned long long resident_work_items =
                (batch_size + nonces_per_thread - 1ULL) / nonces_per_thread;
            unsigned long long max_resident_work_items =
                (unsigned long long)dispatch_threads_per_group * METAL_PERSISTENT_GROUP_MULTIPLIER;
            unsigned long long thread_count = resident_work_items;
            if (thread_count < (unsigned long long)dispatch_threads_per_group) {
                thread_count = dispatch_threads_per_group;
            }
            if (thread_count > max_resident_work_items) {
                thread_count = max_resident_work_items;
            }
            if (thread_count > total_work_items) {
                thread_count = total_work_items;
            }
            if (thread_count == 0) {
                thread_count = 1;
            }

            NSUInteger group_thread_count = dispatch_threads_per_group;
            if ((unsigned long long)group_thread_count > thread_count) {
                group_thread_count = (NSUInteger)thread_count;
            }

            MTLSize grid_size = MTLSizeMake((NSUInteger)thread_count, 1, 1);
            MTLSize group_size = MTLSizeMake(group_thread_count, 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:group_size];
            [encoder endEncoding];

            [command_buffer commit];
            [command_buffer waitUntilCompleted];

            if (command_buffer.status == MTLCommandBufferStatusError) {
                NSString *message = command_buffer.error.localizedDescription ?: @"Metal command buffer failed.";
                copy_error_message(error_message, error_message_length, message);
                return false;
            }

            if (result->found != 0) {
                unsigned long long chunk_found_attempts = segment_nonce_count;
                if (result->nonce >= current_nonce) {
                    unsigned long long nonce_delta = result->nonce - current_nonce;
                    if (nonce_delta % nonce_step == 0) {
                        chunk_found_attempts = (nonce_delta / nonce_step) + 1ULL;
                        if (chunk_found_attempts > segment_nonce_count) {
                            chunk_found_attempts = segment_nonce_count;
                        }
                    }
                }
                *out_nonce = result->nonce;
                *out_attempts = attempts + chunk_found_attempts;
                *out_found = 1;
                memcpy(found_digest, result->digest, sizeof(found_digest));
                digest_to_hex(found_digest, out_hex);
                return true;
            }

            attempts += segment_nonce_count;
            current_nonce += segment_nonce_count * nonce_step;
            while (progress_interval > 0 && attempts >= next_progress_mark) {
                printf("\rTried %llu nonces...", start_nonce + (next_progress_mark * nonce_step));
                fflush(stdout);
                next_progress_mark += progress_interval;
            }
        }

        if (attempts == 0) {
            *out_nonce = current_nonce;
        } else {
            *out_nonce = current_nonce - nonce_step;
        }
        *out_attempts = attempts;
        return true;
	    }
}

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
) {
    unsigned long long attempts = 0;
    int found = 0;

    return metal_mine_pow_range(
        prefix,
        prefix_length,
        difficulty_bits,
        start_nonce,
        0,
        progress_interval,
        batch_size,
        nonce_step,
        nonces_per_thread,
        threads_per_group,
        out_nonce,
        out_hex,
        &attempts,
        &found,
        out_cancelled,
        error_message,
        error_message_length
    );
}
