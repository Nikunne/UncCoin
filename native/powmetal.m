#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "powmetal.h"

extern int pow_cancel_requested(void);

#define SHA256_HEX_LENGTH 64
#define SHA256_BINARY_LENGTH 32
#define NONCE_BUFFER_LENGTH 32
#define DEFAULT_GPU_BATCH_SIZE 262144

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
    uint32_t difficulty_bits;
    uint32_t nonce_count;
    uint64_t start_nonce;
    uint64_t nonce_step;
} metal_mining_params;

typedef struct {
    uint32_t found;
    uint32_t padding;
    uint64_t nonce;
    uint8_t digest[SHA256_BINARY_LENGTH];
} metal_mining_result;

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
    "    ulong start_nonce;\n"
    "    ulong nonce_step;\n"
    "};\n"
    "struct MiningResult {\n"
    "    atomic_uint found;\n"
    "    uint padding;\n"
    "    ulong nonce;\n"
    "    uchar digest[SHA256_BINARY_LENGTH];\n"
    "};\n"
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
    "inline void sha256_transform(thread SHA256Context &context, thread const uchar data[64]) {\n"
    "    uint schedule[64];\n"
    "    for (uint i = 0; i < 16; ++i) {\n"
    "        schedule[i] = ((uint)data[i * 4] << 24) | ((uint)data[i * 4 + 1] << 16) |\n"
    "                      ((uint)data[i * 4 + 2] << 8) | ((uint)data[i * 4 + 3]);\n"
    "    }\n"
    "    for (uint i = 16; i < 64; ++i) {\n"
    "        uint sigma0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);\n"
    "        uint sigma1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);\n"
    "        schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1;\n"
    "    }\n"
    "    uint a = context.state[0]; uint b = context.state[1]; uint c = context.state[2]; uint d = context.state[3];\n"
    "    uint e = context.state[4]; uint f = context.state[5]; uint g = context.state[6]; uint h = context.state[7];\n"
    "    for (uint i = 0; i < 64; ++i) {\n"
    "        uint sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);\n"
    "        uint choose = (e & f) ^ ((~e) & g);\n"
    "        uint temp1 = h + sum1 + choose + SHA256_K[i] + schedule[i];\n"
    "        uint sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n"
    "        uint majority = (a & b) ^ (a & c) ^ (b & c);\n"
    "        uint temp2 = sum0 + majority;\n"
    "        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;\n"
    "    }\n"
    "    context.state[0] += a; context.state[1] += b; context.state[2] += c; context.state[3] += d;\n"
    "    context.state[4] += e; context.state[5] += f; context.state[6] += g; context.state[7] += h;\n"
    "}\n"
    "inline void sha256_update(thread SHA256Context &context, thread const uchar *data, uint length) {\n"
    "    for (uint i = 0; i < length; ++i) {\n"
    "        context.data[context.data_length] = data[i];\n"
    "        context.data_length += 1;\n"
    "        if (context.data_length == 64) {\n"
    "            sha256_transform(context, context.data);\n"
    "            context.bit_length += 512;\n"
    "            context.data_length = 0;\n"
    "        }\n"
    "    }\n"
    "}\n"
    "inline void sha256_final(thread SHA256Context &context, thread uchar hash[SHA256_BINARY_LENGTH]) {\n"
    "    uint index = context.data_length;\n"
    "    context.data[index++] = 0x80;\n"
    "    if (index > 56) {\n"
    "        while (index < 64) { context.data[index++] = 0x00; }\n"
    "        sha256_transform(context, context.data);\n"
    "        index = 0;\n"
    "    }\n"
    "    while (index < 56) { context.data[index++] = 0x00; }\n"
    "    context.bit_length += (ulong)context.data_length * 8ul;\n"
    "    context.data[63] = (uchar)(context.bit_length);\n"
    "    context.data[62] = (uchar)(context.bit_length >> 8);\n"
    "    context.data[61] = (uchar)(context.bit_length >> 16);\n"
    "    context.data[60] = (uchar)(context.bit_length >> 24);\n"
    "    context.data[59] = (uchar)(context.bit_length >> 32);\n"
    "    context.data[58] = (uchar)(context.bit_length >> 40);\n"
    "    context.data[57] = (uchar)(context.bit_length >> 48);\n"
    "    context.data[56] = (uchar)(context.bit_length >> 56);\n"
    "    sha256_transform(context, context.data);\n"
    "    for (uint i = 0; i < 4; ++i) {\n"
    "        hash[i] = (uchar)((context.state[0] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 4] = (uchar)((context.state[1] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 8] = (uchar)((context.state[2] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 12] = (uchar)((context.state[3] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 16] = (uchar)((context.state[4] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 20] = (uchar)((context.state[5] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 24] = (uchar)((context.state[6] >> (24 - i * 8)) & 0xFFu);\n"
    "        hash[i + 28] = (uchar)((context.state[7] >> (24 - i * 8)) & 0xFFu);\n"
    "    }\n"
    "}\n"
    "inline bool has_leading_zero_bits(thread const uchar *digest, uint difficulty_bits) {\n"
    "    uint full_zero_bytes = difficulty_bits / 8u;\n"
    "    uint remaining_bits = difficulty_bits % 8u;\n"
    "    for (uint i = 0; i < full_zero_bytes; ++i) { if (digest[i] != 0) { return false; } }\n"
    "    if (remaining_bits == 0u) { return true; }\n"
    "    uchar mask = (uchar)(0xFFu << (8u - remaining_bits));\n"
    "    return (digest[full_zero_bytes] & mask) == 0;\n"
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
    "kernel void minePow(device const SHA256Context *prefix_context [[buffer(0)]],\n"
    "                    device const MiningParams *params [[buffer(1)]],\n"
    "                    device MiningResult *result [[buffer(2)]],\n"
    "                    uint gid [[thread_position_in_grid]]) {\n"
    "    if (gid >= params->nonce_count) { return; }\n"
    "    if (atomic_load_explicit(&result->found, memory_order_relaxed) != 0u) { return; }\n"
    "    ulong nonce = params->start_nonce + ((ulong)gid * params->nonce_step);\n"
    "    SHA256Context context = prefix_context[0];\n"
    "    uchar nonce_chars[NONCE_BUFFER_LENGTH];\n"
    "    uchar digest[SHA256_BINARY_LENGTH];\n"
    "    uint nonce_length = nonce_to_ascii(nonce, nonce_chars);\n"
    "    sha256_update(context, nonce_chars, nonce_length);\n"
    "    sha256_final(context, digest);\n"
    "    if (!has_leading_zero_bits(digest, params->difficulty_bits)) { return; }\n"
    "    if (atomic_exchange_explicit(&result->found, 1u, memory_order_relaxed) == 0u) {\n"
    "        result->nonce = nonce;\n"
    "        for (uint i = 0; i < SHA256_BINARY_LENGTH; ++i) { result->digest[i] = digest[i]; }\n"
    "    }\n"
    "}\n";

static id<MTLDevice> metal_device = nil;
static id<MTLCommandQueue> metal_queue = nil;
static id<MTLComputePipelineState> metal_pipeline = nil;
static dispatch_once_t metal_init_once;
static bool metal_available = false;

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

        metal_queue = [metal_device newCommandQueue];
        if (metal_queue == nil) {
            metal_pipeline = nil;
            return;
        }

        metal_available = true;
    }
}

bool metal_pow_is_available(void) {
    dispatch_once(&metal_init_once, ^{
        initialize_metal_backend();
    });
    return metal_available;
}

bool metal_mine_pow(
    const char *prefix,
    size_t prefix_length,
    int difficulty_bits,
    unsigned long long start_nonce,
    unsigned long long progress_interval,
    unsigned long long batch_size,
    unsigned long long nonce_step,
    unsigned long long *out_nonce,
    char out_hex[65],
    int *out_cancelled,
    char *error_message,
    size_t error_message_length
) {
    @autoreleasepool {
        if (out_nonce == NULL || out_hex == NULL || out_cancelled == NULL) {
            copy_error_message(error_message, error_message_length, @"Metal PoW received null output pointers.");
            return false;
        }

        *out_cancelled = 0;

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

        sha256_context prefix_context;
        sha256_init(&prefix_context);
        sha256_update(&prefix_context, (const uint8_t *)prefix, prefix_length);

        metal_prefix_context gpu_prefix_context;
        memcpy(&gpu_prefix_context, &prefix_context, sizeof(gpu_prefix_context));

        id<MTLBuffer> prefix_buffer = [metal_device newBufferWithBytes:&gpu_prefix_context
                                                                length:sizeof(gpu_prefix_context)
                                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> params_buffer = [metal_device newBufferWithLength:sizeof(metal_mining_params)
                                                                options:MTLResourceStorageModeShared];
        id<MTLBuffer> result_buffer = [metal_device newBufferWithLength:sizeof(metal_mining_result)
                                                                options:MTLResourceStorageModeShared];

        if (prefix_buffer == nil || params_buffer == nil || result_buffer == nil) {
            copy_error_message(error_message, error_message_length, @"Failed to allocate Metal buffers.");
            return false;
        }

        metal_mining_params *params = (metal_mining_params *)params_buffer.contents;
        metal_mining_result *result = (metal_mining_result *)result_buffer.contents;
        unsigned long long attempts = 0;
        unsigned long long next_progress_mark = progress_interval;
        unsigned long long current_nonce = start_nonce;

        while (true) {
            if (pow_cancel_requested()) {
                *out_nonce = current_nonce;
                out_hex[0] = '\0';
                *out_cancelled = 1;
                return true;
            }

            memset(result, 0, sizeof(*result));
            params->difficulty_bits = (uint32_t)difficulty_bits;
            params->nonce_count = (uint32_t)batch_size;
            params->start_nonce = current_nonce;
            params->nonce_step = nonce_step;

            id<MTLCommandBuffer> command_buffer = [metal_queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (command_buffer == nil || encoder == nil) {
                copy_error_message(error_message, error_message_length, @"Failed to create Metal command buffer.");
                return false;
            }

            [encoder setComputePipelineState:metal_pipeline];
            [encoder setBuffer:prefix_buffer offset:0 atIndex:0];
            [encoder setBuffer:params_buffer offset:0 atIndex:1];
            [encoder setBuffer:result_buffer offset:0 atIndex:2];

            NSUInteger width = metal_pipeline.threadExecutionWidth;
            NSUInteger threads_per_group = width > 0 ? width : 1;
            if (metal_pipeline.maxTotalThreadsPerThreadgroup < threads_per_group) {
                threads_per_group = metal_pipeline.maxTotalThreadsPerThreadgroup;
            }
            if (threads_per_group == 0) {
                threads_per_group = 1;
            }

            MTLSize grid_size = MTLSizeMake((NSUInteger)batch_size, 1, 1);
            MTLSize group_size = MTLSizeMake(threads_per_group, 1, 1);
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
                *out_nonce = result->nonce;
                digest_to_hex(result->digest, out_hex);
                return true;
            }

            attempts += batch_size;
            current_nonce += batch_size * nonce_step;

            if (progress_interval > 0 && attempts >= next_progress_mark) {
                printf("\rTried %llu nonces...", current_nonce);
                fflush(stdout);
                next_progress_mark += progress_interval;
            }
        }
    }
}
