import ctypes
import ctypes.util
import os
from dataclasses import dataclass
from typing import Callable


CL_SUCCESS = 0
CL_TRUE = 1
CL_DEVICE_TYPE_GPU = 1 << 2
CL_PLATFORM_NAME = 0x0902
CL_DEVICE_NAME = 0x102B
CL_DEVICE_VENDOR = 0x102C
CL_PROGRAM_BUILD_LOG = 0x1183
CL_MEM_READ_WRITE = 1 << 0
CL_MEM_COPY_HOST_PTR = 1 << 5


cl_int = ctypes.c_int
cl_uint = ctypes.c_uint
cl_ulong = ctypes.c_ulonglong
cl_bool = cl_uint
cl_bitfield = cl_ulong
cl_device_type = cl_bitfield
cl_platform_id = ctypes.c_void_p
cl_device_id = ctypes.c_void_p
cl_context = ctypes.c_void_p
cl_command_queue = ctypes.c_void_p
cl_program = ctypes.c_void_p
cl_kernel = ctypes.c_void_p
cl_mem = ctypes.c_void_p
size_t = ctypes.c_size_t


_KERNEL_SOURCE = r"""
typedef struct {
    uint found;
    uint reserved;
    ulong nonce;
    uchar digest[32];
} mining_result;

__constant uint SHA256_K[64] = {
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

inline uint rotr(uint value, uint bits) {
    return (value >> bits) | (value << (32U - bits));
}

inline void sha256_transform(uint state[8], const uchar block[64]) {
    uint schedule[64];

    for (uint index = 0; index < 16; index++) {
        uint offset = index * 4;
        schedule[index] =
            ((uint)block[offset] << 24) |
            ((uint)block[offset + 1] << 16) |
            ((uint)block[offset + 2] << 8) |
            ((uint)block[offset + 3]);
    }

    for (uint index = 16; index < 64; index++) {
        uint sigma0 = rotr(schedule[index - 15], 7) ^
                      rotr(schedule[index - 15], 18) ^
                      (schedule[index - 15] >> 3);
        uint sigma1 = rotr(schedule[index - 2], 17) ^
                      rotr(schedule[index - 2], 19) ^
                      (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16] + sigma0 + schedule[index - 7] + sigma1;
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint index = 0; index < 64; index++) {
        uint sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint choose = (e & f) ^ ((~e) & g);
        uint temp1 = h + sum1 + choose + SHA256_K[index] + schedule[index];
        uint sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint majority = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline void sha256_init(uint state[8]) {
    state[0] = 0x6a09e667U;
    state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U;
    state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU;
    state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU;
    state[7] = 0x5be0cd19U;
}

inline void sha256_update_byte(uint state[8], uchar block[64], uint *data_length, ulong *bit_length, uchar value) {
    block[*data_length] = value;
    *data_length += 1;
    if (*data_length == 64U) {
        sha256_transform(state, block);
        *bit_length += 512UL;
        *data_length = 0U;
    }
}

inline void sha256_finalize(uint state[8], uchar block[64], uint data_length, ulong bit_length, uchar digest[32]) {
    bit_length += ((ulong)data_length) * 8UL;
    block[data_length++] = 0x80;

    if (data_length > 56U) {
        while (data_length < 64U) {
            block[data_length++] = 0;
        }
        sha256_transform(state, block);
        data_length = 0U;
    }

    while (data_length < 56U) {
        block[data_length++] = 0;
    }

    for (uint index = 0; index < 8; index++) {
        block[63U - index] = (uchar)(bit_length >> (index * 8U));
    }
    sha256_transform(state, block);

    for (uint index = 0; index < 8; index++) {
        uint word = state[index];
        uint offset = index * 4;
        digest[offset] = (uchar)(word >> 24);
        digest[offset + 1] = (uchar)(word >> 16);
        digest[offset + 2] = (uchar)(word >> 8);
        digest[offset + 3] = (uchar)(word);
    }
}

inline uint nonce_to_ascii(ulong nonce, uchar digits[20]) {
    uint length = 0;
    do {
        digits[length++] = (uchar)('0' + (nonce % 10UL));
        nonce /= 10UL;
    } while (nonce != 0UL);
    return length;
}

inline int digest_matches_difficulty(const uchar digest[32], uint difficulty_bits) {
    uint whole_bytes = difficulty_bits / 8U;
    uint remaining_bits = difficulty_bits % 8U;

    for (uint index = 0; index < whole_bytes; index++) {
        if (digest[index] != 0) {
            return 0;
        }
    }

    if (remaining_bits == 0U) {
        return 1;
    }

    uchar mask = (uchar)(0xFFU << (8U - remaining_bits));
    return (digest[whole_bytes] & mask) == 0;
}

__kernel void mine_pow_gpu(
    __global const uchar *prefix,
    uint prefix_length,
    uint difficulty_bits,
    ulong start_nonce,
    ulong nonce_step,
    ulong work_items,
    __global mining_result *result
) {
    ulong gid = get_global_id(0);
    if (gid >= work_items || result[0].found != 0U) {
        return;
    }

    ulong nonce = start_nonce + (gid * nonce_step);
    uint state[8];
    uchar block[64];
    uchar digest[32];
    uchar digits[20];
    uint data_length = 0U;
    ulong bit_length = 0UL;

    sha256_init(state);

    for (uint index = 0; index < prefix_length; index++) {
        sha256_update_byte(state, block, &data_length, &bit_length, prefix[index]);
    }

    uint digit_length = nonce_to_ascii(nonce, digits);
    for (uint index = 0; index < digit_length; index++) {
        sha256_update_byte(
            state,
            block,
            &data_length,
            &bit_length,
            digits[digit_length - index - 1]
        );
    }

    sha256_finalize(state, block, data_length, bit_length, digest);

    if (!digest_matches_difficulty(digest, difficulty_bits)) {
        return;
    }

    if (atomic_cmpxchg((volatile __global int *)&result[0].found, 0, 1) == 0) {
        result[0].nonce = nonce;
        for (uint index = 0; index < 32; index++) {
            result[0].digest[index] = digest[index];
        }
    }
}
"""


class OpenCLError(RuntimeError):
    pass


class _MiningResult(ctypes.Structure):
    _fields_ = [
        ("found", cl_uint),
        ("reserved", cl_uint),
        ("nonce", cl_ulong),
        ("digest", ctypes.c_ubyte * 32),
    ]


@dataclass
class _DeviceInfo:
    platform_name: str
    device_name: str
    vendor_name: str


class _OpenCLLibrary:
    def __init__(self) -> None:
        library_path = self._find_library_path()
        if library_path is None:
            raise OpenCLError("No OpenCL runtime was found.")

        self._lib = ctypes.CDLL(library_path)
        self._configure_functions()

    @staticmethod
    def _find_library_path() -> str | None:
        candidates = []
        located = ctypes.util.find_library("OpenCL")
        if located:
            candidates.append(located)

        candidates.extend(
            [
                "/usr/lib/wsl/lib/libOpenCL.so.1",
                "/usr/lib/x86_64-linux-gnu/libOpenCL.so.1",
                "/usr/lib/aarch64-linux-gnu/libOpenCL.so.1",
                "/usr/local/lib/libOpenCL.so.1",
                "OpenCL.dll",
            ]
        )

        seen: set[str] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                ctypes.CDLL(candidate)
            except OSError:
                continue
            return candidate
        return None

    def _configure_functions(self) -> None:
        lib = self._lib

        lib.clGetPlatformIDs.argtypes = [cl_uint, ctypes.POINTER(cl_platform_id), ctypes.POINTER(cl_uint)]
        lib.clGetPlatformIDs.restype = cl_int
        lib.clGetDeviceIDs.argtypes = [
            cl_platform_id,
            cl_device_type,
            cl_uint,
            ctypes.POINTER(cl_device_id),
            ctypes.POINTER(cl_uint),
        ]
        lib.clGetDeviceIDs.restype = cl_int
        lib.clGetPlatformInfo.argtypes = [
            cl_platform_id,
            cl_uint,
            size_t,
            ctypes.c_void_p,
            ctypes.POINTER(size_t),
        ]
        lib.clGetPlatformInfo.restype = cl_int
        lib.clGetDeviceInfo.argtypes = [
            cl_device_id,
            cl_uint,
            size_t,
            ctypes.c_void_p,
            ctypes.POINTER(size_t),
        ]
        lib.clGetDeviceInfo.restype = cl_int
        lib.clCreateContext.argtypes = [
            ctypes.c_void_p,
            cl_uint,
            ctypes.POINTER(cl_device_id),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(cl_int),
        ]
        lib.clCreateContext.restype = cl_context
        lib.clCreateCommandQueue.argtypes = [
            cl_context,
            cl_device_id,
            cl_bitfield,
            ctypes.POINTER(cl_int),
        ]
        lib.clCreateCommandQueue.restype = cl_command_queue
        lib.clCreateProgramWithSource.argtypes = [
            cl_context,
            cl_uint,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(size_t),
            ctypes.POINTER(cl_int),
        ]
        lib.clCreateProgramWithSource.restype = cl_program
        lib.clBuildProgram.argtypes = [
            cl_program,
            cl_uint,
            ctypes.POINTER(cl_device_id),
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.clBuildProgram.restype = cl_int
        lib.clGetProgramBuildInfo.argtypes = [
            cl_program,
            cl_device_id,
            cl_uint,
            size_t,
            ctypes.c_void_p,
            ctypes.POINTER(size_t),
        ]
        lib.clGetProgramBuildInfo.restype = cl_int
        lib.clCreateKernel.argtypes = [cl_program, ctypes.c_char_p, ctypes.POINTER(cl_int)]
        lib.clCreateKernel.restype = cl_kernel
        lib.clCreateBuffer.argtypes = [cl_context, cl_bitfield, size_t, ctypes.c_void_p, ctypes.POINTER(cl_int)]
        lib.clCreateBuffer.restype = cl_mem
        lib.clSetKernelArg.argtypes = [cl_kernel, cl_uint, size_t, ctypes.c_void_p]
        lib.clSetKernelArg.restype = cl_int
        lib.clEnqueueNDRangeKernel.argtypes = [
            cl_command_queue,
            cl_kernel,
            cl_uint,
            ctypes.POINTER(size_t),
            ctypes.POINTER(size_t),
            ctypes.POINTER(size_t),
            cl_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.clEnqueueNDRangeKernel.restype = cl_int
        lib.clEnqueueReadBuffer.argtypes = [
            cl_command_queue,
            cl_mem,
            cl_bool,
            size_t,
            size_t,
            ctypes.c_void_p,
            cl_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.clEnqueueReadBuffer.restype = cl_int
        lib.clEnqueueWriteBuffer.argtypes = [
            cl_command_queue,
            cl_mem,
            cl_bool,
            size_t,
            size_t,
            ctypes.c_void_p,
            cl_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.clEnqueueWriteBuffer.restype = cl_int
        lib.clFinish.argtypes = [cl_command_queue]
        lib.clFinish.restype = cl_int
        lib.clReleaseMemObject.argtypes = [cl_mem]
        lib.clReleaseMemObject.restype = cl_int
        lib.clReleaseKernel.argtypes = [cl_kernel]
        lib.clReleaseKernel.restype = cl_int
        lib.clReleaseProgram.argtypes = [cl_program]
        lib.clReleaseProgram.restype = cl_int
        lib.clReleaseCommandQueue.argtypes = [cl_command_queue]
        lib.clReleaseCommandQueue.restype = cl_int
        lib.clReleaseContext.argtypes = [cl_context]
        lib.clReleaseContext.restype = cl_int

    def __getattr__(self, name: str):
        return getattr(self._lib, name)


class _OpenCLMiner:
    def __init__(self) -> None:
        self._lib = _OpenCLLibrary()
        self._device = self._pick_device()
        self._context = self._create_context()
        self._queue = self._create_command_queue()
        self._program = self._build_program()
        self._kernel = self._create_kernel()

    def _check(self, result: int, context: str) -> None:
        if result != CL_SUCCESS:
            raise OpenCLError(f"{context} failed with OpenCL error {result}.")

    def _get_platforms(self) -> list[cl_platform_id]:
        count = cl_uint()
        self._check(self._lib.clGetPlatformIDs(0, None, ctypes.byref(count)), "clGetPlatformIDs")
        if count.value == 0:
            return []
        platforms = (cl_platform_id * count.value)()
        self._check(self._lib.clGetPlatformIDs(count, platforms, None), "clGetPlatformIDs")
        return list(platforms)

    def _get_platform_string(self, platform: cl_platform_id, key: int) -> str:
        value_size = size_t()
        self._check(
            self._lib.clGetPlatformInfo(platform, key, 0, None, ctypes.byref(value_size)),
            "clGetPlatformInfo",
        )
        buffer = ctypes.create_string_buffer(value_size.value or 1)
        self._check(
            self._lib.clGetPlatformInfo(platform, key, value_size, buffer, None),
            "clGetPlatformInfo",
        )
        return buffer.value.decode("utf-8", errors="replace")

    def _get_device_string(self, device: cl_device_id, key: int) -> str:
        value_size = size_t()
        self._check(
            self._lib.clGetDeviceInfo(device, key, 0, None, ctypes.byref(value_size)),
            "clGetDeviceInfo",
        )
        buffer = ctypes.create_string_buffer(value_size.value or 1)
        self._check(
            self._lib.clGetDeviceInfo(device, key, value_size, buffer, None),
            "clGetDeviceInfo",
        )
        return buffer.value.decode("utf-8", errors="replace")

    def _pick_device(self) -> tuple[cl_platform_id, cl_device_id, _DeviceInfo]:
        for platform in self._get_platforms():
            count = cl_uint()
            result = self._lib.clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, None, ctypes.byref(count))
            if result != CL_SUCCESS or count.value == 0:
                continue
            devices = (cl_device_id * count.value)()
            self._check(
                self._lib.clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, count, devices, None),
                "clGetDeviceIDs",
            )
            device = devices[0]
            return (
                platform,
                device,
                _DeviceInfo(
                    platform_name=self._get_platform_string(platform, CL_PLATFORM_NAME),
                    device_name=self._get_device_string(device, CL_DEVICE_NAME),
                    vendor_name=self._get_device_string(device, CL_DEVICE_VENDOR),
                ),
            )
        raise OpenCLError("No OpenCL GPU device was found.")

    def _create_context(self) -> cl_context:
        _, device, _ = self._device
        device_list = (cl_device_id * 1)(device)
        error = cl_int()
        context = self._lib.clCreateContext(None, 1, device_list, None, None, ctypes.byref(error))
        self._check(error.value, "clCreateContext")
        return context

    def _create_command_queue(self) -> cl_command_queue:
        _, device, _ = self._device
        error = cl_int()
        queue = self._lib.clCreateCommandQueue(self._context, device, 0, ctypes.byref(error))
        self._check(error.value, "clCreateCommandQueue")
        return queue

    def _build_program(self) -> cl_program:
        error = cl_int()
        source_bytes = _KERNEL_SOURCE.encode("utf-8")
        source_buffer = ctypes.c_char_p(source_bytes)
        source_length = size_t(len(source_bytes))
        program = self._lib.clCreateProgramWithSource(
            self._context,
            1,
            ctypes.byref(source_buffer),
            ctypes.byref(source_length),
            ctypes.byref(error),
        )
        self._check(error.value, "clCreateProgramWithSource")

        _, device, _ = self._device
        device_arg = (cl_device_id * 1)(device)
        result = self._lib.clBuildProgram(program, 1, device_arg, b"-cl-std=CL1.2", None, None)
        if result != CL_SUCCESS:
            build_log_size = size_t()
            self._lib.clGetProgramBuildInfo(
                program,
                device,
                CL_PROGRAM_BUILD_LOG,
                0,
                None,
                ctypes.byref(build_log_size),
            )
            build_log_buffer = ctypes.create_string_buffer(build_log_size.value or 1)
            self._lib.clGetProgramBuildInfo(
                program,
                device,
                CL_PROGRAM_BUILD_LOG,
                build_log_size,
                build_log_buffer,
                None,
            )
            build_log = build_log_buffer.value.decode("utf-8", errors="replace").strip()
            raise OpenCLError(f"OpenCL kernel build failed: {build_log or result}")
        return program

    def _create_kernel(self) -> cl_kernel:
        error = cl_int()
        kernel = self._lib.clCreateKernel(self._program, b"mine_pow_gpu", ctypes.byref(error))
        self._check(error.value, "clCreateKernel")
        return kernel

    def _create_buffer(self, flags: int, byte_count: int, host_pointer) -> cl_mem:
        error = cl_int()
        buffer = self._lib.clCreateBuffer(self._context, flags, byte_count, host_pointer, ctypes.byref(error))
        self._check(error.value, "clCreateBuffer")
        return buffer

    @property
    def device_info(self) -> _DeviceInfo:
        return self._device[2]

    def mine(
        self,
        prefix: str,
        difficulty_bits: int,
        start_nonce: int,
        batch_size: int,
        nonce_step: int,
        cancel_requested: Callable[[], bool],
    ) -> tuple[int, str, bool]:
        prefix_bytes = prefix.encode("utf-8")
        if not prefix_bytes:
            raise OpenCLError("OpenCL proof-of-work requires a non-empty prefix.")

        prefix_array = (ctypes.c_ubyte * len(prefix_bytes))(*prefix_bytes)
        result_host = _MiningResult()
        prefix_buffer = self._create_buffer(
            CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
            len(prefix_bytes),
            ctypes.cast(prefix_array, ctypes.c_void_p),
        )
        result_buffer = self._create_buffer(
            CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
            ctypes.sizeof(_MiningResult),
            ctypes.cast(ctypes.byref(result_host), ctypes.c_void_p),
        )

        try:
            prefix_mem = cl_mem(prefix_buffer)
            result_mem = cl_mem(result_buffer)
            prefix_length_value = cl_uint(len(prefix_bytes))
            difficulty_value = cl_uint(difficulty_bits)
            nonce_step_value = cl_ulong(nonce_step)

            self._check(
                self._lib.clSetKernelArg(self._kernel, 0, ctypes.sizeof(cl_mem), ctypes.byref(prefix_mem)),
                "clSetKernelArg(prefix)",
            )
            self._check(
                self._lib.clSetKernelArg(self._kernel, 1, ctypes.sizeof(cl_uint), ctypes.byref(prefix_length_value)),
                "clSetKernelArg(prefix_length)",
            )
            self._check(
                self._lib.clSetKernelArg(self._kernel, 2, ctypes.sizeof(cl_uint), ctypes.byref(difficulty_value)),
                "clSetKernelArg(difficulty_bits)",
            )
            self._check(
                self._lib.clSetKernelArg(self._kernel, 4, ctypes.sizeof(cl_ulong), ctypes.byref(nonce_step_value)),
                "clSetKernelArg(nonce_step)",
            )
            self._check(
                self._lib.clSetKernelArg(self._kernel, 6, ctypes.sizeof(cl_mem), ctypes.byref(result_mem)),
                "clSetKernelArg(result)",
            )

            work_items = max(1, batch_size)
            local_size = size_t(min(256, work_items))
            batch_start = start_nonce

            while True:
                if cancel_requested():
                    return batch_start, "", True

                start_nonce_value = cl_ulong(batch_start)
                work_items_value = cl_ulong(work_items)
                global_size = size_t(
                    ((work_items + local_size.value - 1) // local_size.value) * local_size.value
                )
                result_host = _MiningResult()
                self._check(
                    self._lib.clEnqueueWriteBuffer(
                        self._queue,
                        result_buffer,
                        CL_TRUE,
                        0,
                        ctypes.sizeof(_MiningResult),
                        ctypes.byref(result_host),
                        0,
                        None,
                        None,
                    ),
                    "clEnqueueWriteBuffer(result)",
                )
                self._check(
                    self._lib.clSetKernelArg(self._kernel, 3, ctypes.sizeof(cl_ulong), ctypes.byref(start_nonce_value)),
                    "clSetKernelArg(start_nonce)",
                )
                self._check(
                    self._lib.clSetKernelArg(self._kernel, 5, ctypes.sizeof(cl_ulong), ctypes.byref(work_items_value)),
                    "clSetKernelArg(work_items)",
                )
                self._check(
                    self._lib.clEnqueueNDRangeKernel(
                        self._queue,
                        self._kernel,
                        1,
                        None,
                        ctypes.byref(global_size),
                        ctypes.byref(local_size),
                        0,
                        None,
                        None,
                    ),
                    "clEnqueueNDRangeKernel",
                )
                self._check(self._lib.clFinish(self._queue), "clFinish")
                self._check(
                    self._lib.clEnqueueReadBuffer(
                        self._queue,
                        result_buffer,
                        CL_TRUE,
                        0,
                        ctypes.sizeof(_MiningResult),
                        ctypes.byref(result_host),
                        0,
                        None,
                        None,
                    ),
                    "clEnqueueReadBuffer(result)",
                )

                if result_host.found:
                    return int(result_host.nonce), bytes(result_host.digest).hex(), False

                batch_start += work_items * nonce_step
        finally:
            self._lib.clReleaseMemObject(result_buffer)
            self._lib.clReleaseMemObject(prefix_buffer)


_cancel_requested = False
_backend: _OpenCLMiner | None = None
_backend_error: Exception | None = None


def _is_opencl_disabled() -> bool:
    raw_value = os.environ.get("UNCCOIN_DISABLE_OPENCL_GPU", "")
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _get_backend() -> _OpenCLMiner:
    global _backend, _backend_error

    if _backend is not None:
        return _backend
    if _backend_error is not None:
        raise _backend_error
    if _is_opencl_disabled():
        _backend_error = OpenCLError("OpenCL GPU mining is disabled by UNCCOIN_DISABLE_OPENCL_GPU.")
        raise _backend_error

    try:
        _backend = _OpenCLMiner()
    except Exception as error:
        _backend_error = error
        raise
    return _backend


def gpu_available() -> bool:
    try:
        _get_backend()
    except Exception:
        return False
    return True


def mine_pow_gpu(
    prefix: str,
    difficulty_bits: int,
    start_nonce: int = 0,
    progress_interval: int = 0,
    batch_size: int = 262_144,
    nonce_step: int = 1,
) -> tuple[int, str, bool]:
    del progress_interval
    backend = _get_backend()
    return backend.mine(
        prefix=prefix,
        difficulty_bits=difficulty_bits,
        start_nonce=start_nonce,
        batch_size=batch_size,
        nonce_step=nonce_step,
        cancel_requested=lambda: _cancel_requested,
    )


def request_cancel() -> None:
    global _cancel_requested
    _cancel_requested = True


def reset_cancel() -> None:
    global _cancel_requested
    _cancel_requested = False
