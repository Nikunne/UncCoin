#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA256_HEX_LENGTH 64
#define SHA256_BINARY_LENGTH CC_SHA256_DIGEST_LENGTH
#define NONCE_BUFFER_LENGTH 32

static bool has_leading_zero_bits(const unsigned char *digest, int difficulty_bits) {
    int full_zero_bytes = difficulty_bits / 8;
    int remaining_bits = difficulty_bits % 8;

    for (int index = 0; index < full_zero_bytes; index++) {
        if (digest[index] != 0) {
            return false;
        }
    }

    if (remaining_bits == 0) {
        return true;
    }

    unsigned char mask = (unsigned char)(0xFF << (8 - remaining_bits));
    return (digest[full_zero_bytes] & mask) == 0;
}

static void digest_to_hex(const unsigned char *digest, char *hex_output) {
    static const char hex_chars[] = "0123456789abcdef";

    for (int index = 0; index < SHA256_BINARY_LENGTH; index++) {
        hex_output[index * 2] = hex_chars[(digest[index] >> 4) & 0xF];
        hex_output[index * 2 + 1] = hex_chars[digest[index] & 0xF];
    }

    hex_output[SHA256_HEX_LENGTH] = '\0';
}

static PyObject *mine_pow(PyObject *Py_UNUSED(self), PyObject *args) {
    const char *prefix = NULL;
    Py_ssize_t prefix_length = 0;
    int difficulty_bits = 0;
    unsigned long long start_nonce = 0;
    unsigned long long progress_interval = 0;

    if (!PyArg_ParseTuple(
            args,
            "s#i|KK",
            &prefix,
            &prefix_length,
            &difficulty_bits,
            &start_nonce,
            &progress_interval)) {
        return NULL;
    }

    if (difficulty_bits < 0 || difficulty_bits > 256) {
        PyErr_SetString(PyExc_ValueError, "difficulty_bits must be between 0 and 256.");
        return NULL;
    }

    size_t buffer_length = (size_t)prefix_length + NONCE_BUFFER_LENGTH;
    char *buffer = malloc(buffer_length);
    if (buffer == NULL) {
        return PyErr_NoMemory();
    }

    memcpy(buffer, prefix, (size_t)prefix_length);

    unsigned char digest[SHA256_BINARY_LENGTH];
    char hex_digest[SHA256_HEX_LENGTH + 1];
    unsigned long long nonce = start_nonce;

    Py_BEGIN_ALLOW_THREADS
    while (true) {
        int nonce_length = snprintf(
            buffer + prefix_length,
            NONCE_BUFFER_LENGTH,
            "%llu",
            nonce
        );

        if (nonce_length < 0 || nonce_length >= NONCE_BUFFER_LENGTH) {
            free(buffer);
            PyErr_SetString(PyExc_RuntimeError, "Failed to serialize nonce.");
            return NULL;
        }

        CC_SHA256(
            buffer,
            (CC_LONG)((size_t)prefix_length + (size_t)nonce_length),
            digest
        );

        if (has_leading_zero_bits(digest, difficulty_bits)) {
            break;
        }

        nonce += 1;

        if (progress_interval > 0 && nonce % progress_interval == 0) {
            printf("\rTried %llu nonces...", nonce);
            fflush(stdout);
        }
    }
    Py_END_ALLOW_THREADS

    digest_to_hex(digest, hex_digest);
    free(buffer);

    return Py_BuildValue("Ks", nonce, hex_digest);
}

static PyMethodDef NativePowMethods[] = {
    {
        "mine_pow",
        mine_pow,
        METH_VARARGS,
        "Run proof of work and return the winning nonce and SHA-256 hash."
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
    return PyModule_Create(&native_pow_module);
}
