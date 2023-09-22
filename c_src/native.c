#include <stdio.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "sha256.h"

#include <stdint.h>

#define CBC 1
#define CTR 0 
#define ECB 0
#include "aes.h"
#include <key.h>

#define STRINGIFY(X) #X

    static PyObject *decrypt(PyObject *self, PyObject *args)
    {
        Py_buffer content, salt_iv;
        if (!PyArg_ParseTuple(args, "y*y*", &content, &salt_iv))
        {
            return NULL; // If parsing failed, return NULL to indicate a Python exception.
        }

        char *decrypted_content = (char *)malloc(content.len);
        if (decrypted_content == NULL)
        {
            PyBuffer_Release(&content);
            PyBuffer_Release(&salt_iv);
            return PyErr_NoMemory();
        }
        memcpy(decrypted_content, content.buf, content.len);

        uint8_t *salt_data = (uint8_t*)salt_iv.buf;
        uint8_t *iv_data = (uint8_t*)salt_iv.buf + 16;

        uint8_t key[32];  

        int password_len;
        uint8_t *password = generate_data(&password_len);
        deobfuscate(password, password_len, XORKEY);

        SHA256_CTX sha_ctx;
        sha256_init(&sha_ctx);
        sha256_update(&sha_ctx, password, password_len);
        sha256_update(&sha_ctx, salt_data, 16);
        sha256_final(&sha_ctx, key);

        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, (const uint8_t *) key, (const uint8_t *)iv_data);
        AES_CBC_decrypt_buffer(&ctx, (uint8_t *)decrypted_content, content.len);
 
        PyBuffer_Release(&content);
        PyBuffer_Release(&salt_iv);

        int decrypted_len;
        memcpy(&decrypted_len, decrypted_content, 4);
        decrypted_content[decrypted_len + 4] = '\0';
        fprintf(stderr, "About to execute: %s\n", decrypted_content + 4);
        int res = PyRun_SimpleString(decrypted_content+ 4);
        free(decrypted_content);
        if (res != 0)
        {
            fprintf(stderr, "AN ERROR OCCURRED\n");
            return NULL; // An error occurred
        }
        Py_RETURN_NONE;
    }

    static PyMethodDef methods[] = {
        {"decrypt", decrypt, METH_VARARGS, "Decrypt input from given char* and size"},
        {NULL, NULL, 0, NULL}};

static struct PyModuleDef source_encrypt_native = {
    PyModuleDef_HEAD_INIT,
    "source_encrypt_native", 
    NULL, 
    -1, 
    methods 
};

PyMODINIT_FUNC PyInit_source_encrypt_native(void) {
    return PyModule_Create(&source_encrypt_native);
}