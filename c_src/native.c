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

    static void do_decrypt_input(Py_buffer *content, Py_buffer *salt_iv, char *output, int *output_len)
    {
        memcpy(output, content->buf, content->len);

        uint8_t *salt_data = (uint8_t *)salt_iv->buf;
        uint8_t *iv_data = (uint8_t *)salt_iv->buf + 16;

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
        AES_init_ctx_iv(&ctx, (const uint8_t *)key, (const uint8_t *)iv_data);
        AES_CBC_decrypt_buffer(&ctx, (uint8_t *)output, content->len);

        memcpy(output_len, output, 4);
        output[*output_len + 4] = '\0';
    }

    static PyObject *decrypt(PyObject *self, PyObject *args)
    {
        Py_buffer content, salt_iv;
        char *file_name;
        Py_ssize_t filename_length;
        int timestamp;

        if (!PyArg_ParseTuple(args, "y*y*s#i", &content, &salt_iv, &file_name, &filename_length, &timestamp))
        {
            return NULL; // If parsing failed, return NULL to indicate a Python exception.
        }
        int decrypted_content_len;
        char *decrypted_content = (char *)malloc(content.len);
        if (decrypted_content == NULL)
        {
            return PyErr_NoMemory();
        }
        do_decrypt_input(&content, &salt_iv, decrypted_content, &decrypted_content_len);
        PyBuffer_Release(&content);
        PyBuffer_Release(&salt_iv);

        // Compile the code
        PyObject *compiled_code = Py_CompileStringExFlags(decrypted_content + 4, file_name, Py_file_input, NULL, 1);

        free(decrypted_content);

        if (compiled_code == NULL)
        {
            // Compilation error; Python exception is already set by Py_CompileString
            return NULL;
        }

        // Get current globals and locals
        PyObject *globals = PyEval_GetGlobals();
        PyObject *locals = PyEval_GetLocals();

        if (globals == NULL || locals == NULL)
        {
            PyErr_SetString(PyExc_RuntimeError, "Could not get current execution context");
            Py_DECREF(compiled_code);
            return NULL;
        }

        // Execute the code
        PyObject *result = PyEval_EvalCode(compiled_code, globals, locals);
        Py_DECREF(compiled_code);

        if (result == NULL)
        {
            // Runtime error; Python exception is already set by PyEval_EvalCode
            return NULL;
        }

        Py_DECREF(result);
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