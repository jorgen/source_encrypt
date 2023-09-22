#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static uint8_t XORKEY = /*FILL RANDOM BYTE HERE*/;

static uint8_t* generate_data(int *len)
{
    uint8_t* data = (uint8_t *) malloc(/*FILL SIZE HERE*/ * sizeof(uint8_t));
    if (data == NULL) {
        return NULL;
    }

    /*FILL DATA HERE*/

    return data;
}

static void deobfuscate(uint8_t *data, size_t length, uint8_t key)
{
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key;
    }
}