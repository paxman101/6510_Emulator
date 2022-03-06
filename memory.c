//
// Created by Paxton on 2022-03-04.
//

#include "memory.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

static u_int8_t *memory_contents = NULL;
static u_int16_t mem_size;

void initMemory(u_int16_t size) {
    assert(memory_contents == NULL);
    memory_contents = malloc(size);
    mem_size = size;
}

void clearMemory() {
    assert(memory_contents != NULL);
    memset(memory_contents, 0, mem_size);
}

void freeMemory() {
    assert(memory_contents != NULL);
    free(memory_contents);
}

u_int8_t *getMemoryPtr(u_int16_t address) {
    assert(memory_contents != NULL);
    assert(address <= mem_size);
    return &memory_contents[address];
}

void loadBinFile(const char *path, u_int16_t offset, long file_offset, u_int16_t bytes_to_read) {
    FILE *bin_file = fopen(path, "rb");

    if (bin_file == NULL) {
        perror("loadBinFile(): fopen():");
        exit(1);
    }

    if (fseek(bin_file, file_offset, SEEK_SET) != 0) {
        perror("loadBinFile(): fseek():");
    }

    int in;

    int loc = 0;
    while ((in = getc(bin_file)) != EOF && loc < bytes_to_read) {
        memory_contents[offset + loc++] = in;
    }

    fclose(bin_file);
}
