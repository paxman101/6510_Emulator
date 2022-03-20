//
// Created by Paxton on 2022-03-04.
//

#include "memory.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static GetMemoryFunc get_memory_func;

void initMemory(GetMemoryFunc func) {
    get_memory_func = func;
}

uint8_t *getMemoryPtr(uint16_t address) {
    return get_memory_func(address);
}

void loadBinFile(const char *path, uint16_t offset, long file_offset, uint16_t bytes_to_read) {
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
        *getMemoryPtr(offset + loc++) = in;
    }

    fclose(bin_file);
}
