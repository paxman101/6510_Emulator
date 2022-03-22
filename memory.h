//
// Created by Paxton on 2022-03-04.
//

#ifndef INC_6510_MEMORY_H
#define INC_6510_MEMORY_H

#include <stdint.h>

typedef uint8_t (*GetMemoryFunc)(uint16_t address);
typedef void (*SetMemoryFunc)(uint16_t address, uint8_t val);

/* Define function that will access the memory with func. */
void initMemoryFuncs(GetMemoryFunc get_func, SetMemoryFunc set_func);

uint8_t getMemoryValue(uint16_t address);

void setMemoryValue(uint16_t address, uint8_t val);

void loadBinFile(const char *path, uint16_t mem_offset, long file_offset, uint16_t bytes_to_read);

#endif //INC_6510_MEMORY_H
