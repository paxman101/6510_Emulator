//
// Created by Paxton on 2022-03-04.
//

#ifndef INC_6510_MEMORY_H
#define INC_6510_MEMORY_H

#include <stdint.h>

typedef uint8_t *(*GetMemoryFunc)(uint16_t address);

/* Define function that will access the memory with func. */
void initMemory(GetMemoryFunc func);

/* Returns pointer to the memory at the given address */
uint8_t *getMemoryPtr(uint16_t address);

void loadBinFile(const char *path, uint16_t mem_offset, long file_offset, uint16_t bytes_to_read);

#endif //INC_6510_MEMORY_H
