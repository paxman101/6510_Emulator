//
// Created by Paxton on 2022-03-04.
//

#ifndef INC_6510_MEMORY_H
#define INC_6510_MEMORY_H

#include <stdlib.h>

typedef u_int8_t *(*GetMemoryFunc)(u_int16_t address);

/* Define function that will access the memory with func. */
void initMemory(GetMemoryFunc func);

/* Returns pointer to the memory at the given address */
u_int8_t *getMemoryPtr(u_int16_t address);

void loadBinFile(const char *path, u_int16_t mem_offset, long file_offset, u_int16_t bytes_to_read);

#endif //INC_6510_MEMORY_H
