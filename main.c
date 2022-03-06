#include <stdio.h>

#include "cpu.h"
#include "memory.h"

int main() {
    initMemory((1 << 16) - 1);

    loadBinFile("nestest.nes", 0x8000, 0x0010, 0x4000);
    loadBinFile("nestest.nes", 0xC000, 0x0010, 0x4000);

    u_int8_t *mem = getMemoryPtr(INT_RESET+1);
    *mem = 0xC0;
    *(mem - 1) = 0x00;

    initCPU();
    startCPUExecution();

    return 0;
}
