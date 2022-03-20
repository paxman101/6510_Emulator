#include <stdio.h>

#include "cpu.h"
#include "memory.h"

int main() {
    initMemory((1 << 16) - 1);

    loadBinFile("testing/nestest.nes", 0x8000, 0x0010, 0x4000);
    loadBinFile("testing/nestest.nes", 0xC000, 0x0010, 0x4000);

    u_int8_t *mem = getMemoryPtr(INT_RESET+1);
    *mem = 0xC0;
    *(mem - 1) = 0x00;

    initCPU();
    FILE *fs = fopen("testing/testnes.log", "w");
    setCPUFreq(100000);
//    startCPUExecution(stdout);

    while (!feof(stdin));
    fclose(fs);

    return 0;
}
