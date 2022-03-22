#include <stdio.h>

#include "cpu.h"
#include "memory.h"

static uint8_t *mem_vals;

static uint8_t getMemory(uint16_t addr) {
    return mem_vals[addr];
}

static void setMemory(uint16_t addr, uint8_t val) {
    mem_vals[addr] = val;
}

int main() {
    mem_vals = malloc(1 << 16);
    initMemoryFuncs(getMemory, setMemory);

    loadBinFile("testing/nestest.nes", 0x8000, 0x0010, 0x4000);
    loadBinFile("testing/nestest.nes", 0xC000, 0x0010, 0x4000);

    uint8_t *mem = &mem_vals[INT_RESET+1];
    *mem = 0xC0;
    *(mem - 1) = 0x00;

    initCPU();
    FILE *fs = fopen("testing/testnes.log", "w");
    setCPUFreq(100000);
    runLoop(fs);

    fclose(fs);

    return 0;
}
