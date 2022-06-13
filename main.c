#include <stdio.h>
#include <unistd.h>

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
    mem_vals = calloc(1 << 16, 1);
    initMemoryFuncs(getMemory, setMemory);

//    loadBinFile("testing/nestest.nes", 0x8000, 0x0010, 0x4000);
//    loadBinFile("testing/nestest.nes", 0xC000, 0x0010, 0x4000);
//
//    uint8_t *mem = &mem_vals[INT_RESET+1];
//    *mem = 0xC0;
//    *(mem - 1) = 0x00;
//
//    initCPU();
//    FILE *fs = fopen("testing/testnes.log", "w");
//    setCPUFreq(100000);
//    while (1) {
//        runCycle(fs);
//    }

//    loadBinFile("testing/AllSuiteA.bin", 0xF000, 0, 0x4000);
//
//    uint8_t *mem = &mem_vals[INT_RESET+1];
//    *mem = 0xF0;
//    *(mem - 1) = 0x00;

    loadBinFile("testing/6502_functional_test.bin", 0x0000, 0, 0x0000);
    uint8_t *mem = &mem_vals[INT_RESET+1];
    *mem = 0x04;
    *(mem - 1) = 0x00;


    initCPU();
    FILE *fs = fopen("testing/AllSuiteA.log", "w");
    while (1) {
        runCycle(stdout);
//        printf("%02X\n", getMemory(0x210));
        usleep(1);
    }
    runLoop(fs);

    fclose(fs);

    return 0;
}
