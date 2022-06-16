//
// Created by Paxton on 2022-03-01.
//

#ifndef INC_6510_CPU_H
#define INC_6510_CPU_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef void (*SleepFunction)(uint64_t cycles);

/* Types of interrupts to be handled by the cpu.
 * The value of which corresponds to the LSB of each interrupt's respective interrupt vector (excpet for KILL) */
enum InterruptTypes {
    INT_KILL  = -1,
    INT_RESET = 0xFFFC,
    INT_NMI   = 0xFFFA,  /* Non maskable interrupt */
    INT_IRQ   = 0xFFFE   /* Maskable interrupt */
};

void initCPU();

/* When set true, the BCD flag is ignored like on the Ricoh 2A03 */
void setNESMode(bool enable_NES_mode);

/* Triggers an INT_RESET. */
void resetCPU();

void triggerInterrupt(enum InterruptTypes interrupt);

/* Run loop for the CPU emulation.
 * aux should be a pointer to a FILE stream.
 * If aux is not NULL, the cpu will print debug info to the given file
 * each cycle. */
void runLoop(void *aux);

/* Like runLoop(), can be used to cause execution of the CPU.
 * However, this function will only cause one single cycle of
 * execution before returning.
 * This may be used to more accurately emulate the timings of
 * the 6502. */
void runCycle(void *log_stream);

/* Stops CPU execution by raising INT_KILL. */
void stopCPUExecution();

/* If you want to emulate the execution speed of the 6502 with the
 * frequency set with setCPUFreq(), you can specify a function that
 * will sleep given a time_to_sleep arg in seconds. */
void setSleepFunction(SleepFunction func);

/* Set emulated CPU freq to freq given in Hz. */
void setCPUFreq(uint32_t freq);

#endif //INC_6510_CPU_H
