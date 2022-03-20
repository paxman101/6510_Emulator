//
// Created by Paxton on 2022-03-01.
//

#ifndef INC_6510_CPU_H
#define INC_6510_CPU_H

#include <stdio.h>

/* Types of interrupts to be handled by the cpu.
 * The value of which corresponds to the LSB of each interrupt's respective interrupt vector (excpet for KILL) */
enum InterruptTypes {
    INT_KILL  = -1,
    INT_RESET = 0xFFFC,
    INT_NMI   = 0xFFFA,  /* Non maskable interrupt */
    INT_IRQ   = 0xFFFE   /* Maskable interrupt */
};

void initCPU();

/* Triggers an INT_RESET. */
void resetCPU();

void triggerInterrupt(enum InterruptTypes interrupt);

/* Begins CPU execution in a new thread.
 * If log_stream is not NULL, the cpu will print debug info to the given file
 * each cycle. */
void startCPUExecution(FILE *log_stream);

#endif //INC_6510_CPU_H
