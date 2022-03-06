//
// Created by Paxton on 2022-03-01.
//

#ifndef INC_6510_CPU_H
#define INC_6510_CPU_H

/* Types of interrupts to be handled by the cpu.
 * The value of which corresponds to the LSB of each interrupt's respective interrupt vector */
enum InterruptTypes {
    INT_RESET = 0xFFFC,
    INT_NMI   = 0xFFFA,  /* Non maskable interrupt */
    INT_IRQ   = 0xFFFE   /* Maskable interrupt */
};

void initCPU();

void resetCPU();

void triggerInterrupt(enum InterruptTypes interrupt);

void startCPUExecution();

#endif //INC_6510_CPU_H
