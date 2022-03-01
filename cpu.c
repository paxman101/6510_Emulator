//
// Created by Paxton on 2022-03-01.
//

#include "cpu.h"

#include <stdlib.h>

/* 6510 Registers (https://www.c64-wiki.com/wiki/CPU_6510-Register_set) */
static u_int16_t PC;
static u_int8_t  STATUS;
static u_int8_t  ACCUMULATOR;
static u_int8_t  X;
static u_int8_t  Y;
