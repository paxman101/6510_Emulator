//
// Created by Paxton on 2022-03-01.
//

#include "cpu.h"

#include <stdlib.h>
#include <stdbool.h>

/* 6510 Registers (https://www.c64-wiki.com/wiki/CPU_6510-Register_set) */
static u_int16_t PC;
static u_int8_t  STATUS;
static u_int8_t  A;
static u_int8_t  X;
static u_int8_t  Y;

/* Status Flags */
enum STATUS_FLAG {
    STAT_CARRY = 0,
    STAT_ZERO  = 1,
    STAT_IRQ_DISABLE = 2,
    STAT_DEC_MODE = 3,
    STAT_BRK_COMMAND = 4,
    STAT_OVERFLOW = 6,
    STAT_NEGATIVE = 7
};

static inline bool get_status_flag(enum STATUS_FLAG flag) {
    return (STATUS ^ (1 << flag)) >> flag;
}
