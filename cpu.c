//
// Created by Paxton on 2022-03-01.
//

#include "cpu.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

/* 6510 Registers (https://www.c64-wiki.com/wiki/CPU_6510-Register_set) */
static u_int16_t PC;
static u_int8_t  STATUS;
static u_int8_t  A;         /* accumulator */
static u_int8_t  X;         /* X index */
static u_int8_t  Y;         /* Y index */
static u_int8_t  S;         /* stack point */

/* Status Flags */
enum StatusFlag {
    STAT_CARRY = 0,
    STAT_ZERO  = 1,
    STAT_IRQ_DISABLE = 2,
    STAT_DEC_MODE = 3,
    STAT_BRK_COMMAND = 4,
    STAT_OVERFLOW = 6,
    STAT_NEGATIVE = 7
};

static inline bool get_status_flag(enum StatusFlag flag) {
    return (STATUS ^ (1 << flag)) >> flag;
}

enum Operation {
    OP_ORA,
    OP_AND,
    OP_EOR,
    OP_ADC,
    OP_STA,
    OP_LDA,
    OP_CMP,
    OP_SBC
};

char *op_names[] = {
       "OP_ORA",
       "OP_AND",
       "OP_EOR",
       "OP_ADC",
       "OP_STA",
       "OP_LDA",
       "OP_CMP",
       "OP_SBC"
};

enum AddressingMode {
    ADDR_ACCUMULATOR,
    ADDR_IMMEDIATE,
    ADDR_ABSOLUTE,
    ADDR_ZERO_PAGE,
    ADDR_INDEXED_ZERO_PAGE,
    ADDR_INDEX_ABSOLUTE,
    ADDR_IMPLIED,
    ADDR_RELATIVE,
    ADDR_INDEXED_INDIRECT,
    ADDR_INDIRECT_INDEXED,
    ADDR_ABSOLUTE_INDIRECT
};

struct OpcodeInfo {
    enum Operation op_type;
    enum AddressingMode addr_mode;
    char index; /* Which index A or B to use for indexed operations. X = 'X', Y = 'Y'. */
};

static struct OpcodeInfo OPCODE_INFO_VEC[256];

/* https://llx.com/Neil/a2/opcodes.html */
static void init_opcode_vec() {
    /* Bit pattern aaabbbcc */
    u_int8_t aaa;
    u_int8_t bbb;
    u_int8_t cc;

    /* cc = 1 case */
    cc = 1;
    for (aaa = 0; aaa < 8; aaa++) {
        for (bbb = 0; bbb < 8; bbb++) {
            u_int8_t instruction = (aaa << 5) + (bbb << 2) + cc;

            /* immediate STA is invalid */
            if (instruction == 0x89) {
                break;
            }

            struct OpcodeInfo op_info;

            switch (aaa) {
                case 0:
                    op_info.op_type = OP_ORA;
                    break;
                case 1:
                    op_info.op_type = OP_AND;
                    break;
                case 2:
                    op_info.op_type = OP_EOR;
                    break;
                case 3:
                    op_info.op_type = OP_ADC;
                    break;
                case 4:
                    op_info.op_type = OP_STA;
                    break;
                case 5:
                    op_info.op_type = OP_LDA;
                    break;
                case 6:
                    op_info.op_type = OP_CMP;
                    break;
                case 7:
                    op_info.op_type = OP_SBC;
                    break;
                default:
                    assert(false);
            }

            switch (bbb) {
                case 0:
                    op_info.addr_mode = ADDR_INDEXED_INDIRECT;
                    op_info.index = 'X';
                    break;
                case 1:
                    op_info.addr_mode = ADDR_ZERO_PAGE;
                    break;
                case 2:
                    op_info.addr_mode = ADDR_IMMEDIATE;
                    break;
                case 3:
                    op_info.addr_mode = ADDR_ABSOLUTE;
                    break;
                case 4:
                    op_info.addr_mode = ADDR_INDIRECT_INDEXED;
                    op_info.index = 'Y';
                case 5:
                    op_info.addr_mode = ADDR_INDEXED_ZERO_PAGE;
                    op_info.index = 'X';
                    break;
                case 6:
                    op_info.addr_mode = ADDR_INDEX_ABSOLUTE;
                    op_info.index = 'Y';
                    break;
                case 7:
                    op_info.addr_mode = ADDR_INDEX_ABSOLUTE;
                    op_info.index = 'X';
                    break;
                default:
                    assert(false);
            }
            OPCODE_INFO_VEC[instruction] = op_info;
        }
    }
}

static void instruction_decode(u_int16_t instruction) {

}

#include <stdio.h>

int main () {
    init_opcode_vec();
    for (int i = 0; i < 256; i++) {
        struct OpcodeInfo info = OPCODE_INFO_VEC[i];
        if (info.addr_mode != 0) {
            printf("OP: %s ADDR: %d VAL: 0x%02x\n", op_names[info.op_type], info.addr_mode, i);
        }
    }
    return 0;
}
