//
// Created by Paxton on 2022-03-01.
//

#include "cpu.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

#include "memory.h"

/* Change nth bit to val. https://stackoverflow.com/a/47990 */
#define changeBit(num, n, val) ((num) = (num) & ~(1UL << (n)) | ((val) << (n)))

/* 6510 Registers (https://www.c64-wiki.com/wiki/CPU_6510-Register_set) */
static u_int16_t PC;
static u_int8_t  STATUS;
static u_int8_t  A;         /* accumulator */
static u_int8_t  X;         /* X index */
static u_int8_t  Y;         /* Y index */
static u_int8_t  S;         /* stack point */

static u_int64_t cycles;

static enum InterruptTypes current_interrupt = 0;
pthread_t cpu_run_thread;

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
    return (STATUS & (1 << flag)) >> flag;
}

static inline void set_status_flag(enum StatusFlag flag, bool val) {
    changeBit(STATUS, flag, val);
}

// checks if the two given addresses are on different pages
static inline bool crossed_boundary(u_int16_t addr1, u_int16_t addr2) {
    return (addr1 >> 8) != (addr2 >> 8);
}

enum Operation {
    OP_ORA,
    OP_AND,
    OP_EOR,
    OP_ADC,
    OP_STA,
    OP_LDA,
    OP_CMP,
    OP_SBC,
    OP_ASL,
    OP_ROL,
    OP_LSR,
    OP_ROR,
    OP_STX,
    OP_LDX,
    OP_DEC,
    OP_INC,
    OP_BIT,
    OP_JMP,
    OP_STY,
    OP_LDY,
    OP_CPY,
    OP_CPX,
    OP_BIF, /* General "branch if" op. The condition is defined for each specific branch instruc. in the OpcodeInfo struct */
    OP_BRK,
    OP_JSR,
    OP_RTI,
    OP_RTS,
    OP_PHP,
    OP_PLP,
    OP_PHA,
    OP_PLA,
    OP_DEY,
    OP_TAY,
    OP_INY,
    OP_INX,
    OP_CLC,
    OP_SEC,
    OP_CLI,
    OP_SEI,
    OP_TYA,
    OP_CLV,
    OP_CLD,
    OP_SED,
    OP_TXA,
    OP_TXS,
    OP_TAX,
    OP_TSX,
    OP_DEX,
    OP_NOP
};

char *op_names[] = {
       "OP_ORA",
       "OP_AND",
       "OP_EOR",
       "OP_ADC",
       "OP_STA",
       "OP_LDA",
       "OP_CMP",
       "OP_SBC",
       "OP_ASL",
       "OP_ROL",
       "OP_LSR",
       "OP_ROR",
       "OP_STX",
       "OP_LDX",
       "OP_DEC",
       "OP_INC",
       "OP_BIT",
       "OP_JMP",
       "OP_STY",
       "OP_LDY",
       "OP_CPY",
       "OP_CPX",
       "OP_BIF",
       "OP_BRK",
       "OP_JSR",
       "OP_RTI",
       "OP_RTS",
       "OP_PHP",
       "OP_PLP",
       "OP_PHA",
       "OP_PLA",
       "OP_DEY",
       "OP_TAY",
       "OP_INY",
       "OP_INX",
       "OP_CLC",
       "OP_SEC",
       "OP_CLI",
       "OP_SEI",
       "OP_TYA",
       "OP_CLV",
       "OP_CLD",
       "OP_SED",
       "OP_TXA",
       "OP_TXS",
       "OP_TAX",
       "OP_TSX",
       "OP_DEX",
       "OP_NOP"
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
    char index;                        /* Which index A or B to use for indexed operations. X = 'X', Y = 'Y'. */
    enum StatusFlag branch_condition;  /* Flag used for OP_BIF */
    bool branch_eq;                    /* bool for OP_BIF. true if we should branch when branch_condition is 1 and vice versa */
    u_int8_t num_cycles;
    bool extra_cycle_if_cross;         /* true when the instruction takes an extra cycle on page boundary cross */
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

            bool is_valid = true;
            /* immediate STA is invalid */
            if (instruction == 0x89) {
                is_valid = false;
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
                    break;
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
            if (is_valid) {
                OPCODE_INFO_VEC[instruction] = op_info;
            }
        }

    }

    /* cc = 2 case */
    cc = 2;
    for (aaa = 0; aaa < 8; aaa++) {
        for (bbb = 0; bbb < 8; bbb++) {
            u_int8_t instruction = (aaa << 5) + (bbb << 2) + cc;
            bool is_valid = true;

            struct OpcodeInfo op_info;

            switch (aaa) {
                case 0:
                    op_info.op_type = OP_ASL;
                    break;
                case 1:
                    op_info.op_type = OP_ROL;
                    break;
                case 2:
                    op_info.op_type = OP_LSR;
                    break;
                case 3:
                    op_info.op_type = OP_ROR;
                    break;
                case 4:
                    op_info.op_type = OP_STX;
                    break;
                case 5:
                    op_info.op_type = OP_LDX;
                    break;
                case 6:
                    op_info.op_type = OP_DEC;
                    break;
                case 7:
                    op_info.op_type = OP_INC;
                    break;
                default:
                    assert(false);
            }

            switch (bbb) {
                case 0:
                    op_info.addr_mode = ADDR_IMMEDIATE;
                    is_valid = op_info.op_type == OP_LDX;
                    break;
                case 1:
                    op_info.addr_mode = ADDR_ZERO_PAGE;
                    break;
                case 2:
                    op_info.addr_mode = ADDR_ACCUMULATOR;
                    is_valid = op_info.op_type < OP_STX;
                    break;
                case 3:
                    op_info.addr_mode = ADDR_ABSOLUTE;
                    break;
                case 5:
                    op_info.addr_mode = ADDR_INDEXED_ZERO_PAGE;
                    op_info.index = op_info.op_type == OP_STX || op_info.op_type == OP_LDX ? 'Y' : 'X';
                    break;
                case 7:
                    op_info.addr_mode = ADDR_INDEX_ABSOLUTE;
                    op_info.index = op_info.op_type == OP_LDX ? 'Y' : 'X';
                    is_valid = op_info.op_type != OP_STX;
                    break;
                default:
                    is_valid = false;
            }
            if (is_valid) {
                OPCODE_INFO_VEC[instruction] = op_info;
            }
        }
    }

    /* cc = 0 case */
    cc = 0;
    for (aaa = 1; aaa < 8; aaa++) {
        for (bbb = 0; bbb < 8; bbb++) {
            u_int8_t instruction = (aaa << 5) + (bbb << 2) + cc;
            bool is_valid = true;

            struct OpcodeInfo op_info;

            switch (aaa) {
                case 1:
                    op_info.op_type = OP_BIT;
                    break;
                case 2:
                case 3:
                    op_info.op_type = OP_JMP;
                    break;
                case 4:
                    op_info.op_type = OP_STY;
                    break;
                case 5:
                    op_info.op_type = OP_LDY;
                    break;
                case 6:
                    op_info.op_type = OP_CPY;
                    break;
                case 7:
                    op_info.op_type = OP_CPX;
                    break;
                default:
                    assert(false);
            }

            switch (bbb) {
                case 0:
                    op_info.addr_mode = ADDR_IMMEDIATE;
                    is_valid = op_info.op_type > OP_STY;
                    break;
                case 1:
                    op_info.addr_mode = ADDR_ZERO_PAGE;
                    is_valid = op_info.op_type != OP_JMP;
                    break;
                case 3:
                    op_info.addr_mode = ADDR_ABSOLUTE;
                    if (aaa == 3) {
                        op_info.addr_mode = ADDR_ABSOLUTE_INDIRECT;
                    }
                    break;
                case 5:
                    op_info.addr_mode = ADDR_INDEXED_ZERO_PAGE;
                    op_info.index = 'X';
                    is_valid = op_info.op_type == OP_STY || op_info.op_type == OP_LDY;
                    break;
                case 7:
                    op_info.addr_mode = ADDR_INDEX_ABSOLUTE;
                    op_info.index = 'X';
                    is_valid = op_info.op_type == OP_LDY;
                    break;
                default:
                    is_valid = false;
            }
            if (is_valid) {
                OPCODE_INFO_VEC[instruction] = op_info;
            }
        }
    }

    /* conditional branch instructions with bit pattern xxy10000 */
    for (u_int8_t xx = 0; xx < 4; xx++) {
        for (u_int8_t y = 0; y < 2; y++) {
            u_int8_t instruction = (xx << 6) + (y << 5) + 16;
            struct OpcodeInfo op_info = {.op_type = OP_BIF, .addr_mode = ADDR_RELATIVE, .branch_eq = y};
            switch (xx) {
                case 0:
                    op_info.branch_condition = STAT_NEGATIVE;
                    break;
                case 1:
                    op_info.branch_condition = STAT_OVERFLOW;
                    break;
                case 2:
                    op_info.branch_condition = STAT_CARRY;
                    break;
                case 3:
                    op_info.branch_condition = STAT_ZERO;
                    break;
                default:
                    assert(false);
            }
            OPCODE_INFO_VEC[instruction] = op_info;
        }
    }

    /* Remaining instructions: */
    struct OpcodeInfo op_info = {.addr_mode = ADDR_IMPLIED};
    op_info.op_type = OP_BRK;
    OPCODE_INFO_VEC[0x00] = op_info;
    op_info.op_type = OP_JSR;
    op_info.addr_mode = ADDR_ABSOLUTE;
    OPCODE_INFO_VEC[0x20] = op_info;
    op_info.op_type = OP_RTI;
    op_info.addr_mode = ADDR_IMPLIED;
    OPCODE_INFO_VEC[0x40] = op_info;
    op_info.op_type = OP_RTS;
    OPCODE_INFO_VEC[0x60] = op_info;
    op_info.op_type = OP_PHP;
    OPCODE_INFO_VEC[0x08] = op_info;
    op_info.op_type = OP_PLP;
    OPCODE_INFO_VEC[0x28] = op_info;
    op_info.op_type = OP_PHA;
    OPCODE_INFO_VEC[0x48] = op_info;
    op_info.op_type = OP_PLA;
    OPCODE_INFO_VEC[0x68] = op_info;
    op_info.op_type = OP_DEY;
    OPCODE_INFO_VEC[0x88] = op_info;
    op_info.op_type = OP_TAY;
    OPCODE_INFO_VEC[0xA8] = op_info;
    op_info.op_type = OP_INY;
    OPCODE_INFO_VEC[0xC8] = op_info;
    op_info.op_type = OP_INX;
    OPCODE_INFO_VEC[0xE8] = op_info;
    op_info.op_type = OP_CLC;
    OPCODE_INFO_VEC[0x18] = op_info;
    op_info.op_type = OP_SEC;
    OPCODE_INFO_VEC[0x38] = op_info;
    op_info.op_type = OP_CLI;
    OPCODE_INFO_VEC[0x58] = op_info;
    op_info.op_type = OP_SEI;
    OPCODE_INFO_VEC[0x78] = op_info;
    op_info.op_type = OP_TYA;
    OPCODE_INFO_VEC[0x98] = op_info;
    op_info.op_type = OP_CLV;
    OPCODE_INFO_VEC[0xB8] = op_info;
    op_info.op_type = OP_CLD;
    OPCODE_INFO_VEC[0xD8] = op_info;
    op_info.op_type = OP_SED;
    OPCODE_INFO_VEC[0xF8] = op_info;
    op_info.op_type = OP_TXA;
    OPCODE_INFO_VEC[0x8A] = op_info;
    op_info.op_type = OP_TXS;
    OPCODE_INFO_VEC[0x9A] = op_info;
    op_info.op_type = OP_TAX;
    OPCODE_INFO_VEC[0xAA] = op_info;
    op_info.op_type = OP_TSX;
    OPCODE_INFO_VEC[0xBA] = op_info;
    op_info.op_type = OP_DEX;
    OPCODE_INFO_VEC[0xCA] = op_info;
    op_info.op_type = OP_NOP;
    OPCODE_INFO_VEC[0xEA] = op_info;
    /* set cycle count for each instruction */
    OPCODE_INFO_VEC[0x00].num_cycles = 7;
    OPCODE_INFO_VEC[0x01].num_cycles = 6;
    OPCODE_INFO_VEC[0x05].num_cycles = 3;
    OPCODE_INFO_VEC[0x06].num_cycles = 5;
    OPCODE_INFO_VEC[0x08].num_cycles = 3;
    OPCODE_INFO_VEC[0x09].num_cycles = 2;
    OPCODE_INFO_VEC[0x0A].num_cycles = 2;
    OPCODE_INFO_VEC[0x0D].num_cycles = 4;
    OPCODE_INFO_VEC[0x0E].num_cycles = 6;
    OPCODE_INFO_VEC[0x10].num_cycles = 2;
    OPCODE_INFO_VEC[0x10].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x11].num_cycles = 5;
    OPCODE_INFO_VEC[0x11].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x15].num_cycles = 4;
    OPCODE_INFO_VEC[0x16].num_cycles = 6;
    OPCODE_INFO_VEC[0x18].num_cycles = 2;
    OPCODE_INFO_VEC[0x19].num_cycles = 4;
    OPCODE_INFO_VEC[0x19].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x1D].num_cycles = 4;
    OPCODE_INFO_VEC[0x1D].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x1E].num_cycles = 7;
    OPCODE_INFO_VEC[0x20].num_cycles = 6;
    OPCODE_INFO_VEC[0x21].num_cycles = 6;
    OPCODE_INFO_VEC[0x24].num_cycles = 3;
    OPCODE_INFO_VEC[0x25].num_cycles = 3;
    OPCODE_INFO_VEC[0x26].num_cycles = 5;
    OPCODE_INFO_VEC[0x28].num_cycles = 4;
    OPCODE_INFO_VEC[0x29].num_cycles = 2;
    OPCODE_INFO_VEC[0x2A].num_cycles = 2;
    OPCODE_INFO_VEC[0x2C].num_cycles = 4;
    OPCODE_INFO_VEC[0x2D].num_cycles = 4;
    OPCODE_INFO_VEC[0x2E].num_cycles = 6;
    OPCODE_INFO_VEC[0x30].num_cycles = 2;
    OPCODE_INFO_VEC[0x30].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x31].num_cycles = 5;
    OPCODE_INFO_VEC[0x31].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x35].num_cycles = 4;
    OPCODE_INFO_VEC[0x36].num_cycles = 6;
    OPCODE_INFO_VEC[0x38].num_cycles = 2;
    OPCODE_INFO_VEC[0x39].num_cycles = 4;
    OPCODE_INFO_VEC[0x39].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x3D].num_cycles = 4;
    OPCODE_INFO_VEC[0x3D].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x3E].num_cycles = 7;
    OPCODE_INFO_VEC[0x40].num_cycles = 6;
    OPCODE_INFO_VEC[0x41].num_cycles = 6;
    OPCODE_INFO_VEC[0x45].num_cycles = 3;
    OPCODE_INFO_VEC[0x46].num_cycles = 5;
    OPCODE_INFO_VEC[0x48].num_cycles = 3;
    OPCODE_INFO_VEC[0x49].num_cycles = 2;
    OPCODE_INFO_VEC[0x4A].num_cycles = 2;
    OPCODE_INFO_VEC[0x4C].num_cycles = 3;
    OPCODE_INFO_VEC[0x4D].num_cycles = 4;
    OPCODE_INFO_VEC[0x4E].num_cycles = 6;
    OPCODE_INFO_VEC[0x50].num_cycles = 2;
    OPCODE_INFO_VEC[0x50].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x51].num_cycles = 5;
    OPCODE_INFO_VEC[0x51].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x55].num_cycles = 4;
    OPCODE_INFO_VEC[0x56].num_cycles = 6;
    OPCODE_INFO_VEC[0x58].num_cycles = 2;
    OPCODE_INFO_VEC[0x59].num_cycles = 4;
    OPCODE_INFO_VEC[0x59].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x5D].num_cycles = 4;
    OPCODE_INFO_VEC[0x5D].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x5E].num_cycles = 7;
    OPCODE_INFO_VEC[0x60].num_cycles = 6;
    OPCODE_INFO_VEC[0x61].num_cycles = 6;
    OPCODE_INFO_VEC[0x65].num_cycles = 3;
    OPCODE_INFO_VEC[0x66].num_cycles = 5;
    OPCODE_INFO_VEC[0x68].num_cycles = 4;
    OPCODE_INFO_VEC[0x69].num_cycles = 2;
    OPCODE_INFO_VEC[0x6A].num_cycles = 2;
    OPCODE_INFO_VEC[0x6C].num_cycles = 5;
    OPCODE_INFO_VEC[0x6D].num_cycles = 4;
    OPCODE_INFO_VEC[0x6E].num_cycles = 6;
    OPCODE_INFO_VEC[0x70].num_cycles = 2;
    OPCODE_INFO_VEC[0x70].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x71].num_cycles = 5;
    OPCODE_INFO_VEC[0x71].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x75].num_cycles = 4;
    OPCODE_INFO_VEC[0x76].num_cycles = 6;
    OPCODE_INFO_VEC[0x78].num_cycles = 2;
    OPCODE_INFO_VEC[0x79].num_cycles = 4;
    OPCODE_INFO_VEC[0x79].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x7D].num_cycles = 4;
    OPCODE_INFO_VEC[0x7D].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x7E].num_cycles = 7;
    OPCODE_INFO_VEC[0x81].num_cycles = 6;
    OPCODE_INFO_VEC[0x84].num_cycles = 3;
    OPCODE_INFO_VEC[0x85].num_cycles = 3;
    OPCODE_INFO_VEC[0x86].num_cycles = 3;
    OPCODE_INFO_VEC[0x88].num_cycles = 2;
    OPCODE_INFO_VEC[0x8A].num_cycles = 2;
    OPCODE_INFO_VEC[0x8C].num_cycles = 4;
    OPCODE_INFO_VEC[0x8D].num_cycles = 4;
    OPCODE_INFO_VEC[0x8E].num_cycles = 4;
    OPCODE_INFO_VEC[0x90].num_cycles = 2;
    OPCODE_INFO_VEC[0x90].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x91].num_cycles = 6;
    OPCODE_INFO_VEC[0x94].num_cycles = 4;
    OPCODE_INFO_VEC[0x95].num_cycles = 4;
    OPCODE_INFO_VEC[0x96].num_cycles = 4;
    OPCODE_INFO_VEC[0x98].num_cycles = 2;
    OPCODE_INFO_VEC[0x99].num_cycles = 5;
    OPCODE_INFO_VEC[0x9A].num_cycles = 2;
    OPCODE_INFO_VEC[0x9D].num_cycles = 5;
    OPCODE_INFO_VEC[0xA0].num_cycles = 2;
    OPCODE_INFO_VEC[0xA1].num_cycles = 6;
    OPCODE_INFO_VEC[0xA2].num_cycles = 2;
    OPCODE_INFO_VEC[0xA4].num_cycles = 3;
    OPCODE_INFO_VEC[0xA5].num_cycles = 3;
    OPCODE_INFO_VEC[0xA6].num_cycles = 3;
    OPCODE_INFO_VEC[0xA8].num_cycles = 2;
    OPCODE_INFO_VEC[0xA9].num_cycles = 2;
    OPCODE_INFO_VEC[0xAA].num_cycles = 2;
    OPCODE_INFO_VEC[0xAC].num_cycles = 4;
    OPCODE_INFO_VEC[0xAD].num_cycles = 4;
    OPCODE_INFO_VEC[0xAE].num_cycles = 4;
    OPCODE_INFO_VEC[0xB0].num_cycles = 2;
    OPCODE_INFO_VEC[0xB0].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xB1].num_cycles = 5;
    OPCODE_INFO_VEC[0xB1].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xB4].num_cycles = 4;
    OPCODE_INFO_VEC[0xB5].num_cycles = 4;
    OPCODE_INFO_VEC[0xB6].num_cycles = 4;
    OPCODE_INFO_VEC[0xB8].num_cycles = 2;
    OPCODE_INFO_VEC[0xB9].num_cycles = 4;
    OPCODE_INFO_VEC[0xB9].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xBA].num_cycles = 2;
    OPCODE_INFO_VEC[0xBC].num_cycles = 4;
    OPCODE_INFO_VEC[0xBC].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xBD].num_cycles = 4;
    OPCODE_INFO_VEC[0xBD].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xBE].num_cycles = 4;
    OPCODE_INFO_VEC[0xBE].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xC0].num_cycles = 2;
    OPCODE_INFO_VEC[0xC1].num_cycles = 6;
    OPCODE_INFO_VEC[0xC4].num_cycles = 3;
    OPCODE_INFO_VEC[0xC5].num_cycles = 3;
    OPCODE_INFO_VEC[0xC6].num_cycles = 5;
    OPCODE_INFO_VEC[0xC8].num_cycles = 2;
    OPCODE_INFO_VEC[0xC9].num_cycles = 2;
    OPCODE_INFO_VEC[0xCA].num_cycles = 2;
    OPCODE_INFO_VEC[0xCC].num_cycles = 4;
    OPCODE_INFO_VEC[0xCD].num_cycles = 4;
    OPCODE_INFO_VEC[0xCE].num_cycles = 6;
    OPCODE_INFO_VEC[0xD0].num_cycles = 2;
    OPCODE_INFO_VEC[0xD0].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xD1].num_cycles = 5;
    OPCODE_INFO_VEC[0xD1].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xD5].num_cycles = 4;
    OPCODE_INFO_VEC[0xD6].num_cycles = 6;
    OPCODE_INFO_VEC[0xD8].num_cycles = 2;
    OPCODE_INFO_VEC[0xD9].num_cycles = 4;
    OPCODE_INFO_VEC[0xD9].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xDD].num_cycles = 4;
    OPCODE_INFO_VEC[0xDD].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xDE].num_cycles = 7;
    OPCODE_INFO_VEC[0xE0].num_cycles = 2;
    OPCODE_INFO_VEC[0xE1].num_cycles = 6;
    OPCODE_INFO_VEC[0xE4].num_cycles = 3;
    OPCODE_INFO_VEC[0xE5].num_cycles = 3;
    OPCODE_INFO_VEC[0xE6].num_cycles = 5;
    OPCODE_INFO_VEC[0xE8].num_cycles = 2;
    OPCODE_INFO_VEC[0xE9].num_cycles = 2;
    OPCODE_INFO_VEC[0xEA].num_cycles = 2;
    OPCODE_INFO_VEC[0xEC].num_cycles = 4;
    OPCODE_INFO_VEC[0xED].num_cycles = 4;
    OPCODE_INFO_VEC[0xEE].num_cycles = 6;
    OPCODE_INFO_VEC[0xF0].num_cycles = 2;
    OPCODE_INFO_VEC[0xF0].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xF1].num_cycles = 5;
    OPCODE_INFO_VEC[0xF1].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xF5].num_cycles = 4;
    OPCODE_INFO_VEC[0xF6].num_cycles = 6;
    OPCODE_INFO_VEC[0xF8].num_cycles = 2;
    OPCODE_INFO_VEC[0xF9].num_cycles = 4;
    OPCODE_INFO_VEC[0xF9].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xFD].num_cycles = 4;
    OPCODE_INFO_VEC[0xFD].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xFE].num_cycles = 7;
    OPCODE_INFO_VEC[0x03].num_cycles = 8;
    OPCODE_INFO_VEC[0x04].num_cycles = 3;
    OPCODE_INFO_VEC[0x07].num_cycles = 5;
    OPCODE_INFO_VEC[0x0B].num_cycles = 2;
    OPCODE_INFO_VEC[0x0C].num_cycles = 4;
    OPCODE_INFO_VEC[0x0F].num_cycles = 6;
    OPCODE_INFO_VEC[0x13].num_cycles = 8;
    OPCODE_INFO_VEC[0x14].num_cycles = 4;
    OPCODE_INFO_VEC[0x17].num_cycles = 6;
    OPCODE_INFO_VEC[0x1A].num_cycles = 2;
    OPCODE_INFO_VEC[0x1B].num_cycles = 7;
    OPCODE_INFO_VEC[0x1C].num_cycles = 4;
    OPCODE_INFO_VEC[0x1C].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x1F].num_cycles = 7;
    OPCODE_INFO_VEC[0x23].num_cycles = 8;
    OPCODE_INFO_VEC[0x27].num_cycles = 5;
    OPCODE_INFO_VEC[0x2B].num_cycles = 2;
    OPCODE_INFO_VEC[0x2F].num_cycles = 6;
    OPCODE_INFO_VEC[0x33].num_cycles = 8;
    OPCODE_INFO_VEC[0x34].num_cycles = 4;
    OPCODE_INFO_VEC[0x37].num_cycles = 6;
    OPCODE_INFO_VEC[0x3A].num_cycles = 2;
    OPCODE_INFO_VEC[0x3B].num_cycles = 7;
    OPCODE_INFO_VEC[0x3C].num_cycles = 4;
    OPCODE_INFO_VEC[0x3C].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x3F].num_cycles = 7;
    OPCODE_INFO_VEC[0x43].num_cycles = 8;
    OPCODE_INFO_VEC[0x44].num_cycles = 3;
    OPCODE_INFO_VEC[0x47].num_cycles = 5;
    OPCODE_INFO_VEC[0x4B].num_cycles = 2;
    OPCODE_INFO_VEC[0x4F].num_cycles = 6;
    OPCODE_INFO_VEC[0x53].num_cycles = 8;
    OPCODE_INFO_VEC[0x54].num_cycles = 4;
    OPCODE_INFO_VEC[0x57].num_cycles = 6;
    OPCODE_INFO_VEC[0x5A].num_cycles = 2;
    OPCODE_INFO_VEC[0x5B].num_cycles = 7;
    OPCODE_INFO_VEC[0x5C].num_cycles = 4;
    OPCODE_INFO_VEC[0x5C].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x5F].num_cycles = 7;
    OPCODE_INFO_VEC[0x63].num_cycles = 8;
    OPCODE_INFO_VEC[0x64].num_cycles = 3;
    OPCODE_INFO_VEC[0x67].num_cycles = 5;
    OPCODE_INFO_VEC[0x6B].num_cycles = 2;
    OPCODE_INFO_VEC[0x6F].num_cycles = 6;
    OPCODE_INFO_VEC[0x73].num_cycles = 8;
    OPCODE_INFO_VEC[0x74].num_cycles = 4;
    OPCODE_INFO_VEC[0x77].num_cycles = 6;
    OPCODE_INFO_VEC[0x7A].num_cycles = 2;
    OPCODE_INFO_VEC[0x7B].num_cycles = 7;
    OPCODE_INFO_VEC[0x7C].num_cycles = 4;
    OPCODE_INFO_VEC[0x7C].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0x7F].num_cycles = 7;
    OPCODE_INFO_VEC[0x80].num_cycles = 2;
    OPCODE_INFO_VEC[0x82].num_cycles = 2;
    OPCODE_INFO_VEC[0x83].num_cycles = 6;
    OPCODE_INFO_VEC[0x87].num_cycles = 3;
    OPCODE_INFO_VEC[0x89].num_cycles = 2;
    OPCODE_INFO_VEC[0x8B].num_cycles = 2;
    OPCODE_INFO_VEC[0x8F].num_cycles = 4;
    OPCODE_INFO_VEC[0x93].num_cycles = 6;
    OPCODE_INFO_VEC[0x97].num_cycles = 4;
    OPCODE_INFO_VEC[0x9B].num_cycles = 5;
    OPCODE_INFO_VEC[0x9C].num_cycles = 5;
    OPCODE_INFO_VEC[0x9E].num_cycles = 5;
    OPCODE_INFO_VEC[0x9F].num_cycles = 5;
    OPCODE_INFO_VEC[0xA3].num_cycles = 6;
    OPCODE_INFO_VEC[0xA7].num_cycles = 3;
    OPCODE_INFO_VEC[0xAB].num_cycles = 2;
    OPCODE_INFO_VEC[0xAF].num_cycles = 4;
    OPCODE_INFO_VEC[0xB3].num_cycles = 5;
    OPCODE_INFO_VEC[0xB3].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xB7].num_cycles = 4;
    OPCODE_INFO_VEC[0xBB].num_cycles = 4;
    OPCODE_INFO_VEC[0xBB].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xBF].num_cycles = 4;
    OPCODE_INFO_VEC[0xBF].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xC2].num_cycles = 2;
    OPCODE_INFO_VEC[0xC3].num_cycles = 8;
    OPCODE_INFO_VEC[0xC7].num_cycles = 5;
    OPCODE_INFO_VEC[0xCB].num_cycles = 2;
    OPCODE_INFO_VEC[0xCF].num_cycles = 6;
    OPCODE_INFO_VEC[0xD3].num_cycles = 8;
    OPCODE_INFO_VEC[0xD4].num_cycles = 4;
    OPCODE_INFO_VEC[0xD7].num_cycles = 6;
    OPCODE_INFO_VEC[0xDA].num_cycles = 2;
    OPCODE_INFO_VEC[0xDB].num_cycles = 7;
    OPCODE_INFO_VEC[0xDC].num_cycles = 4;
    OPCODE_INFO_VEC[0xDC].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xDF].num_cycles = 7;
    OPCODE_INFO_VEC[0xE2].num_cycles = 2;
    OPCODE_INFO_VEC[0xE3].num_cycles = 8;
    OPCODE_INFO_VEC[0xE7].num_cycles = 5;
    OPCODE_INFO_VEC[0xEB].num_cycles = 2;
    OPCODE_INFO_VEC[0xEF].num_cycles = 6;
    OPCODE_INFO_VEC[0xF3].num_cycles = 8;
    OPCODE_INFO_VEC[0xF4].num_cycles = 4;
    OPCODE_INFO_VEC[0xF7].num_cycles = 6;
    OPCODE_INFO_VEC[0xFA].num_cycles = 2;
    OPCODE_INFO_VEC[0xFB].num_cycles = 7;
    OPCODE_INFO_VEC[0xFC].num_cycles = 4;
    OPCODE_INFO_VEC[0xFC].extra_cycle_if_cross = true;
    OPCODE_INFO_VEC[0xFF].num_cycles = 7;
}

static inline void set_negative_flag(u_int8_t reg_val) {
    set_status_flag(STAT_NEGATIVE, reg_val >> 7);
}

static inline void set_zero_flag(u_int8_t reg_val) {
    set_status_flag(STAT_ZERO, reg_val == 0);
}

static inline void push_onto_stack(u_int8_t val) {
    u_int8_t *mem = getMemoryPtr(S + 0x100);
    *mem = val;
    S--;
}

static inline u_int8_t pop_from_stack() {
    S++;
    return *getMemoryPtr(S + 0x100);
}

/* in order as shown on https://en.wikibooks.org/wiki/6502_Assembly */

/* Load and store operations */

static inline void lda(const u_int8_t *mem) {
    A = *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static inline void ldx(const u_int8_t *mem) {
    X = *mem;
    set_negative_flag(X);
    set_zero_flag(X);
}

static inline void ldy(const u_int8_t *mem) {
    Y = *mem;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static inline void sta(u_int8_t *mem) {
    *mem = A;
}

static inline void stx(u_int8_t *mem) {
    *mem = X;
}

static inline void sty(u_int8_t *mem) {
    *mem = Y;
}

/* Arithmetic operations */

static inline void adc(const u_int8_t *mem) {
    u_int8_t prev_a = A;
    A = A + *mem + get_status_flag(STAT_CARRY);
    set_status_flag(STAT_CARRY, A < *mem);
    set_zero_flag(A);
    /* overflow from http://www.righto.com/2012/12/the-6502-overflow-flag-explained.html */
    set_status_flag(STAT_OVERFLOW, ((prev_a ^ A) & (*mem ^ A) & 0x80));
    set_negative_flag(A);
}

static inline void sbc(const u_int8_t *mem) {
    /* formulas from http://www.righto.com/2012/12/the-6502-overflow-flag-explained.html */
    u_int8_t prev_a = A;
    A = A + ~(*mem) + get_status_flag(STAT_CARRY);
    set_status_flag(STAT_CARRY, (int8_t)A >= 0);
    set_zero_flag(A);
    set_status_flag(STAT_OVERFLOW, ((prev_a ^ A) & (~(*mem) ^ A) & 0x80));
    set_negative_flag(A);
}

/* Increment and decrement */

static inline void inc(u_int8_t *mem) {
    (*mem)++;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
}

static inline void inx() {
    X++;
    set_negative_flag(X);
    set_zero_flag(X);
}

static inline void iny() {
    Y++;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static inline void dec(u_int8_t *mem) {
    (*mem)--;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
}

static inline void dex() {
    X--;
    set_negative_flag(X);
    set_zero_flag(X);
}

static inline void dey() {
    Y--;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

/* Shift and rotate */

static inline void asl(u_int8_t *mem) {
    bool carry = *mem & 0x80;
    *mem = *mem << 1;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static inline void lsr(u_int8_t *mem) {
    bool carry = *mem & 1;
    *mem = *mem >> 1;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static inline void rol(u_int8_t *mem) {
    bool carry = *mem & 0x80;
    *mem = *mem << 1;
    changeBit(*mem, 0, get_status_flag(STAT_CARRY));
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static inline void ror(u_int8_t *mem) {
    bool carry = *mem & 1;
    *mem = *mem >> 1;
    changeBit(*mem, 7, get_status_flag(STAT_CARRY));
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

/* Logic */

static inline void and(const u_int8_t *mem) {
    A &= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static inline void ora(const u_int8_t *mem) {
    A |= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static inline void eor(const u_int8_t *mem) {
    A ^= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

/* Compare and test bit */

static inline void cmp(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, (A - *mem) >> 7);
    set_status_flag(STAT_ZERO, A == *mem);
    set_status_flag(STAT_CARRY, A >= *mem);
}

static inline void cpx(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, (X - *mem) >> 7 );
    set_status_flag(STAT_ZERO, X == *mem);
    set_status_flag(STAT_CARRY, X >= *mem);
}

static inline void cpy(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, (Y - *mem) >> 7);
    set_status_flag(STAT_ZERO, Y == *mem);
    set_status_flag(STAT_CARRY, Y >= *mem);
}

static inline void bit(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, *mem >> 7);
    set_status_flag(STAT_OVERFLOW, (*mem & 0x40) >> 6);
    set_zero_flag(A & *mem);
}

static inline void bif(const int8_t *mem, enum StatusFlag flag, bool branch_eq) {
    if (get_status_flag(flag) == branch_eq) {
        u_int16_t old_pc = PC;
        PC += *mem;
        // more cycles are taken on page cross and when the branch is taken
        cycles += crossed_boundary(old_pc+2, PC) ? 2 : 1;
    }
}

static inline void tax() {
    X = A;
    set_negative_flag(X);
    set_zero_flag(X);
}

static inline void txa() {
    A = X;
    set_negative_flag(A);
    set_zero_flag(A);
}

static inline void tay() {
    Y = A;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static inline void tya() {
    A = Y;
    set_negative_flag(A);
    set_zero_flag(A);
}

static inline void tsx() {
    X = S;
    set_negative_flag(X);
    set_zero_flag(X);
}

static inline void txs() {
    S = X;
}

static inline void pha() {
    push_onto_stack(A);
}

static inline void pla() {
    A = pop_from_stack();
    set_zero_flag(A);
    set_negative_flag(A);
}

static inline void php() {
    /* BRK flag is always set when STATUS is pushed */
    push_onto_stack(STATUS | 0x10);
}

static inline void plp() {
    /* Ignore BRK flag but always set 5th bit*/
    STATUS = (pop_from_stack() & 0xEF) | 0x20;
}

/* Subroutines and jump */

static inline void jmp(const u_int16_t *mem) {
    PC = *mem;
}

static inline void jsr(const u_int16_t *mem) {
    u_int8_t low_byte = (PC+2) & 0xFF;
    u_int8_t high_byte = ((PC+2) & 0xFF00) >> 8;
    push_onto_stack(high_byte);
    push_onto_stack(low_byte);
    PC = *mem;
}

static inline void rts () {
    u_int8_t low_byte = pop_from_stack();
    u_int8_t high_byte = pop_from_stack();
    u_int16_t addr = (high_byte << 8) + low_byte;
    PC = addr;
}

static inline void rti () {
    /* Make sure 5th bit is always set */
    STATUS = pop_from_stack() | 0x20;
    u_int8_t low_byte = pop_from_stack();
    u_int8_t high_byte = pop_from_stack();
    u_int16_t addr = (high_byte << 8) + low_byte;
    PC = addr;
}

/* Set and clear */

static inline void clc() {
    set_status_flag(STAT_CARRY, 0);
}

static inline void sec() {
    set_status_flag(STAT_CARRY, 1);
}

static inline void cld() {
    set_status_flag(STAT_DEC_MODE, 0);
}

static inline void sed() {
    set_status_flag(STAT_DEC_MODE, 1);
}

static inline void cli() {
    set_status_flag(STAT_IRQ_DISABLE, 0);
}

static inline void sei() {
    set_status_flag(STAT_IRQ_DISABLE, 1);
}

/* Miscellaneous */

static inline void clv() {
    set_status_flag(STAT_OVERFLOW, 0);
}

static inline void brk() {
    set_status_flag(STAT_BRK_COMMAND, 1);
    set_status_flag(STAT_IRQ_DISABLE, 1);
}

static inline void nop() {
}

typedef void (*OpFunc)();

OpFunc op_vec[] = {
        ora,
        and,
        eor,
        adc,
        sta,
        lda,
        cmp,
        sbc,
        asl,
        rol,
        lsr,
        ror,
        stx,
        ldx,
        dec,
        inc,
        bit,
        jmp,
        sty,
        ldy,
        cpy,
        cpx,
        (OpFunc) bif, /* General "branch if" op. The condition is defined for each specific branch instruc. in the OpcodeInfo struct */
        brk,
        jsr,
        rti,
        rts,
        php,
        plp,
        pha,
        pla,
        dey,
        tay,
        iny,
        inx,
        clc,
        sec,
        cli,
        sei,
        tya,
        clv,
        cld,
        sed,
        txa,
        txs,
        tax,
        tsx,
        dex,
        nop
};


static void serviceInterrupt(enum InterruptTypes interrupt) {
    // Reset is a special case
    if (interrupt == INT_IRQ && get_status_flag(STAT_IRQ_DISABLE)) {
        return;
    }
    if (interrupt != INT_RESET) {
        u_int8_t pc_lsb = PC & 0x00FF;
        u_int8_t pc_msb = (PC & 0xFF00) >> 8;
        push_onto_stack(pc_msb);
        push_onto_stack(pc_lsb);
        push_onto_stack(STATUS);
    }
    else {
        // Zero out registers. This is not standard behavior on the actual 6502.
        STATUS = 0;
        X = 0;
        Y = 0;
        A = 0;
        cycles = 7;
        set_status_flag(STAT_IRQ_DISABLE, 1);
        // set unused 5th bit which is always set
        set_status_flag(5, 1);
        S = 0xFD;
    }
    PC = (*getMemoryPtr(interrupt+1) << 8) + *getMemoryPtr(interrupt);
}

static inline void call0(const struct OpcodeInfo *info) {
    op_vec[info->op_type]();
}

static inline void call1(const struct OpcodeInfo *info, u_int8_t *mem) {
    op_vec[info->op_type](mem);
}

void initCPU() {
    init_opcode_vec();
    resetCPU();
}

void resetCPU() {
    triggerInterrupt(INT_RESET);
}

void triggerInterrupt(enum InterruptTypes interrupt) {
    current_interrupt = interrupt;
}

static void *runLoop(void *aux) {
    FILE *log_stream = aux;
    while (true) {
        const struct OpcodeInfo *next_op = &OPCODE_INFO_VEC[*getMemoryPtr(PC)];
        u_int64_t start_cycle = cycles;
        struct timespec start_time;
        timespec_get(&start_time, TIME_UTC);

        if (log_stream) {
            fprintf(log_stream, "%04X  %02X    A:%02X X:%02X Y:%02X P:%02X SP:%02X CYC:%lu\n", PC, *getMemoryPtr(PC),
                   A, X, Y, STATUS, S, cycles);
        }

        switch (next_op->addr_mode) {
            case ADDR_ACCUMULATOR:
                call1(next_op, &A);
                PC += 1;
                break;
            case ADDR_IMPLIED:
                call0(next_op);
                if (next_op->op_type != OP_RTI) {
                    PC += 1;
                }
                break;
            case ADDR_IMMEDIATE:
                call1(next_op, getMemoryPtr(PC + 1));
                PC += 2;
                break;
            case ADDR_ABSOLUTE: {
                u_int16_t val = (*getMemoryPtr(PC + 2) << 8) + *getMemoryPtr(PC + 1);
                if (next_op->op_type != OP_JMP && next_op->op_type != OP_JSR) {
                    call1(next_op, getMemoryPtr(val));
                    PC += 3;
                }
                else {
                    call1(next_op, (u_int8_t *) &val);
                }
                break;
            }
            case ADDR_ZERO_PAGE:
                call1(next_op, getMemoryPtr(0x00 + *getMemoryPtr(PC + 1)));
                PC += 2;
                break;
            case ADDR_INDEXED_ZERO_PAGE:
                if (next_op->index == 'X') {
                    call1(next_op, getMemoryPtr((u_int8_t)(X + *getMemoryPtr(PC + 1))));
                }
                else {
                    call1(next_op, getMemoryPtr((u_int8_t)(Y + *getMemoryPtr(PC + 1))));
                }
                PC += 2;
                break;
            case ADDR_INDEX_ABSOLUTE: {
                u_int16_t abs_addr = (*getMemoryPtr(PC + 2) << 8) + *getMemoryPtr(PC + 1);
                u_int16_t indexed_addr = abs_addr + (next_op->index == 'X' ? X : Y);
                call1(next_op, getMemoryPtr(indexed_addr));
                if (next_op->extra_cycle_if_cross && crossed_boundary(abs_addr, indexed_addr)) {
                    cycles++;
                }
                PC += 3;
                break;
            }
            case ADDR_RELATIVE:
                assert(next_op->op_type == OP_BIF);
                bif((const int8_t *)getMemoryPtr(PC + 1), next_op->branch_condition, next_op->branch_eq);
                PC += 2;
                break;
            case ADDR_INDEXED_INDIRECT: {
                assert(next_op->index == 'X');
                u_int8_t low_byte = *getMemoryPtr((u_int8_t)(X + *getMemoryPtr(PC + 1)));
                u_int8_t high_byte = *getMemoryPtr((u_int8_t)(X + *getMemoryPtr(PC + 1) + 1));
                u_int16_t indirect_addr = (high_byte << 8) + low_byte;
                call1(next_op, getMemoryPtr(indirect_addr));
                PC += 2;
                break;
            }
            case ADDR_INDIRECT_INDEXED: {
                assert(next_op->index == 'Y');
                u_int8_t low_byte = *getMemoryPtr((u_int8_t)(*getMemoryPtr(PC + 1)));
                u_int8_t high_byte = *getMemoryPtr((u_int8_t)(*getMemoryPtr(PC + 1) + 1));
                u_int16_t indirect_addr = (high_byte << 8) + low_byte;
                u_int16_t indirect_indexed_addr = Y + indirect_addr;
                call1(next_op, getMemoryPtr(indirect_indexed_addr));
                if (next_op->extra_cycle_if_cross && crossed_boundary(indirect_addr, indirect_indexed_addr)) {
                    cycles++;
                }
                PC += 2;
                break;
            }
            case ADDR_ABSOLUTE_INDIRECT: {
                assert(next_op->op_type == OP_JMP);
                u_int8_t low_byte = *getMemoryPtr((*getMemoryPtr(PC + 2) << 8) + *getMemoryPtr(PC + 1));
                u_int8_t high_byte = *getMemoryPtr((*getMemoryPtr(PC + 2) << 8) + (u_int8_t)(*getMemoryPtr(PC + 1) + 1));
                u_int16_t indirect_addr = (high_byte << 8) + low_byte;
                jmp(&indirect_addr);
                break;
            }
            default:
                assert(false);
        }
        cycles += next_op->num_cycles;

        if (current_interrupt != 0) {
            if (current_interrupt == INT_KILL) {
                return;
            }
            serviceInterrupt(current_interrupt);
            current_interrupt = 0;
        }
    }
}

void startCPUExecution(FILE *log_stream) {
    pthread_create(&cpu_run_thread, NULL, runLoop, log_stream);
    pthread_join(cpu_run_thread, NULL);
}

//int main () {
//    init_opcode_vec();
//    for (int i = 0; i < 256; i++) {
//        struct OpcodeInfo info = OPCODE_INFO_VEC[i];
//        if (info.addr_mode != 0) {
//            printf("OP: %s ADDR: %d VAL: 0x%02x\n", op_names[info.op_type], info.addr_mode, i);
//        }
//    }
//    return 0;
//}
