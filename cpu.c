//
// Created by Paxton on 2022-03-01.
//

#include "cpu.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

/* Change nth bit to val. https://stackoverflow.com/a/47990 */
#define changeBit(num, n, val) ((num) = (num) & ~(1UL << (n)) | ((val) << (n)))

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
    return (STATUS & (1 << flag)) >> flag;
}

static inline void set_status_flag(enum StatusFlag flag, bool val) {
    changeBit(STATUS, flag, val);
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
}

static void instruction_decode(u_int16_t instruction) {

}

static inline void set_negative_flag(u_int8_t reg_val) {
    set_status_flag(STAT_NEGATIVE, reg_val >> 7);
}

static inline void set_zero_flag(u_int8_t reg_val) {
    set_status_flag(STAT_NEGATIVE, reg_val == 0);
}

/* in order as shown on https://en.wikibooks.org/wiki/6502_Assembly */

/* Load and store operations */

static void lda(const u_int8_t *mem) {
    A = *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static void ldx(const u_int8_t *mem) {
    X = *mem;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void ldy(const u_int8_t *mem) {
    Y = *mem;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static void sta(u_int8_t *mem) {
    *mem = A;
}

static void stx(u_int8_t *mem) {
    *mem = X;
}

static void sty(u_int8_t *mem) {
    *mem = Y;
}

/* Arithmetic operations */

static void adc(const u_int8_t *mem) {
    A = A + *mem + get_status_flag(STAT_CARRY);
    set_status_flag(STAT_CARRY, A < *mem);
    set_zero_flag(A);
    set_status_flag(STAT_OVERFLOW, (get_status_flag(STAT_NEGATIVE) == *mem >> 7) && (A >> 7 != *mem >> 7));
    set_negative_flag(A);
}

static void sbc(const u_int8_t *mem) {
    A = A - *mem - ~get_status_flag(STAT_CARRY);
    // TODO: Status flags
}

/* Increment and decrement */

static void inc(u_int8_t *mem) {
    (*mem)++;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
}

static void inx(u_int8_t *mem) {
    X++;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void iny(u_int8_t *mem) {
    Y++;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static void dec(u_int8_t *mem) {
    (*mem)++;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
}

static void dex(u_int8_t *mem) {
    X--;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void dey(u_int8_t *mem) {
    Y--;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

/* Shift and rotate */

static void asl(u_int8_t *mem) {
    bool carry = *mem & 0x8;
    *mem = *mem << 1;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static void lsr(u_int8_t *mem) {
    bool carry = *mem & 1;
    *mem = *mem >> 1;
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static void rol(u_int8_t *mem) {
    bool carry = *mem & 0x8;
    *mem = *mem << 1;
    changeBit(*mem, 0, get_status_flag(STAT_CARRY));
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

static void ror(u_int8_t *mem) {
    bool carry = *mem & 1;
    *mem = *mem >> 1;
    changeBit(*mem, 7, get_status_flag(STAT_CARRY));
    set_negative_flag(*mem);
    set_zero_flag(*mem);
    set_status_flag(STAT_CARRY, carry);
}

/* Logic */

static void and(const u_int8_t *mem) {
    A &= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static void ora(const u_int8_t *mem) {
    A |= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

static void eor(const u_int8_t *mem) {
    A ^= *mem;
    set_negative_flag(A);
    set_zero_flag(A);
}

/* Compare and test bit */

static void cmp(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, A < *mem);
    set_status_flag(STAT_ZERO, A == *mem);
    set_status_flag(STAT_CARRY, A >= *mem);
}

static void cpx(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, X < *mem);
    set_status_flag(STAT_ZERO, X == *mem);
    set_status_flag(STAT_CARRY, X >= *mem);
}

static void cpy(const u_int8_t *mem) {
    set_status_flag(STAT_NEGATIVE, Y < *mem);
    set_status_flag(STAT_ZERO, Y == *mem);
    set_status_flag(STAT_CARRY, Y >= *mem);
}

static void bit(const u_int8_t *mem) {
    u_int8_t anded_val = A & *mem;
    set_status_flag(STAT_NEGATIVE, anded_val >> 7);
    set_status_flag(STAT_OVERFLOW, anded_val >> 6);
}

static void bif(const int8_t *mem, enum StatusFlag flag, bool branch_eq) {
    if (get_status_flag(flag) == branch_eq) {
        PC += *mem;
    }
}

static void tax() {
    X = A;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void txa() {
    A = X;
    set_negative_flag(A);
    set_zero_flag(A);
}

static void tay() {
    Y = A;
    set_negative_flag(Y);
    set_zero_flag(Y);
}

static void tya() {
    A = Y;
    set_negative_flag(A);
    set_zero_flag(A);
}

static void tsx() {
    X = S;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void txs() {
    S = X;
    set_negative_flag(X);
    set_zero_flag(X);
}

static void pha() {
    // mem = get_mem(S)
    S -= 8;
    // *mem = A;
}

static void pla() {
    // mem = get_mem(S)
    // A = *mem
    S += 8;
}

static void php() {
    // mem = get_mem(S)
    S -= 8;
    // *mem = STATUS;
}

static void plp() {
    // mem = get_mem(S)
    // STATUS = *mem
    S += 8;
}

/* Subroutines and jump */

static void jmp(const u_int16_t *mem) {
    PC = *mem;
}

static void jsr(const u_int8_t *mem) {
    u_int8_t low_byte = (PC-1) & 0x0F;
    u_int8_t high_byte = (PC-1) & 0xF0;
    S -= 16;
    // stack_mem = get_mem(S + 8);
    // *stack_mem = high_byte;
    // stack_mem = get_mem(S);
    // *stack_mem = low_byte;
    PC = *mem;
}

static void rts () {
    // u_int8_t low_byte = *get_mem(S);
    // u_int8_t high_byte = *get_mem(S - 8);
    S += 16;
    // u_int16_t addr = (high_byte << 8) + low_byte;
    // pc = addr;
}

static void rti () {
    // u_int8_t low_byte = *get_mem(S);
    // u_int8_t high_byte = *get_mem(S - 8);
    S += 16;
    // u_int16_t addr = (high_byte << 8) + low_byte;
    // STATUS = addr;
    // low_byte = *get_mem(S);
    // high_byte = *get_mem(S - 8);
    S += 16;
    // u_int16_t addr = (high_byte << 8) + low_byte;
    // PC = addr;
}

/* Set and clear */

static void clc() {
    set_status_flag(STAT_CARRY, 0);
}

static void sec() {
    set_status_flag(STAT_CARRY, 1);
}

static void cld() {
    set_status_flag(STAT_DEC_MODE, 0);
}

static void sed() {
    set_status_flag(STAT_DEC_MODE, 1);
}

static void cli() {
    set_status_flag(STAT_IRQ_DISABLE, 0);
}

static void sei() {
    set_status_flag(STAT_IRQ_DISABLE, 1);
}

/* Miscellaneous */

static void clv() {
    set_status_flag(STAT_OVERFLOW, 0);
}

static void brk() {
    set_status_flag(STAT_BRK_COMMAND, 1);
    set_status_flag(STAT_IRQ_DISABLE, 1);
}

static void nop() {
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
        bif, /* General "branch if" op. The condition is defined for each specific branch instruc. in the OpcodeInfo struct */
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

static inline void call0(struct OpcodeInfo *info) {
    op_vec[info->op_type]();
}

static inline void call1(struct OpcodeInfo *info, u_int8_t *mem) {
    op_vec[info->op_type](mem);
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
