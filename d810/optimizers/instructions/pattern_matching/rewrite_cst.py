from ida_hexrays import *

from d810.ast import AstLeaf, AstConstant, AstNode
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.hexrays_helpers import equal_bnot_cst, SUB_TABLE, AND_TABLE, equal_bnot_mop


class CstSimplificationRule1(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_bnot,
                              AstLeaf("x_0")),
                      AstNode(m_xor,
                              AstNode(m_bnot,
                                      AstLeaf("x_0")),
                              AstConstant("c_1")))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstNode(m_bnot,
                                                  AstConstant("c_1"))),
                                  AstNode(m_bnot, AstConstant("c_1")))


class CstSimplificationRule2(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf("x_0"),
                                      AstConstant("c_1_1")),
                              AstConstant("c_2_1")),
                      AstNode(m_and,
                              AstNode(m_xor,
                                      AstLeaf("x_0"),
                                      AstConstant("c_1_2")),
                              AstConstant("c_2_2")))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_res"))

    def check_candidate(self, candidate):
        if not equal_bnot_cst(candidate["c_2_1"].mop, candidate["c_2_2"].mop):
            return False
        c_res = ((candidate["c_1_1"].value ^ candidate["c_1_2"].value) & candidate["c_2_1"].value)
        c_res ^= candidate["c_1_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1_1"].size)
        return True


class CstSimplificationRule3(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_sub,
                              AstLeaf("x_0"),
                              AstConstant("c_0")),
                      AstNode(m_mul,
                              AstConstant("c_1"),
                              AstNode(m_sub,
                                      AstLeaf("x_0"),
                                      AstConstant("c_2"))))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_mul,
                                          AstConstant("c_coeff"),
                                          AstLeaf("x_0")),
                                  AstConstant("c_sub"))

    def check_candidate(self, candidate):
        c_coeff = candidate["c_1"].value + 1
        c_sub = (candidate["c_1"].value * candidate["c_2"].value) + candidate["c_0"].value
        candidate.add_constant_leaf("c_coeff", c_coeff, candidate["c_1"].size)
        candidate.add_constant_leaf("c_sub", c_sub, candidate["c_2"].size)
        return True


class CstSimplificationRule4(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf("x_0"),
                      AstNode(m_sub,
                              AstConstant("c_1"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstLeaf("x_0"),
                                  AstNode(m_add,
                                          AstLeaf("x_1"),
                                          AstConstant("c_res")))

    def check_candidate(self, candidate):
        c_res = SUB_TABLE[candidate["c_1"].size] - candidate["c_1"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True


class CstSimplificationRule5(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstNode(m_and,
                              AstLeaf("x_1"),
                              AstConstant("c_2")))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstNode(m_xor,
                                                  AstLeaf("x_0"),
                                                  AstLeaf("x_1")),
                                          AstConstant("c_1")),
                                  AstLeaf("x_1"))

    def check_candidate(self, candidate):
        return equal_bnot_cst(candidate["c_1"].mop, candidate["c_2"].mop)


class CstSimplificationRule6(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_2")),
                                  AstConstant("c_res"))

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value & candidate["c_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_2"].size)
        return True


class CstSimplificationRule7(PatternMatchingRule):
    PATTERN = AstNode(m_shr,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_and,
                                  AstNode(m_shr,
                                          AstLeaf("x_0"),
                                          AstConstant("c_2")),
                                  AstConstant("c_res"))

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value >> candidate["c_2"].value
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True


class CstSimplificationRule8(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_res")),
                                  AstConstant("c_2"))

    def check_candidate(self, candidate):
        c_res = candidate["c_1"].value & ~candidate["c_2"].value
        if c_res == candidate["c_1"].value:
            return False
        candidate.add_constant_leaf("c_res", c_res, candidate["c_1"].size)
        return True


class CstSimplificationRule9(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_and")),
                                  AstConstant("c_xor"))

    def check_candidate(self, candidate):
        c_and = (AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value) & candidate["c_2"].value
        c_xor = candidate["c_1"].value & candidate["c_2"].value
        candidate.add_constant_leaf("c_and", c_and, candidate["x_0"].size)
        candidate.add_constant_leaf("c_xor", c_xor, candidate["x_0"].size)
        return True


class CstSimplificationRule10(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_2")))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_and")))

    def check_candidate(self, candidate):
        if (candidate["c_1"].value & candidate["c_2"].value) != candidate["c_1"].value:
            return False
        c_and = (AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value) & candidate["c_2"].value
        candidate.add_constant_leaf("c_and", c_and, candidate["x_0"].size)
        return True


class CstSimplificationRule11(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_xor,
                              AstNode(m_bnot,
                                      AstLeaf("x_0")),
                              AstConstant("c_1")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_2")))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstConstant("c_1_bnot")),
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_and")))

    def check_candidate(self, candidate):
        c_1_bnot = (AND_TABLE[candidate["c_1"].size] ^ candidate["c_1"].value)
        c_and = c_1_bnot & candidate["c_2"].value
        candidate.add_constant_leaf("c_1_bnot", c_1_bnot, candidate["c_1"].size)
        candidate.add_constant_leaf("c_and", c_and, candidate["c_1"].size)
        return True


class CstSimplificationRule12(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_sub,
                              AstConstant("c_1"),
                              AstLeaf("x_0")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_and,
                                      AstNode(m_bnot,
                                              AstLeaf("x_0")),
                                      AstConstant("c_2"))))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_xor,
                                          AstNode(m_bnot, AstLeaf("x_0")),
                                          AstConstant("c_2")),
                                  AstConstant("c_diff"))

    def check_candidate(self, candidate):
        c_diff = candidate["c_2"].value - candidate["c_1"].value
        candidate.add_constant_leaf("c_diff", c_diff, candidate["c_1"].size)
        return True


class CstSimplificationRule13(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstNode(m_and,
                              AstConstant("cst_1"),
                              AstNode(m_xor,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))),
                      AstLeaf("x_1"))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("cst_1")),
                                  AstNode(m_and, AstLeaf("x_1"),
                                          AstConstant("not_cst_1")))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("not_cst_1", ~candidate["cst_1"].value, candidate["cst_1"].size)
        return True


class CstSimplificationRule14(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_or,
                                          AstLeaf("x_0"),
                                          AstLeaf("lnot_c_1")),
                                  AstConstant("val_1"))

    def check_candidate(self, candidate):
        lnot_c_1_value = candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size]
        tmp = lnot_c_1_value ^ candidate["c_2"].value
        if tmp != 1:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate["c_2"].size)
        candidate.add_constant_leaf("lnot_c_1", lnot_c_1_value, candidate["c_1"].size)


class CstSimplificationRule15(PatternMatchingRule):
    PATTERN = AstNode(m_shr,
                      AstNode(m_shr,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_res"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("c_res", candidate["c_1"].value + candidate["c_2"].value, candidate["c_1"].size)
        return True


class CstSimplificationRule16(PatternMatchingRule):
    PATTERN = AstNode(m_bnot,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstConstant("c_1")))
    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstLeaf("x_0"),
                                  AstLeaf("bnot_c_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("bnot_c_1", candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
                                    candidate["c_1"].size)
        return True


class CstSimplificationRule17(PatternMatchingRule):
    PATTERN = AstNode(m_bnot,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstConstant("c_1")))
    REPLACEMENT_PATTERN = AstNode(m_and,
                                  AstNode(m_bnot, AstLeaf("x_0")),
                                  AstLeaf("bnot_c_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("bnot_c_1", candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
                                    candidate["c_1"].size)
        return True


class CstSimplificationRule18(PatternMatchingRule):
    PATTERN = AstNode(m_bnot,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstNode(m_bnot, AstLeaf("x_0")),
                                  AstLeaf("bnot_c_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("bnot_c_1", candidate["c_1"].value ^ AND_TABLE[candidate["c_1"].size],
                                    candidate["c_1"].size)
        return True


class CstSimplificationRule19(PatternMatchingRule):
    PATTERN = AstNode(m_sar,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("c_1")),
                      AstConstant("c_2"))
    REPLACEMENT_PATTERN = AstNode(m_and, AstNode(m_shr, AstLeaf("x_0"), AstConstant("c_2")), AstConstant("c_res"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("c_res", candidate["c_1"].value >> candidate["c_2"].value,
                                    candidate["c_1"].size)
        return True


# Found sometimes with OLLVM
class CstSimplificationRule20(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf('bnot_x_0'),
                              AstConstant('c_and_1')),
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('c_and_2')),
                              AstConstant('c_xor')))

    REPLACEMENT_PATTERN = AstNode(m_xor,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("c_and_res")),
                                  AstConstant("c_xor_res"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if candidate["c_and_1"].value & candidate["c_and_2"].value != 0:
            return False
        candidate.add_constant_leaf("c_and_res", candidate["c_and_1"].value ^ candidate["c_and_2"].value,
                                    candidate["c_and_1"].size)
        candidate.add_constant_leaf("c_xor_res", candidate["c_and_1"].value ^ candidate["c_xor"].value,
                                    candidate["c_and_1"].size)
        return True


# Found sometimes with OLLVM
class CstSimplificationRule21(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('c_and')),
                              AstConstant('c_xor_1')),
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('bnot_c_and')),
                              AstConstant('c_xor_2')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_xor_res"))

    def check_candidate(self, candidate):
        if not equal_bnot_cst(candidate["c_and"].mop, candidate["bnot_c_and"].mop):
            return False
        if candidate["c_xor_1"].mop.nnn.value & candidate["c_xor_2"].mop.nnn.value != 0:
            return False
        candidate.add_constant_leaf("c_xor_res", candidate["c_xor_1"].value ^ candidate["c_xor_2"].value,
                                    candidate["c_xor_1"].size)
        return True


# Found sometimes with OLLVM
class CstSimplificationRule22(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf('x_0'),
                                      AstConstant('c_and')),
                              AstConstant('c_xor_1')),
                      AstNode(m_xor,
                              AstNode(m_and,
                                      AstLeaf('bnot_x_0'),
                                      AstConstant('bnot_c_and')),
                              AstConstant('c_xor_2')))
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstConstant("c_xor_res"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_cst(candidate["c_and"].mop, candidate["bnot_c_and"].mop):
            return False
        if candidate["c_xor_1"].mop.nnn.value & candidate["c_xor_2"].mop.nnn.value != 0:
            return False
        if candidate["c_xor_1"].mop.nnn.value & candidate["bnot_c_and"].mop.nnn.value != 0:
            return False
        candidate.add_constant_leaf("c_xor_res", candidate["c_xor_1"].value ^ candidate["c_xor_2"].value ^ candidate["bnot_c_and"].value,
                                    candidate["c_xor_1"].size)
        return True


class CstSimplificationRule23(PatternMatchingRule):
    PATTERN = AstNode(m_or,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("mask_1")),
                      AstNode(m_and,
                              AstLeaf("x_1"),
                              AstConstant("mask_2")))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("val_result"))

    def check_candidate(self, candidate):
        mask1 = candidate["mask_1"].value
        mask2 = candidate["mask_2"].value
        if (mask1 | mask2) == mask2:
            candidate.add_constant_leaf("val_result", mask2, candidate["mask_1"].size)
            return True
        return False


class CstSimplificationRule24(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstConstant("c_or")),
                      AstConstant("mask"))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstConstant("mask")),
                                  AstConstant("c_result"))

    def check_candidate(self, candidate):
        c_result = candidate["c_or"].value & candidate["mask"].value
        if c_result == 0:
            return False
        candidate.add_constant_leaf("c_result", c_result, candidate["c_or"].size)
        return True


class CstSimplificationRule25(PatternMatchingRule):
    PATTERN = AstNode(m_xor,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstConstant("mask")),
                      AstConstant("c_xor"))
    REPLACEMENT_PATTERN = AstNode(m_and,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstConstant("c_xor")),
                                  AstConstant("mask"))

    def check_candidate(self, candidate):
        c_xor_val = candidate["c_xor"].value
        mask_val = candidate["mask"].value

        if (c_xor_val & mask_val) != c_xor_val:
            return False

        c_res = c_xor_val & mask_val
        if (c_res & mask_val) == c_res:
            return False

        is_small_mask = mask_val in [1, 3, 7, 15, 31, 63, 127, 255, 0xFFFF, 0xFFFFFFFF]
        return is_small_mask


class CstSimplificationRule26(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_sub,
                              AstConstant("c_sub"),
                              AstLeaf("x_0")),
                      AstConstant("mask"))
    REPLACEMENT_PATTERN = AstNode(m_and,
                                  AstNode(m_neg,
                                          AstLeaf("x_0")),
                                  AstConstant("mask"))

    def check_candidate(self, candidate):
        return (candidate["c_sub"].value & candidate["mask"].value) == 0


class CstSimplificationRule27(PatternMatchingRule):
    PATTERN = AstNode(m_xdu, AstConstant("c_val"))
    REPLACEMENT_PATTERN = AstNode(m_mov, AstConstant("c_extended"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("c_extended", candidate["c_val"].value, candidate.size)
        return True


class CstSimplificationRule28(PatternMatchingRule):
    PATTERN = AstNode(m_xdu,
                      AstNode(m_and,
                              AstNode(m_neg, AstLeaf("x_0")),
                              AstConstant("mask")))
    REPLACEMENT_PATTERN = None  # Создаём вручную

    def check_candidate(self, candidate):
        return True

    def get_replacement(self, candidate):
        # Создаём xdu с правильным размером результата вручную
        xdu_ins = minsn_t(candidate.ea)
        xdu_ins.opcode = m_xdu
        xdu_ins.l = candidate["x_0"].mop.copy()
        xdu_ins.d = mop_t()
        xdu_ins.d.size = candidate.size  # Размер результата xdu (8 байт)

        # Создаём mop из xdu инструкции
        xdu_mop = mop_t()
        xdu_mop.create_from_insn(xdu_ins)

        # Создаём AND с xdu и маской
        new_ins = minsn_t(candidate.ea)
        new_ins.opcode = m_and
        new_ins.l = xdu_mop

        # Создаём маску с правильным размером
        mask_mop = mop_t()
        mask_mop.make_number(candidate["mask"].value, candidate.size)
        new_ins.r = mask_mop

        new_ins.d = candidate.dst_mop
        return new_ins


class CstSimplificationRule29(PatternMatchingRule):
    PATTERN = AstNode(m_and,
                      AstNode(m_xdu, AstLeaf("x_0")),
                      AstConstant("mask"))
    REPLACEMENT_PATTERN = None  # Создаём вручную

    def check_candidate(self, candidate):
        xdu_size = candidate.size
        x_0_size = candidate["x_0"].mop.size
        mask_val = candidate["mask"].value

        # Проверяем что маска помещается в размер x_0
        if xdu_size > x_0_size:
            mask_fits = (mask_val >> (x_0_size * 8)) == 0
            return mask_fits
        return False

    def get_replacement(self, candidate):
        x_0_size = candidate["x_0"].mop.size
        mask_val = candidate["mask"].value

        # Создаём (x & mask) с размером x_0
        and_ins = minsn_t(candidate.ea)
        and_ins.opcode = m_and
        and_ins.l = candidate["x_0"].mop.copy()

        mask_mop = mop_t()
        mask_mop.make_number(mask_val, x_0_size)
        and_ins.r = mask_mop

        and_ins.d = mop_t()
        and_ins.d.size = x_0_size

        # Создаём mop из AND
        and_mop = mop_t()
        and_mop.create_from_insn(and_ins)

        # Создаём xdu с правильным размером результата
        xdu_ins = minsn_t(candidate.ea)
        xdu_ins.opcode = m_xdu
        xdu_ins.l = and_mop
        xdu_ins.d = candidate.dst_mop  # Правильный размер результата

        return xdu_ins
