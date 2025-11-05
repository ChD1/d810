from __future__ import annotations
import logging
from typing import List, Union, Dict, Tuple
from functools import lru_cache

from ida_hexrays import *

from d810.utils import unsigned_to_signed, signed_to_unsigned, \
    get_add_cf, get_add_of, get_sub_of, get_parity_flag
from d810.hexrays_helpers import OPCODES_INFO, MBA_RELATED_OPCODES, Z3_SPECIAL_OPERANDS, MINSN_TO_AST_FORBIDDEN_OPCODES, \
    equal_mops_ignore_size, AND_TABLE
from d810.hexrays_formatters import format_minsn_t, format_mop_t
from d810.errors import AstEvaluationException

try:
    from d810.optimizations import AST_OPCODE_EVALUATORS, FastAstCache
    OPTIMIZATIONS_AVAILABLE = True
except ImportError:
    OPTIMIZATIONS_AVAILABLE = False

logger = logging.getLogger('D810')

_ast_cache = FastAstCache() if OPTIMIZATIONS_AVAILABLE else None


def _get_mop_key(mop: mop_t):
    if mop is None:
        return None
    if mop.t == mop_n:
        return (mop.t, mop.size, mop.nnn.value)
    elif mop.t == mop_r:
        return (mop.t, mop.size, mop.r)
    elif mop.t == mop_S:
        return (mop.t, mop.size, mop.s.off)
    return (mop.t, mop.size, id(mop))


def check_and_add_to_list(new_ast: Union[AstNode, AstLeaf], known_ast_list: List[Union[AstNode, AstLeaf]],
                          known_ast_dict: Dict = None):
    if known_ast_dict is None:
        for existing_elt in known_ast_list:
            if equal_mops_ignore_size(new_ast.mop, existing_elt.mop):
                new_ast.ast_index = existing_elt.ast_index
                return
        ast_index = len(known_ast_list)
        new_ast.ast_index = ast_index
        known_ast_list.append(new_ast)
    else:
        mop_key = _get_mop_key(new_ast.mop)
        if mop_key in known_ast_dict:
            existing_elt = known_ast_dict[mop_key]
            new_ast.ast_index = existing_elt.ast_index
        else:
            ast_index = len(known_ast_list)
            new_ast.ast_index = ast_index
            known_ast_list.append(new_ast)
            known_ast_dict[mop_key] = new_ast


def mop_to_ast_internal(mop: mop_t, ast_list: List[Union[AstNode, AstLeaf]],
                        ast_dict: Dict = None) -> Union[None, AstNode, AstLeaf]:
    if mop is None:
        return None

    if mop.t != mop_d or (mop.d.opcode not in MBA_RELATED_OPCODES):
        tree = AstLeaf(format_mop_t(mop))
        tree.mop = mop
        dest_size = mop.size if mop.t != mop_d else mop.d.d.size
        tree.dest_size = dest_size
    else:
        left_ast = mop_to_ast_internal(mop.d.l, ast_list, ast_dict)
        right_ast = mop_to_ast_internal(mop.d.r, ast_list, ast_dict)
        dst_ast = mop_to_ast_internal(mop.d.d, ast_list, ast_dict)
        tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)
        tree.mop = mop
        tree.dest_size = mop.d.d.size
        tree.ea = mop.d.ea

    check_and_add_to_list(tree, ast_list, ast_dict)
    return tree


def mop_to_ast(mop: mop_t) -> Union[None, AstNode, AstLeaf]:
    ast_list = []
    ast_dict = {}
    mop_ast = mop_to_ast_internal(mop, ast_list, ast_dict)
    if mop_ast is not None:
        mop_ast.compute_sub_ast()
    return mop_ast


def minsn_to_ast(instruction: minsn_t) -> Union[None, AstNode, AstLeaf]:
    try:
        if instruction.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
            # To avoid error 50278
            return None

        ins_mop = mop_t()
        ins_mop.create_from_insn(instruction)

        if instruction.opcode == m_mov:
            tmp = AstNode(m_mov, mop_to_ast(ins_mop))
            tmp.mop = ins_mop
            tmp.dest_size = instruction.d.size
            tmp.ea = instruction.ea
            tmp.dst_mop = instruction.d
            return tmp

        tmp = mop_to_ast(ins_mop)
        tmp.dst_mop = instruction.d
        return tmp
    except RuntimeError as e:
        logger.error("Error while transforming instruction {0}: {1}".format(format_minsn_t(instruction), e))
        return None


class AstInfo(object):
    def __init__(self, ast: Union[AstNode, AstLeaf], number_of_use: int):
        self.ast = ast
        self.number_of_use = number_of_use

    def __str__(self):
        return "{0} used {1} times: {2}".format(self.ast, self.number_of_use, format_mop_t(self.ast.mop))


class AstNode(dict):
    def __init__(self, opcode, left=None, right=None, dst=None):
        super(dict, self).__init__()
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dst = dst
        self.dst_mop = None

        self.opcodes = []
        self.mop = None
        self.is_candidate_ok = False

        self.leafs = []
        self.leafs_by_name = {}

        self.ast_index = 0
        self.sub_ast_info_by_index = {}

        self.dest_size = None
        self.ea = None

    @property
    def size(self):
        return self.mop.d.d.size

    def compute_sub_ast(self):
        self.sub_ast_info_by_index = {}
        self.sub_ast_info_by_index[self.ast_index] = AstInfo(self, 1)

        if self.left is not None:
            self.left.compute_sub_ast()
            for ast_index, ast_info in self.left.sub_ast_info_by_index.items():
                if ast_index not in self.sub_ast_info_by_index.keys():
                    self.sub_ast_info_by_index[ast_index] = AstInfo(ast_info.ast, 0)
                self.sub_ast_info_by_index[ast_index].number_of_use += ast_info.number_of_use

        if self.right is not None:
            self.right.compute_sub_ast()
            for ast_index, ast_info in self.right.sub_ast_info_by_index.items():
                if ast_index not in self.sub_ast_info_by_index.keys():
                    self.sub_ast_info_by_index[ast_index] = AstInfo(ast_info.ast, 0)
                self.sub_ast_info_by_index[ast_index].number_of_use += ast_info.number_of_use

    def get_information(self):
        leaf_info_list = []
        cst_list = []
        opcode_list = []
        self.compute_sub_ast()

        for _, ast_info in self.sub_ast_info_by_index.items():
            if (ast_info.ast.mop is not None) and (ast_info.ast.mop.t != mop_z):
                if ast_info.ast.is_leaf():
                    if ast_info.ast.is_constant():
                        cst_list.append(ast_info.ast.mop.nnn.value)
                    else:
                        leaf_info_list.append(ast_info)
                else:
                    opcode_list += [ast_info.ast.opcode] * ast_info.number_of_use

        return leaf_info_list, cst_list, opcode_list

    def __getitem__(self, k) -> AstLeaf:
        return self.leafs_by_name[k]

    def get_leaf_list(self) -> List[AstLeaf]:
        leafs = []
        if self.left is not None:
            leafs += self.left.get_leaf_list()
        if self.right is not None:
            leafs += self.right.get_leaf_list()
        return leafs

    def is_leaf(self) -> bool:
        # An AstNode is not a leaf, so returns False
        return False

    def add_leaf(self, leaf_name: str, leaf_mop: mop_t):
        leaf = AstLeaf(leaf_name)
        leaf.mop = leaf_mop
        self.leafs.append(leaf)
        self.leafs_by_name[leaf_name] = leaf

    def add_constant_leaf(self, leaf_name: str, cst_value: int, cst_size: int):
        cst_mop = mop_t()
        cst_mop.make_number(cst_value & AND_TABLE[cst_size], cst_size)
        self.add_leaf(leaf_name, cst_mop)

    def check_pattern_and_copy_mops(self, ast: Union[AstNode, AstLeaf]) -> bool:
        self.reset_mops()
        is_matching_shape = self._copy_mops_from_ast(ast)
        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.mop = None
        if self.left is not None:
            self.left.reset_mops()
        if self.right is not None:
            self.right.reset_mops()

    def _copy_mops_from_ast(self, other: Union[AstNode, AstLeaf]) -> bool:
        self.mop = other.mop
        self.dst_mop = other.dst_mop
        self.dest_size = other.dest_size
        self.ea = other.ea

        if not isinstance(other, AstNode):
            return False
        if self.opcode != other.opcode:
            return False
        if self.left is not None:
            if not self.left._copy_mops_from_ast(other.left):
                return False
        if self.right is not None:
            if not self.right._copy_mops_from_ast(other.right):
                return False
        return True

    def _check_implicit_equalities(self) -> bool:
        self.leafs = self.get_leaf_list()
        self.leafs_by_name = {}
        self.is_candidate_ok = True

        for leaf in self.leafs:
            ref_leaf = self.leafs_by_name.get(leaf.name)
            if ref_leaf is not None:
                if not equal_mops_ignore_size(ref_leaf.mop, leaf.mop):
                    self.is_candidate_ok = False
            self.leafs_by_name[leaf.name] = leaf
        return self.is_candidate_ok

    def update_leafs_mop(self, other: Union[AstNode, AstLeaf], other2: Union[None, AstNode, AstLeaf] = None) -> bool:
        self.leafs = self.get_leaf_list()
        all_leafs_found = True
        for leaf in self.leafs:
            if leaf.name in other.leafs_by_name.keys():
                leaf.mop = other.leafs_by_name[leaf.name].mop
            elif (other2 is not None) and (leaf.name in other2.leafs_by_name.keys()):
                leaf.mop = other2.leafs_by_name[leaf.name].mop
            else:
                all_leafs_found = False
        return all_leafs_found

    def create_mop(self, ea: int) -> mop_t:
        new_ins = self.create_minsn(ea)
        new_ins_mop = mop_t()
        new_ins_mop.create_from_insn(new_ins)
        return new_ins_mop

    def create_minsn(self, ea: int, dest=None) -> minsn_t:
        new_ins = minsn_t(ea)
        new_ins.opcode = self.opcode

        if self.left is not None:
            new_ins.l = self.left.create_mop(ea)
            if self.right is not None:
                new_ins.r = self.right.create_mop(ea)

        new_ins.d = mop_t()

        if self.left is not None:
            new_ins.d.size = new_ins.l.size
        if dest is not None:
            new_ins.d = dest
        return new_ins

    def get_pattern(self) -> str:
        nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
        if nb_operands == 0:
            return "AstNode({0})".format(OPCODES_INFO[self.opcode]["name"])
        elif nb_operands == 1:
            return "AstNode(m_{0}, {1})".format(OPCODES_INFO[self.opcode]["name"], self.left.get_pattern())
        elif nb_operands == 2:
            return "AstNode(m_{0}, {1}, {2})" \
                .format(OPCODES_INFO[self.opcode]["name"], self.left.get_pattern(), self.right.get_pattern())

    def evaluate_with_leaf_info(self, leafs_info, leafs_value):
        dict_index_to_value = {leaf_info.ast.ast_index: leaf_value for leaf_info, leaf_value in
                               zip(leafs_info, leafs_value)}
        res = self.evaluate(dict_index_to_value)
        return res

    def evaluate(self, dict_index_to_value):
        if self.ast_index in dict_index_to_value:
            return dict_index_to_value[self.ast_index]

        res_mask = AND_TABLE[self.dest_size]

        if OPTIMIZATIONS_AVAILABLE and self.opcode in AST_OPCODE_EVALUATORS:
            left_val = self.left.evaluate(dict_index_to_value) if self.left else 0
            right_val = self.right.evaluate(dict_index_to_value) if self.right else 0
            left_size = self.left.dest_size if self.left else self.dest_size
            right_size = self.right.dest_size if self.right else self.dest_size
            return AST_OPCODE_EVALUATORS[self.opcode]([left_val, right_val], res_mask, [left_size, right_size])

        if self.opcode == m_mov:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_neg:
            return (- self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_lnot:
            return self.left.evaluate(dict_index_to_value) != 0
        elif self.opcode == m_bnot:
            return (self.left.evaluate(dict_index_to_value) ^ res_mask) & res_mask
        elif self.opcode == m_xds:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            return signed_to_unsigned(left_value_signed, self.dest_size) & res_mask
        elif self.opcode == m_xdu:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_low:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_add:
            return (self.left.evaluate(dict_index_to_value) + self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_sub:
            return (self.left.evaluate(dict_index_to_value) - self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_mul:
            return (self.left.evaluate(dict_index_to_value) * self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_udiv:
            return (self.left.evaluate(dict_index_to_value) // self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_sdiv:
            return (self.left.evaluate(dict_index_to_value) // self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_umod:
            return (self.left.evaluate(dict_index_to_value) % self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_smod:
            return (self.left.evaluate(dict_index_to_value) % self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_or:
            return (self.left.evaluate(dict_index_to_value) | self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_and:
            return (self.left.evaluate(dict_index_to_value) & self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_xor:
            return (self.left.evaluate(dict_index_to_value) ^ self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_shl:
            return (self.left.evaluate(dict_index_to_value) << self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_shr:
            return (self.left.evaluate(dict_index_to_value) >> self.right.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == m_sar:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            res_signed = left_value_signed >> self.right.evaluate(dict_index_to_value)
            return signed_to_unsigned(res_signed, self.dest_size) & res_mask
        elif self.opcode == m_cfadd:
            tmp = get_add_cf(self.left.evaluate(dict_index_to_value), self.right.evaluate(dict_index_to_value),
                             self.left.dest_size)
            return tmp & res_mask
        elif self.opcode == m_ofadd:
            tmp = get_add_of(self.left.evaluate(dict_index_to_value), self.right.evaluate(dict_index_to_value),
                             self.left.dest_size)
            return tmp & res_mask
        elif self.opcode == m_sets:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            res = 1 if left_value_signed < 0 else 0
            return res & res_mask
        elif self.opcode == m_seto:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            right_value_signed = unsigned_to_signed(self.right.evaluate(dict_index_to_value), self.right.dest_size)
            sub_overflow = get_sub_of(left_value_signed, right_value_signed, self.left.dest_size)
            return sub_overflow & res_mask
        elif self.opcode == m_setnz:
            res = 1 if self.left.evaluate(dict_index_to_value) != self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_setz:
            res = 1 if self.left.evaluate(dict_index_to_value) == self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_setae:
            res = 1 if self.left.evaluate(dict_index_to_value) >= self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_setb:
            res = 1 if self.left.evaluate(dict_index_to_value) < self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_seta:
            res = 1 if self.left.evaluate(dict_index_to_value) > self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_setbe:
            res = 1 if self.left.evaluate(dict_index_to_value) <= self.right.evaluate(dict_index_to_value) else 0
            return res & res_mask
        elif self.opcode == m_setg:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            right_value_signed = unsigned_to_signed(self.right.evaluate(dict_index_to_value), self.right.dest_size)
            res = 1 if left_value_signed > right_value_signed else 0
            return res & res_mask
        elif self.opcode == m_setge:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            right_value_signed = unsigned_to_signed(self.right.evaluate(dict_index_to_value), self.right.dest_size)
            res = 1 if left_value_signed >= right_value_signed else 0
            return res & res_mask
        elif self.opcode == m_setl:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            right_value_signed = unsigned_to_signed(self.right.evaluate(dict_index_to_value), self.right.dest_size)
            res = 1 if left_value_signed < right_value_signed else 0
            return res & res_mask
        elif self.opcode == m_setle:
            left_value_signed = unsigned_to_signed(self.left.evaluate(dict_index_to_value), self.left.dest_size)
            right_value_signed = unsigned_to_signed(self.right.evaluate(dict_index_to_value), self.right.dest_size)
            res = 1 if left_value_signed <= right_value_signed else 0
            return res & res_mask
        elif self.opcode == m_setp:
            res = get_parity_flag(self.left.evaluate(dict_index_to_value), self.right.evaluate(dict_index_to_value),
                                  self.left.dest_size)
            return res & res_mask
        else:
            raise AstEvaluationException("Can't evaluate opcode: {0}".format(self.opcode))

    def simplify(self):
        if self.left is not None:
            self.left = self.left.simplify()
        if self.right is not None:
            self.right = self.right.simplify()

        left_is_const = isinstance(self.left, AstLeaf) and self.left.is_constant() if self.left else False
        right_is_const = isinstance(self.right, AstLeaf) and self.right.is_constant() if self.right else False
        left_val = self.left.value if left_is_const else None
        right_val = self.right.value if right_is_const else None

        if left_is_const and right_is_const:
            try:
                result_val = self.evaluate({})
                result_leaf = AstLeaf("const")
                result_mop = mop_t()
                result_mop.make_number(result_val, self.dest_size)
                result_leaf.mop = result_mop
                result_leaf.dest_size = self.dest_size
                result_leaf.ea = self.ea
                return result_leaf
            except:
                pass

        if self.opcode == m_add:
            if right_is_const and right_val == 0:
                return self.left
            if left_is_const and left_val == 0:
                return self.right
            if left_is_const and right_is_const:
                return self._create_const_leaf((left_val + right_val) & AND_TABLE[self.dest_size])
            if isinstance(self.left, AstNode) and self.left.opcode == m_add:
                if isinstance(self.left.right, AstLeaf) and self.left.right.is_constant() and right_is_const:
                    c1 = self.left.right.value
                    c2 = right_val
                    combined = (c1 + c2) & AND_TABLE[self.dest_size]
                    return AstNode(m_add, self.left.left, self._create_const_leaf(combined))

        elif self.opcode == m_sub:
            if right_is_const and right_val == 0:
                return self.left
            if self.left == self.right:
                return self._create_const_leaf(0)

        elif self.opcode == m_mul:
            if right_is_const:
                if right_val == 0:
                    return self._create_const_leaf(0)
                if right_val == 1:
                    return self.left
            if left_is_const:
                if left_val == 0:
                    return self._create_const_leaf(0)
                if left_val == 1:
                    return self.right
            if isinstance(self.left, AstNode) and self.left.opcode == m_mul:
                if isinstance(self.left.right, AstLeaf) and self.left.right.is_constant() and right_is_const:
                    c1 = self.left.right.value
                    c2 = right_val
                    combined = (c1 * c2) & AND_TABLE[self.dest_size]
                    return AstNode(m_mul, self.left.left, self._create_const_leaf(combined))

        elif self.opcode in [m_udiv, m_sdiv]:
            if right_is_const and right_val == 1:
                return self.left
            if left_is_const and left_val == 0:
                return self._create_const_leaf(0)

        elif self.opcode == m_or:
            if right_is_const and right_val == 0:
                return self.left
            if left_is_const and left_val == 0:
                return self.right
            if right_is_const and right_val == AND_TABLE[self.dest_size]:
                return self._create_const_leaf(AND_TABLE[self.dest_size])
            if self.left == self.right:
                return self.left

        elif self.opcode == m_and:
            if right_is_const and right_val == 0:
                return self._create_const_leaf(0)
            if left_is_const and left_val == 0:
                return self._create_const_leaf(0)
            if right_is_const and right_val == AND_TABLE[self.dest_size]:
                return self.left
            if self.left == self.right:
                return self.left

        elif self.opcode == m_xor:
            if right_is_const and right_val == 0:
                return self.left
            if left_is_const and left_val == 0:
                return self.right
            if self.left == self.right:
                return self._create_const_leaf(0)

        elif self.opcode == m_bnot:
            if isinstance(self.left, AstNode) and self.left.opcode == m_bnot:
                return self.left.left

        elif self.opcode == m_neg:
            if isinstance(self.left, AstNode) and self.left.opcode == m_neg:
                return self.left.left

        elif self.opcode in [m_shl, m_shr, m_sar]:
            if right_is_const and right_val == 0:
                return self.left

        return self

    def _create_const_leaf(self, value):
        result_leaf = AstLeaf("const")
        result_mop = mop_t()
        result_mop.make_number(value & AND_TABLE[self.dest_size], self.dest_size)
        result_leaf.mop = result_mop
        result_leaf.dest_size = self.dest_size
        result_leaf.ea = self.ea
        return result_leaf

    def get_depth_signature(self, depth):
        if depth == 1:
            return ["{0}".format(self.opcode)]
        tmp = []
        nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
        if (nb_operands >= 1) and self.left is not None:
            tmp += self.left.get_depth_signature(depth - 1)
        else:
            tmp += ["N"] * (2 ** (depth - 2))
        if (nb_operands >= 2) and self.right is not None:
            tmp += self.right.get_depth_signature(depth - 1)
        else:
            tmp += ["N"] * (2 ** (depth - 2))
        return tmp

    def __str__(self):
        try:
            nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
            if "symbol" in OPCODES_INFO[self.opcode].keys():
                if nb_operands == 0:
                    return "{0}()".format(OPCODES_INFO[self.opcode]["symbol"])
                elif nb_operands == 1:
                    return "{0}({1})".format(OPCODES_INFO[self.opcode]["symbol"], self.left)
                elif nb_operands == 2:
                    if OPCODES_INFO[self.opcode]["symbol"] not in Z3_SPECIAL_OPERANDS:
                        return "({1} {0} {2})".format(OPCODES_INFO[self.opcode]["symbol"], self.left, self.right)
                    else:
                        return "{0}({1}, {2})".format(OPCODES_INFO[self.opcode]["symbol"], self.left, self.right)
            else:
                if nb_operands == 0:
                    return "{0}()".format(OPCODES_INFO[self.opcode]["name"])
                elif nb_operands == 1:
                    return "{0}({1})".format(OPCODES_INFO[self.opcode]["name"], self.left)
                elif nb_operands == 2:
                    return "{0}({1}, {2})".format(OPCODES_INFO[self.opcode]["name"], self.left, self.right)
            return "Error_AstNode"
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstNode: {0}".format(e))
            return "Error_AstNode"


class AstLeaf(object):
    def __init__(self, name):
        self.name = name
        self.ast_index = None

        self.mop = None
        self.z3_var = None
        self.z3_var_name = None

        self.dest_size = None
        self.ea = None

        self.sub_ast_info_by_index = {}

    def __getitem__(self, name):
        if name == self.name:
            return self
        raise KeyError

    @property
    def size(self):
        return self.mop.size

    @property
    def dst_mop(self):
        return self.mop

    @dst_mop.setter
    def dst_mop(self, mop):
        self.mop = mop

    @property
    def value(self):
        if self.is_constant():
            return self.mop.nnn.value
        else:
            return None

    def compute_sub_ast(self):
        self.sub_ast_info_by_index = {}
        self.sub_ast_info_by_index[self.ast_index] = AstInfo(self, 1)

    def get_information(self):
        # Just here to allow calling get_information on either a AstNode or AstLeaf
        return [], [], []

    def get_leaf_list(self):
        return [self]

    def is_leaf(self):
        return True

    def is_constant(self):
        if self.mop is None:
            return False
        return self.mop.t == mop_n

    def create_mop(self, ea):
        # Currently, we are not creating a new mop but returning the one defined
        return self.mop

    def update_leafs_mop(self, other, other2=None):
        if self.name in other.leafs_by_name.keys():
            self.mop = other.leafs_by_name[self.name].mop
            return True
        elif (other2 is not None) and (self.name in other2.leafs_by_name.keys()):
            self.mop = other2.leafs_by_name[self.name].mop
            return True
        return False

    def check_pattern_and_copy_mops(self, ast):
        self.reset_mops()
        is_matching_shape = self._copy_mops_from_ast(ast)

        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.z3_var = None
        self.z3_var_name = None
        self.mop = None

    def _copy_mops_from_ast(self, other):
        self.mop = other.mop
        return True

    @staticmethod
    def _check_implicit_equalities():
        # An AstLeaf does not have any implicit equalities to be checked, so we always returns True
        return True

    def get_pattern(self):
        if self.is_constant():
            return "AstConstant('{0}', {0})".format(self.mop.nnn.value)
        if self.ast_index is not None:
            return "AstLeaf('x_{0}')".format(self.ast_index)
        if self.name is not None:
            return "AstLeaf('{0}')".format(self.name)

    def evaluate_with_leaf_info(self, leafs_info, leafs_value):
        dict_index_to_value = {leaf_info.ast.ast_index: leaf_value for leaf_info, leaf_value in
                               zip(leafs_info, leafs_value)}
        res = self.evaluate(dict_index_to_value)
        return res

    def evaluate(self, dict_index_to_value):
        if self.is_constant():
            return self.mop.nnn.value
        return dict_index_to_value.get(self.ast_index)

    def simplify(self):
        return self

    def get_depth_signature(self, depth):
        if depth == 1:
            if self.is_constant():
                return ["C"]
            return ["L"]
        else:
            return ["N"] * (2 ** (depth - 1))

    def __str__(self):
        try:
            if self.is_constant():
                return "{0}".format(self.mop.nnn.value)
            if self.z3_var_name is not None:
                return self.z3_var_name
            if self.ast_index is not None:
                return "x_{0}".format(self.ast_index)
            if self.mop is not None:
                return format_mop_t(self.mop)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstLeaf: {0}".format(e))
            return "Error_AstLeaf"


class AstConstant(AstLeaf):
    def __init__(self, name, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
        return self.mop.nnn.value

    def is_constant(self):
        # An AstConstant is always constant, so return True
        return True

    def _copy_mops_from_ast(self, other):
        if other.mop is not None and other.mop.t != mop_n:
            return False

        self.mop = other.mop
        if self.expected_value is None:
            return True
        return self.expected_value == other.mop.nnn.value

    def evaluate(self, dict_index_to_value=None):
        if self.mop is not None and self.mop.t == mop_n:
            return self.mop.nnn.value
        return self.expected_value

    def get_depth_signature(self, depth):
        if depth == 1:
            return ["C"]
        else:
            return ["N"] * (2 ** (depth - 1))

    def __str__(self):
        try:
            if self.mop is not None and self.mop.t == mop_n:
                return "0x{0:x}".format(self.mop.nnn.value)
            if self.expected_value is not None:
                return "0x{0:x}".format(self.expected_value)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstConstant: {0}".format(e))
            return "Error_AstConstant"
