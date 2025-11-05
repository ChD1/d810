import logging
from typing import List, Union
from ida_hexrays import *

from d810.hexrays_helpers import get_mop_index
from d810.hexrays_formatters import format_minsn_t, format_mop_t, opcode_to_string
from d810.ast import mop_to_ast, minsn_to_ast, AstLeaf, AstNode
from d810.errors import D810Z3Exception

logger = logging.getLogger('D810.plugin')
z3_file_logger = logging.getLogger('D810.z3_test')

try:
    import z3
    Z3_INSTALLED = True
except ImportError:
    logger.info("Z3 features disabled. Install Z3 to enable them")
    Z3_INSTALLED = False

try:
    from d810.advanced_optimizations import get_z3_cache, get_simplification_stats
    ADVANCED_OPT_AVAILABLE = True
except ImportError:
    ADVANCED_OPT_AVAILABLE = False


def create_z3_vars(leaf_list: List[AstLeaf]):
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")
    known_leaf_list = []
    known_leaf_z3_var_list = []
    for leaf in leaf_list:
        if not leaf.is_constant():
            leaf_index = get_mop_index(leaf.mop, known_leaf_list)
            if leaf_index == -1:
                known_leaf_list.append(leaf.mop)
                leaf_index = len(known_leaf_list) - 1
                if leaf.mop.size in [1, 2, 4, 8]:
                    # Normally, we should create variable based on their size
                    # but for now it can cause issue when instructions like XDU are used, hence this ugly fix
                    # known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 8 * leaf.mop.size))
                    known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
                    pass
                else:
                    known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
            leaf.z3_var = known_leaf_z3_var_list[leaf_index]
            leaf.z3_var_name = "x_{0}".format(leaf_index)
    return known_leaf_z3_var_list


def ast_to_z3_expression(ast: Union[AstNode, AstLeaf], use_bitvecval=False):
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")

    if ADVANCED_OPT_AVAILABLE:
        simp_stats = get_simplification_stats()
        simp_stats.record_call()
        original_str = str(ast)
        ast = ast.simplify()
        simplified_str = str(ast)
        if original_str != simplified_str:
            simp_stats.record_simplification("z3_expression")
            z3_file_logger.info(f"Simplified: {original_str} -> {simplified_str}")
        elif simp_stats.total_simplify_calls <= 10:
            z3_file_logger.info(f"No simplification for: {original_str}")
    else:
        ast = ast.simplify()

    if isinstance(ast, AstLeaf):
        if ast.is_constant():
            return z3.BitVecVal(ast.value, 32)
        return ast.z3_var
    if ast.opcode == m_neg:
        return -(ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_lnot:
        return not (ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_bnot:
        return ~(ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_add:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) + (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_sub:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) - (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_mul:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) * (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_udiv:
        return z3.UDiv(ast_to_z3_expression(ast.left, use_bitvecval=True),
                       ast_to_z3_expression(ast.right, use_bitvecval=True))
    elif ast.opcode == m_sdiv:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) / (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_umod:
        return z3.URem(ast_to_z3_expression(ast.left, use_bitvecval), ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_smod:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) % (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_or:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) | (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_and:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) & (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_xor:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) ^ (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_shl:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) << (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_shr:
        return z3.LShR(ast_to_z3_expression(ast.left, use_bitvecval), ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode == m_sar:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) >> (ast_to_z3_expression(ast.right, use_bitvecval))
    elif ast.opcode in [m_xdu, m_xds, m_low, m_high]:
        return ast_to_z3_expression(ast.left, use_bitvecval)
    elif ast.opcode == m_seto:
        # Overflow flag - for now, return a conservative approximation
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr == right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setae:
        # Above or equal (unsigned)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(z3.UGE(left_expr, right_expr), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_seta:
        # Above (unsigned)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(z3.UGT(left_expr, right_expr), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_sets:
        # Sign flag - check if negative
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        return z3.If(left_expr < 0, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setz:
        # Zero flag (equal)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr == right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setnz:
        # Not-zero flag (not equal)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr != right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setb:
        # Below (unsigned less)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(z3.ULT(left_expr, right_expr), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setbe:
        # Below or equal (unsigned less or equal)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(z3.ULE(left_expr, right_expr), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setl:
        # Less (signed less)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr < right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setle:
        # Less or equal (signed less or equal)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr <= right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setg:
        # Greater (signed greater)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr > right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_setge:
        # Greater or equal (signed greater or equal)
        left_expr = ast_to_z3_expression(ast.left, use_bitvecval)
        right_expr = ast_to_z3_expression(ast.right, use_bitvecval)
        return z3.If(left_expr >= right_expr, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    raise D810Z3Exception("Z3 evaluation: Unknown opcode {0} for {1}".format(opcode_to_string(ast.opcode), ast))


def mop_list_to_z3_expression_list(mop_list: List[mop_t]):
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")
    ast_list = [mop_to_ast(mop) for mop in mop_list]
    ast_leaf_list = []
    for ast in ast_list:
        ast_leaf_list += ast.get_leaf_list()
    _ = create_z3_vars(ast_leaf_list)
    return [ast_to_z3_expression(ast) for ast in ast_list]


def z3_check_mop_equality(mop1: mop_t, mop2: mop_t) -> bool:
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")

    if ADVANCED_OPT_AVAILABLE:
        cache = get_z3_cache()
        mop1_str = format_mop_t(mop1)
        mop2_str = format_mop_t(mop2)

        def compute():
            z3_mop1, z3_mop2 = mop_list_to_z3_expression_list([mop1, mop2])
            s = cache.get_solver()
            s.push()
            s.add(z3.Not(z3_mop1 == z3_mop2))
            result = s.check().r == -1
            s.pop()
            return result

        return cache.check_constraint(mop1_str, mop2_str, "equality", compute)
    else:
        z3_mop1, z3_mop2 = mop_list_to_z3_expression_list([mop1, mop2])
        s = z3.Solver()
        s.add(z3.Not(z3_mop1 == z3_mop2))
        if s.check().r == -1:
            return True
        return False


def z3_check_mop_inequality(mop1: mop_t, mop2: mop_t) -> bool:
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")

    if ADVANCED_OPT_AVAILABLE:
        cache = get_z3_cache()
        mop1_str = format_mop_t(mop1)
        mop2_str = format_mop_t(mop2)

        def compute():
            z3_mop1, z3_mop2 = mop_list_to_z3_expression_list([mop1, mop2])
            s = cache.get_solver()
            s.push()
            s.add(z3_mop1 == z3_mop2)
            result = s.check().r == -1
            s.pop()
            return result

        return cache.check_constraint(mop1_str, mop2_str, "inequality", compute)
    else:
        z3_mop1, z3_mop2 = mop_list_to_z3_expression_list([mop1, mop2])
        s = z3.Solver()
        s.add(z3_mop1 == z3_mop2)
        if s.check().r == -1:
            return True
        return False


def rename_leafs(leaf_list: List[AstLeaf]) -> List[str]:
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")
    known_leaf_list = []
    for leaf in leaf_list:
        if not leaf.is_constant() and leaf.mop.t != mop_z:
            leaf_index = get_mop_index(leaf.mop, known_leaf_list)
            if leaf_index == -1:
                known_leaf_list.append(leaf.mop)
                leaf_index = len(known_leaf_list) - 1
            leaf.z3_var_name = "x_{0}".format(leaf_index)

    return ["x_{0} = BitVec('x_{0}', {1})".format(i, 8 * leaf.size) for i, leaf in enumerate(known_leaf_list)]


def log_z3_instructions(original_ins: minsn_t, new_ins: minsn_t):
    if not Z3_INSTALLED:
        raise D810Z3Exception("Z3 is not installed")
    orig_mba_tree = minsn_to_ast(original_ins)
    new_mba_tree = minsn_to_ast(new_ins)
    if orig_mba_tree is None or new_mba_tree is None:
        return None
    orig_leaf_list = orig_mba_tree.get_leaf_list()
    new_leaf_list = new_mba_tree.get_leaf_list()

    var_def_list = rename_leafs(orig_leaf_list + new_leaf_list)

    z3_file_logger.info("print('Testing: {0} == {1}')".format(format_minsn_t(original_ins), format_minsn_t(new_ins)))
    for var_def in var_def_list:
        z3_file_logger.info("{0}".format(var_def))

    removed_xdu = "{0}".format(orig_mba_tree).replace("xdu","")
    z3_file_logger.info("original_expr = {0}".format(removed_xdu))
    removed_xdu = "{0}".format(new_mba_tree).replace("xdu","")
    z3_file_logger.info("new_expr = {0}".format(removed_xdu))
    z3_file_logger.info("prove(original_expr == new_expr)\n")
