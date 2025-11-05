from functools import lru_cache, wraps
from typing import Dict, Callable, Any
from ida_hexrays import *
from d810.utils import unsigned_to_signed, signed_to_unsigned, get_add_cf, get_add_of, get_sub_of, get_parity_flag

__all__ = ['OPCODE_DISPATCH_TABLE', 'memoize_method', 'FastAstCache', 'SignatureCache']


def memoize_method(maxsize=128):
    def decorator(func):
        cache = {}
        cache_info = {'hits': 0, 'misses': 0}

        @wraps(func)
        def wrapper(self, *args):
            key = (id(self),) + args
            if key in cache:
                cache_info['hits'] += 1
                return cache[key]
            cache_info['misses'] += 1
            result = func(self, *args)
            if len(cache) >= maxsize:
                cache.pop(next(iter(cache)))
            cache[key] = result
            return result

        wrapper.cache_info = lambda: cache_info
        wrapper.cache_clear = lambda: cache.clear()
        return wrapper
    return decorator


class FastAstCache:
    def __init__(self, maxsize=1024):
        self.cache = {}
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0

    def get_or_compute(self, mop: mop_t, compute_func: Callable) -> Any:
        if mop is None:
            return None

        key = (mop.t, mop.size)
        if mop.t == mop_n:
            key = (mop.t, mop.size, mop.nnn.value)
        elif mop.t == mop_r:
            key = (mop.t, mop.size, mop.r)
        elif mop.t == mop_d and hasattr(mop, 'd'):
            key = (mop.t, mop.size, mop.d.opcode, id(mop.d))

        if key in self.cache:
            self.hits += 1
            return self.cache[key]

        self.misses += 1
        result = compute_func(mop)

        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))

        self.cache[key] = result
        return result

    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def stats(self):
        return {'hits': self.hits, 'misses': self.misses, 'size': len(self.cache)}


class SignatureCache:
    def __init__(self, maxsize=512):
        self.cache = {}
        self.maxsize = maxsize

    @lru_cache(maxsize=512)
    def get_signature(self, pattern_id: int, depth: int) -> tuple:
        return self.cache.get((pattern_id, depth))

    def store_signature(self, pattern_id: int, depth: int, signature: list):
        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))
        self.cache[(pattern_id, depth)] = tuple(signature)

    def clear(self):
        self.cache.clear()
        self.get_signature.cache_clear()


def _eval_binop(op_func, left_val, right_val, res_mask):
    return op_func(left_val, right_val) & res_mask


def _eval_unop(op_func, val, res_mask):
    return op_func(val) & res_mask


OPCODE_DISPATCH_TABLE: Dict[int, Callable] = {
    m_mov: lambda env, ins, mask: env.eval(ins.l) & mask,
    m_neg: lambda env, ins, mask: (-env.eval(ins.l)) & mask,
    m_lnot: lambda env, ins, mask: int(env.eval(ins.l) != 0),
    m_bnot: lambda env, ins, mask: (env.eval(ins.l) ^ mask) & mask,

    m_xds: lambda env, ins, mask: signed_to_unsigned(
        unsigned_to_signed(env.eval(ins.l), ins.l.size), ins.d.size) & mask,
    m_xdu: lambda env, ins, mask: env.eval(ins.l) & mask,
    m_low: lambda env, ins, mask: env.eval(ins.l) & mask,

    m_add: lambda env, ins, mask: (env.eval(ins.l) + env.eval(ins.r)) & mask,
    m_sub: lambda env, ins, mask: (env.eval(ins.l) - env.eval(ins.r)) & mask,
    m_mul: lambda env, ins, mask: (env.eval(ins.l) * env.eval(ins.r)) & mask,
    m_udiv: lambda env, ins, mask: (env.eval(ins.l) // env.eval(ins.r)) & mask,
    m_sdiv: lambda env, ins, mask: (env.eval(ins.l) // env.eval(ins.r)) & mask,
    m_umod: lambda env, ins, mask: (env.eval(ins.l) % env.eval(ins.r)) & mask,
    m_smod: lambda env, ins, mask: (env.eval(ins.l) % env.eval(ins.r)) & mask,

    m_or: lambda env, ins, mask: (env.eval(ins.l) | env.eval(ins.r)) & mask,
    m_and: lambda env, ins, mask: (env.eval(ins.l) & env.eval(ins.r)) & mask,
    m_xor: lambda env, ins, mask: (env.eval(ins.l) ^ env.eval(ins.r)) & mask,

    m_shl: lambda env, ins, mask: (env.eval(ins.l) << env.eval(ins.r)) & mask,
    m_shr: lambda env, ins, mask: (env.eval(ins.l) >> env.eval(ins.r)) & mask,
    m_sar: lambda env, ins, mask: signed_to_unsigned(
        unsigned_to_signed(env.eval(ins.l), ins.l.size) >> env.eval(ins.r), ins.d.size) & mask,

    m_cfadd: lambda env, ins, mask: get_add_cf(env.eval(ins.l), env.eval(ins.r), ins.l.size) & mask,
    m_ofadd: lambda env, ins, mask: get_add_of(env.eval(ins.l), env.eval(ins.r), ins.l.size) & mask,

    m_sets: lambda env, ins, mask: int(unsigned_to_signed(env.eval(ins.l), ins.l.size) < 0) & mask,
    m_seto: lambda env, ins, mask: get_sub_of(
        unsigned_to_signed(env.eval(ins.l), ins.l.size),
        unsigned_to_signed(env.eval(ins.r), ins.r.size), ins.l.size) & mask,

    m_setnz: lambda env, ins, mask: int(env.eval(ins.l) != env.eval(ins.r)) & mask,
    m_setz: lambda env, ins, mask: int(env.eval(ins.l) == env.eval(ins.r)) & mask,
    m_setae: lambda env, ins, mask: int(env.eval(ins.l) >= env.eval(ins.r)) & mask,
    m_setb: lambda env, ins, mask: int(env.eval(ins.l) < env.eval(ins.r)) & mask,
    m_seta: lambda env, ins, mask: int(env.eval(ins.l) > env.eval(ins.r)) & mask,
    m_setbe: lambda env, ins, mask: int(env.eval(ins.l) <= env.eval(ins.r)) & mask,

    m_setg: lambda env, ins, mask: int(
        unsigned_to_signed(env.eval(ins.l), ins.l.size) >
        unsigned_to_signed(env.eval(ins.r), ins.r.size)) & mask,
    m_setge: lambda env, ins, mask: int(
        unsigned_to_signed(env.eval(ins.l), ins.l.size) >=
        unsigned_to_signed(env.eval(ins.r), ins.r.size)) & mask,
    m_setl: lambda env, ins, mask: int(
        unsigned_to_signed(env.eval(ins.l), ins.l.size) <
        unsigned_to_signed(env.eval(ins.r), ins.r.size)) & mask,
    m_setle: lambda env, ins, mask: int(
        unsigned_to_signed(env.eval(ins.l), ins.l.size) <=
        unsigned_to_signed(env.eval(ins.r), ins.r.size)) & mask,

    m_setp: lambda env, ins, mask: get_parity_flag(
        env.eval(ins.l), env.eval(ins.r), ins.l.size) & mask,
}


def _compute_signed_comparison(vals, sizes, op, mask):
    left_signed = unsigned_to_signed(vals[0], sizes[0])
    right_signed = unsigned_to_signed(vals[1], sizes[1])
    return int(op(left_signed, right_signed)) & mask


AST_OPCODE_EVALUATORS = {
    m_mov: lambda vals, mask, sizes=None: vals[0] & mask,
    m_neg: lambda vals, mask, sizes=None: (-vals[0]) & mask,
    m_lnot: lambda vals, mask, sizes=None: int(vals[0] != 0),
    m_bnot: lambda vals, mask, sizes=None: (vals[0] ^ mask) & mask,

    m_xdu: lambda vals, mask, sizes=None: vals[0] & mask,
    m_low: lambda vals, mask, sizes=None: vals[0] & mask,

    m_add: lambda vals, mask, sizes=None: (vals[0] + vals[1]) & mask,
    m_sub: lambda vals, mask, sizes=None: (vals[0] - vals[1]) & mask,
    m_mul: lambda vals, mask, sizes=None: (vals[0] * vals[1]) & mask,
    m_udiv: lambda vals, mask, sizes=None: (vals[0] // vals[1]) & mask if vals[1] != 0 else 0,
    m_sdiv: lambda vals, mask, sizes=None: (vals[0] // vals[1]) & mask if vals[1] != 0 else 0,
    m_umod: lambda vals, mask, sizes=None: (vals[0] % vals[1]) & mask if vals[1] != 0 else 0,
    m_smod: lambda vals, mask, sizes=None: (vals[0] % vals[1]) & mask if vals[1] != 0 else 0,

    m_or: lambda vals, mask, sizes=None: (vals[0] | vals[1]) & mask,
    m_and: lambda vals, mask, sizes=None: (vals[0] & vals[1]) & mask,
    m_xor: lambda vals, mask, sizes=None: (vals[0] ^ vals[1]) & mask,

    m_shl: lambda vals, mask, sizes=None: (vals[0] << vals[1]) & mask,
    m_shr: lambda vals, mask, sizes=None: (vals[0] >> vals[1]) & mask,

    m_setnz: lambda vals, mask, sizes=None: int(vals[0] != vals[1]) & mask,
    m_setz: lambda vals, mask, sizes=None: int(vals[0] == vals[1]) & mask,
    m_setae: lambda vals, mask, sizes=None: int(vals[0] >= vals[1]) & mask,
    m_setb: lambda vals, mask, sizes=None: int(vals[0] < vals[1]) & mask,
    m_seta: lambda vals, mask, sizes=None: int(vals[0] > vals[1]) & mask,
    m_setbe: lambda vals, mask, sizes=None: int(vals[0] <= vals[1]) & mask,

    m_setg: lambda vals, mask, sizes: _compute_signed_comparison(vals, sizes, lambda l, r: l > r, mask),
    m_setge: lambda vals, mask, sizes: _compute_signed_comparison(vals, sizes, lambda l, r: l >= r, mask),
    m_setl: lambda vals, mask, sizes: _compute_signed_comparison(vals, sizes, lambda l, r: l < r, mask),
    m_setle: lambda vals, mask, sizes: _compute_signed_comparison(vals, sizes, lambda l, r: l <= r, mask),
}
