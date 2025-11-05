from functools import wraps
from typing import Dict, Tuple, Optional
import hashlib
import logging

logger = logging.getLogger('D810.advanced')

try:
    import z3
    Z3_INSTALLED = True
except ImportError:
    Z3_INSTALLED = False


class Z3ConstraintCache:
    def __init__(self, maxsize=512):
        self.cache = {}
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0
        self.solver_reuse_count = 0
        self._solver = None

    def _get_cache_key(self, expr1_str: str, expr2_str: str, check_type: str) -> str:
        combined = f"{check_type}:{expr1_str}:{expr2_str}"
        return hashlib.md5(combined.encode()).hexdigest()

    def get_solver(self):
        if self._solver is None and Z3_INSTALLED:
            self._solver = z3.Solver()
        else:
            self.solver_reuse_count += 1
        return self._solver

    def reset_solver(self):
        if self._solver is not None:
            self._solver.reset()

    def check_constraint(self, expr1_str: str, expr2_str: str, check_type: str,
                        compute_func) -> bool:
        cache_key = self._get_cache_key(expr1_str, expr2_str, check_type)

        if cache_key in self.cache:
            self.hits += 1
            return self.cache[cache_key]

        self.misses += 1
        result = compute_func()

        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))

        self.cache[cache_key] = result
        return result

    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        self.solver_reuse_count = 0
        self._solver = None

    def stats(self):
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'cache_size': len(self.cache),
            'solver_reuses': self.solver_reuse_count
        }


class CFGCache:
    def __init__(self, maxsize=256):
        self.cache = {}
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0
        self._current_cfg_hash = None

    def _get_cfg_hash(self, mba) -> str:
        cfg_signature = []
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk:
                succs = tuple(sorted([s for s in blk.succset]))
                preds = tuple(sorted([p for p in blk.predset]))
                cfg_signature.append((blk_idx, succs, preds))
        return hashlib.md5(str(cfg_signature).encode()).hexdigest()

    def invalidate_on_cfg_change(self, mba):
        new_hash = self._get_cfg_hash(mba)
        if self._current_cfg_hash != new_hash:
            logger.debug(f"CFG changed, invalidating cache (old: {self._current_cfg_hash}, new: {new_hash})")
            self.cache.clear()
            self._current_cfg_hash = new_hash
            return True
        return False

    def _get_search_key(self, blk_serial: int, mop_list_str: str, direction: str) -> str:
        return f"{direction}:{blk_serial}:{mop_list_str}"

    def get_search_result(self, blk_serial: int, mop_list_str: str, direction: str):
        cache_key = self._get_search_key(blk_serial, mop_list_str, direction)

        if cache_key in self.cache:
            self.hits += 1
            return True, self.cache[cache_key]

        self.misses += 1
        return False, None

    def store_search_result(self, blk_serial: int, mop_list_str: str, direction: str, result):
        cache_key = self._get_search_key(blk_serial, mop_list_str, direction)

        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))

        self.cache[cache_key] = result

    def _get_predset_key(self, blk_serial: int) -> str:
        return f"predset:{blk_serial}"

    def get_predset(self, blk_serial: int):
        cache_key = self._get_predset_key(blk_serial)
        if cache_key in self.cache:
            self.hits += 1
            return True, self.cache[cache_key]
        self.misses += 1
        return False, None

    def store_predset(self, blk_serial: int, predset):
        cache_key = self._get_predset_key(blk_serial)
        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))
        self.cache[cache_key] = predset

    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        self._current_cfg_hash = None

    def stats(self):
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'cache_size': len(self.cache)
        }


class PatternMatchCache:
    def __init__(self, maxsize=1024):
        self.cache = {}
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0

    def _get_pattern_key(self, pattern_id: int, ast_str: str) -> str:
        return f"{pattern_id}:{ast_str}"

    def check_pattern(self, pattern_id: int, ast_str: str, check_func) -> Tuple[bool, Optional[dict]]:
        cache_key = self._get_pattern_key(pattern_id, ast_str)

        if cache_key in self.cache:
            self.hits += 1
            return self.cache[cache_key]

        self.misses += 1
        result = check_func()

        if len(self.cache) >= self.maxsize:
            self.cache.pop(next(iter(self.cache)))

        self.cache[cache_key] = result
        return result

    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def stats(self):
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'cache_size': len(self.cache)
        }


class BatchProcessor:
    def __init__(self, batch_size=10):
        self.batch_size = batch_size
        self.pending = []
        self.processed_count = 0

    def add(self, item):
        self.pending.append(item)
        if len(self.pending) >= self.batch_size:
            return True
        return False

    def get_batch(self):
        batch = self.pending[:self.batch_size]
        self.pending = self.pending[self.batch_size:]
        self.processed_count += len(batch)
        return batch

    def flush(self):
        batch = self.pending
        self.pending = []
        self.processed_count += len(batch)
        return batch

    def stats(self):
        return {
            'processed': self.processed_count,
            'pending': len(self.pending)
        }


class EarlyTerminationManager:
    def __init__(self):
        self.termination_checks = 0
        self.early_exits = 0
        self.continue_count = 0

    def should_continue(self, condition: bool, reason: str = "") -> bool:
        self.termination_checks += 1
        if not condition:
            self.early_exits += 1
            if reason:
                logger.debug(f"Early termination: {reason}")
            return False
        self.continue_count += 1
        return True

    def stats(self):
        return {
            'checks': self.termination_checks,
            'early_exits': self.early_exits,
            'continues': self.continue_count,
            'exit_rate': f"{(self.early_exits/self.termination_checks*100) if self.termination_checks > 0 else 0:.1f}%"
        }


class SimplificationStats:
    def __init__(self):
        self.total_simplify_calls = 0
        self.successful_simplifications = 0
        self.simplification_types = {}

    def record_call(self):
        self.total_simplify_calls += 1

    def record_simplification(self, simplification_type: str):
        self.successful_simplifications += 1
        self.simplification_types[simplification_type] = self.simplification_types.get(simplification_type, 0) + 1

    def clear(self):
        self.total_simplify_calls = 0
        self.successful_simplifications = 0
        self.simplification_types.clear()

    def stats(self):
        total = self.total_simplify_calls
        simplified = self.successful_simplifications
        rate = (simplified / total * 100) if total > 0 else 0
        return {
            'total_calls': total,
            'simplifications': simplified,
            'simplification_rate': f"{rate:.1f}%",
            'types': dict(self.simplification_types)
        }


class ParallelPatternStats:
    def __init__(self):
        self.total_checks = 0
        self.parallel_checks = 0
        self.patterns_checked = 0
        self.patterns_saved = 0

    def record_check(self, num_patterns: int, used_parallel: bool):
        self.total_checks += 1
        self.patterns_checked += num_patterns
        if used_parallel:
            self.parallel_checks += 1
            self.patterns_saved += max(0, num_patterns - 1)

    def clear(self):
        self.total_checks = 0
        self.parallel_checks = 0
        self.patterns_checked = 0
        self.patterns_saved = 0

    def stats(self):
        parallel_rate = (self.parallel_checks / self.total_checks * 100) if self.total_checks > 0 else 0
        avg_patterns = (self.patterns_checked / self.total_checks) if self.total_checks > 0 else 0
        return {
            'total_checks': self.total_checks,
            'parallel_checks': self.parallel_checks,
            'parallel_rate': f"{parallel_rate:.1f}%",
            'patterns_checked': self.patterns_checked,
            'patterns_saved': self.patterns_saved,
            'avg_patterns_per_check': f"{avg_patterns:.1f}"
        }


class ParallelPatternMatcher:
    def __init__(self, max_workers=4, min_patterns_for_parallel=2):
        from concurrent.futures import ThreadPoolExecutor
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.min_patterns_for_parallel = min_patterns_for_parallel
        self.stats = ParallelPatternStats()

    def check_single_pattern(self, rule_pattern_info, test_ast, rules_usage_info):
        try:
            new_ins = rule_pattern_info.rule.check_pattern_and_replace(rule_pattern_info.pattern, test_ast)
            if new_ins is not None:
                return (True, new_ins, rule_pattern_info.rule.name)
        except (RuntimeError, AttributeError):
            pass
        except Exception as e:
            logger.debug(f"Error checking pattern: {e}")
        return (False, None, None)

    def check_patterns_parallel(self, all_matchs, test_ast, rules_usage_info):
        num_patterns = len(all_matchs)

        if num_patterns == 0:
            self.stats.record_check(0, False)
            return None

        if num_patterns < self.min_patterns_for_parallel:
            self.stats.record_check(num_patterns, False)
            for rule_pattern_info in all_matchs:
                success, new_ins, rule_name = self.check_single_pattern(rule_pattern_info, test_ast, rules_usage_info)
                if success:
                    return (new_ins, rule_name)
            return None

        self.stats.record_check(num_patterns, True)

        from concurrent.futures import as_completed
        futures = {}
        for rule_pattern_info in all_matchs:
            future = self.executor.submit(self.check_single_pattern, rule_pattern_info, test_ast, rules_usage_info)
            futures[future] = rule_pattern_info

        result = None
        for future in as_completed(futures):
            success, new_ins, rule_name = future.result()
            if success:
                result = (new_ins, rule_name)
                for f in futures:
                    if not f.done():
                        f.cancel()
                break

        return result

    def shutdown(self):
        self.executor.shutdown(wait=False)

    def __del__(self):
        try:
            self.shutdown()
        except:
            pass


_global_z3_cache = None
_global_pattern_cache = None
_global_cfg_cache = None
_global_simplification_stats = None
_global_parallel_matcher = None

def get_z3_cache() -> Z3ConstraintCache:
    global _global_z3_cache
    if _global_z3_cache is None:
        _global_z3_cache = Z3ConstraintCache(maxsize=512)
    return _global_z3_cache


def get_pattern_cache() -> PatternMatchCache:
    global _global_pattern_cache
    if _global_pattern_cache is None:
        _global_pattern_cache = PatternMatchCache(maxsize=1024)
    return _global_pattern_cache


def get_cfg_cache() -> CFGCache:
    global _global_cfg_cache
    if _global_cfg_cache is None:
        _global_cfg_cache = CFGCache(maxsize=256)
    return _global_cfg_cache


def get_simplification_stats() -> SimplificationStats:
    global _global_simplification_stats
    if _global_simplification_stats is None:
        _global_simplification_stats = SimplificationStats()
    return _global_simplification_stats


def get_parallel_matcher() -> ParallelPatternMatcher:
    global _global_parallel_matcher
    if _global_parallel_matcher is None:
        _global_parallel_matcher = ParallelPatternMatcher(max_workers=4, min_patterns_for_parallel=2)
    return _global_parallel_matcher


def clear_all_caches():
    global _global_z3_cache, _global_pattern_cache, _global_cfg_cache, _global_simplification_stats, _global_parallel_matcher
    if _global_z3_cache:
        _global_z3_cache.clear()
    if _global_pattern_cache:
        _global_pattern_cache.clear()
    if _global_cfg_cache:
        _global_cfg_cache.clear()
    if _global_simplification_stats:
        _global_simplification_stats.clear()
    if _global_parallel_matcher:
        _global_parallel_matcher.stats.clear()
    logger.info("All advanced optimization caches cleared")


def print_cache_stats():
    z3_cache = get_z3_cache()
    pattern_cache = get_pattern_cache()
    cfg_cache = get_cfg_cache()
    simp_stats = get_simplification_stats()
    parallel_matcher = get_parallel_matcher()

    logger.info("=== Advanced Optimization Statistics ===")
    logger.info(f"Z3 Cache: {z3_cache.stats()}")
    logger.info(f"Pattern Cache: {pattern_cache.stats()}")
    logger.info(f"CFG Cache: {cfg_cache.stats()}")
    logger.info(f"AST Simplification: {simp_stats.stats()}")
    logger.info(f"Parallel Pattern Matching: {parallel_matcher.stats.stats()}")

    z3_stats = z3_cache.stats()
    total_z3 = z3_stats['hits'] + z3_stats['misses']
    if total_z3 > 0:
        saved_z3_calls = z3_stats['hits']
        logger.info(f"Z3 Performance: {saved_z3_calls} expensive Z3 checks avoided!")

    parallel_stats = parallel_matcher.stats.stats()
    if parallel_stats['patterns_saved'] > 0:
        logger.info(f"Parallel Performance: {parallel_stats['patterns_saved']} pattern checks saved!")

    logger.info("=======================================")
