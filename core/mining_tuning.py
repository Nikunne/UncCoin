import json
import os
import platform
import threading
import time

from config import DEFAULT_MINING_AUTOTUNE_SECONDS
from core.native_pow import gpu_available as native_gpu_available
from core.native_pow import mine_pow as native_mine_pow
from core.native_pow import mine_pow_gpu as native_mine_pow_gpu
from core.native_pow import request_pow_cancel
from core.native_pow import reset_pow_cancel
from state_paths import ensure_state_dir


AUTOTUNE_VERSION = 1
AUTOTUNE_PATH = ensure_state_dir() / "mining_tuning.json"

_autotune_lock = threading.Lock()
_cached_results: dict[tuple[int, bool, int], int] = {}


def get_tuned_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
) -> int:
    if default_workers <= 1 or _autotune_disabled():
        return default_workers

    cache_key = (default_workers, gpu_enabled, gpu_batch_size)
    cached_workers = _cached_results.get(cache_key)
    if cached_workers is not None:
        return cached_workers

    with _autotune_lock:
        cached_workers = _cached_results.get(cache_key)
        if cached_workers is not None:
            return cached_workers

        cached_workers = _load_cached_worker_count(default_workers, gpu_enabled, gpu_batch_size)
        if cached_workers is not None:
            _cached_results[cache_key] = cached_workers
            return cached_workers

        tuned_workers = _benchmark_worker_count(default_workers, gpu_enabled, gpu_batch_size)
        _save_cached_worker_count(tuned_workers, default_workers, gpu_enabled, gpu_batch_size)
        _cached_results[cache_key] = tuned_workers
        return tuned_workers


def _autotune_disabled() -> bool:
    raw_value = os.environ.get("UNCCOIN_DISABLE_MINING_AUTOTUNE", "")
    return raw_value.lower() in {"1", "true", "yes", "on"}


def _machine_signature(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
) -> dict[str, object]:
    return {
        "version": AUTOTUNE_VERSION,
        "system": platform.system(),
        "machine": platform.machine(),
        "cpu_count": max(1, os.cpu_count() or 1),
        "default_workers": default_workers,
        "gpu_enabled": gpu_enabled,
        "gpu_batch_size": gpu_batch_size,
    }


def _load_cached_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
) -> int | None:
    try:
        cached_data = json.loads(AUTOTUNE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    signature = _machine_signature(default_workers, gpu_enabled, gpu_batch_size)
    for key, expected_value in signature.items():
        if cached_data.get(key) != expected_value:
            return None

    tuned_workers = cached_data.get("tuned_workers")
    if not isinstance(tuned_workers, int) or tuned_workers < 1:
        return None
    return tuned_workers


def _save_cached_worker_count(
    tuned_workers: int,
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
) -> None:
    payload = _machine_signature(default_workers, gpu_enabled, gpu_batch_size) | {
        "tuned_workers": tuned_workers,
    }
    try:
        AUTOTUNE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        return


def _benchmark_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
) -> int:
    candidate_workers = _candidate_worker_counts(default_workers)
    benchmark_seconds = DEFAULT_MINING_AUTOTUNE_SECONDS

    if gpu_enabled:
        native_gpu_available()

    scores = {
        workers: _measure_hash_rate(workers, gpu_enabled, gpu_batch_size, benchmark_seconds)
        for workers in candidate_workers
    }

    top_candidates = sorted(scores, key=scores.get, reverse=True)[:2]
    for workers in top_candidates:
        scores[workers] = _measure_hash_rate(
            workers,
            gpu_enabled,
            gpu_batch_size,
            benchmark_seconds * 2.0,
        )

    best_workers = max(candidate_workers, key=lambda workers: (scores[workers], -workers))
    if scores[best_workers] <= 0.0:
        return default_workers
    return best_workers


def _candidate_worker_counts(default_workers: int) -> tuple[int, ...]:
    candidates = {
        max(1, default_workers // 2),
        max(1, default_workers - 2),
        default_workers,
        default_workers + 2,
        default_workers + 4,
    }
    return tuple(sorted(candidates))


def _measure_hash_rate(
    worker_count: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    benchmark_seconds: float,
) -> float:
    total_partitions = worker_count + (1 if gpu_enabled else 0)
    results: dict[tuple[str, int], tuple[int, str, bool]] = {}
    errors: dict[tuple[str, int], str] = {}
    workers: list[threading.Thread] = []

    def run_cpu(worker_index: int) -> None:
        try:
            results[("cpu", worker_index)] = native_mine_pow(
                "mining-autotune|",
                256,
                worker_index,
                0,
                total_partitions,
            )
        except Exception as error:
            errors[("cpu", worker_index)] = repr(error)

    def run_gpu() -> None:
        try:
            results[("gpu", 0)] = native_mine_pow_gpu(
                "mining-autotune|",
                256,
                worker_count,
                0,
                gpu_batch_size,
                total_partitions,
            )
        except Exception as error:
            errors[("gpu", 0)] = repr(error)

    reset_pow_cancel()

    for worker_index in range(worker_count):
        worker = threading.Thread(target=run_cpu, args=(worker_index,), daemon=True)
        workers.append(worker)
        worker.start()

    if gpu_enabled:
        gpu_worker = threading.Thread(target=run_gpu, daemon=True)
        workers.append(gpu_worker)
        gpu_worker.start()

    start_time = time.perf_counter()
    time.sleep(benchmark_seconds)
    request_pow_cancel()
    for worker in workers:
        worker.join(timeout=benchmark_seconds + 5.0)
    elapsed = time.perf_counter() - start_time
    reset_pow_cancel()

    if errors or any(worker.is_alive() for worker in workers):
        return 0.0

    attempts = 0
    for worker_index in range(worker_count):
        nonce, _, cancelled = results.get(("cpu", worker_index), (worker_index, "", False))
        if not cancelled:
            return 0.0
        attempts += max(0, (nonce - worker_index) // total_partitions)

    if gpu_enabled:
        nonce, _, cancelled = results.get(("gpu", 0), (worker_count, "", False))
        if not cancelled:
            return 0.0
        attempts += max(0, (nonce - worker_count) // total_partitions)

    return attempts / max(elapsed, 1e-9)
