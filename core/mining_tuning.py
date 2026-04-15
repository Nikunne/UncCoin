import json
import os
import platform
import statistics
import threading
import time

from config import DEFAULT_GPU_CHUNK_MULTIPLIER
from config import DEFAULT_GPU_NONCES_PER_THREAD
from config import DEFAULT_GPU_WORKERS
from config import DEFAULT_MINING_AUTOTUNE_SECONDS
from core.mining_scheduler import get_cpu_chunk_size
from core.mining_scheduler import run_chunked_mining
from core.native_pow import gpu_available as native_gpu_available
from core.native_pow import gpu_properties as native_gpu_properties
from state_paths import ensure_state_dir


AUTOTUNE_VERSION = 20
AUTOTUNE_PATH = ensure_state_dir() / "mining_tuning.json"
GPU_TUNING_PREFIX = "1||bench|" + ("0" * 64) + "|"
GPU_TUNING_START_NONCE = 100_000_000
CPU_TUNING_PREFIX = "mining-autotune|"

_autotune_lock = threading.RLock()
_cached_worker_results: dict[tuple[int, bool, int, int, int, int, int], int] = {}
_cached_gpu_results: dict[int, tuple[int, int]] = {}
_cached_gpu_chunk_multiplier_results: dict[tuple[int, int, int], int] = {}
_cached_gpu_worker_results: dict[tuple[int, int, int, int], int] = {}


def get_tuned_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int = 0,
    gpu_threads_per_group: int = 0,
    gpu_chunk_multiplier: int = DEFAULT_GPU_CHUNK_MULTIPLIER,
    gpu_worker_count: int = DEFAULT_GPU_WORKERS,
) -> int:
    if default_workers <= 1 or _autotune_disabled():
        return default_workers

    cache_key = (
        default_workers,
        gpu_enabled,
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
        gpu_chunk_multiplier,
        gpu_worker_count,
    )
    cached_workers = _cached_worker_results.get(cache_key)
    if cached_workers is not None:
        return cached_workers

    with _autotune_lock:
        cached_workers = _cached_worker_results.get(cache_key)
        if cached_workers is not None:
            return cached_workers

        cached_workers = _load_cached_worker_count(
            default_workers,
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        )
        if cached_workers is not None:
            _cached_worker_results[cache_key] = cached_workers
            return cached_workers

        if gpu_enabled:
            if gpu_nonces_per_thread <= 0 or gpu_threads_per_group <= 0:
                gpu_nonces_per_thread, gpu_threads_per_group = get_tuned_gpu_launch_config(
                    gpu_batch_size
                )
            if gpu_chunk_multiplier <= 0:
                gpu_chunk_multiplier = get_tuned_gpu_chunk_multiplier(
                    gpu_batch_size,
                    gpu_nonces_per_thread,
                    gpu_threads_per_group,
                )
            if gpu_worker_count <= 0:
                gpu_worker_count = get_tuned_gpu_worker_count(
                    gpu_batch_size,
                    gpu_nonces_per_thread,
                    gpu_threads_per_group,
                    gpu_chunk_multiplier,
                )

        tuned_workers = _benchmark_worker_count(
            default_workers,
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        )
        _save_cached_worker_count(
            tuned_workers,
            default_workers,
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        )
        _cached_worker_results[cache_key] = tuned_workers
        return tuned_workers


def get_tuned_gpu_launch_config(gpu_batch_size: int) -> tuple[int, int]:
    if _autotune_disabled():
        return _default_gpu_launch_config()

    cache_key = gpu_batch_size
    cached_config = _cached_gpu_results.get(cache_key)
    if cached_config is not None:
        return cached_config

    with _autotune_lock:
        cached_config = _cached_gpu_results.get(cache_key)
        if cached_config is not None:
            return cached_config

        cached_config = _load_cached_gpu_launch_config(gpu_batch_size)
        if cached_config is not None:
            _cached_gpu_results[cache_key] = cached_config
            return cached_config

        tuned_config = _benchmark_gpu_launch_config(gpu_batch_size)
        _save_cached_gpu_launch_config(tuned_config, gpu_batch_size)
        _cached_gpu_results[cache_key] = tuned_config
        return tuned_config


def get_tuned_gpu_chunk_multiplier(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
) -> int:
    if _autotune_disabled():
        return DEFAULT_GPU_CHUNK_MULTIPLIER

    cache_key = (gpu_batch_size, gpu_nonces_per_thread, gpu_threads_per_group)
    cached_multiplier = _cached_gpu_chunk_multiplier_results.get(cache_key)
    if cached_multiplier is not None:
        return cached_multiplier

    with _autotune_lock:
        cached_multiplier = _cached_gpu_chunk_multiplier_results.get(cache_key)
        if cached_multiplier is not None:
            return cached_multiplier

        cached_multiplier = _load_cached_gpu_chunk_multiplier(
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
        )
        if cached_multiplier is not None:
            _cached_gpu_chunk_multiplier_results[cache_key] = cached_multiplier
            return cached_multiplier

        tuned_multiplier = _benchmark_gpu_chunk_multiplier(
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
        )
        _save_cached_gpu_chunk_multiplier(
            tuned_multiplier,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
        )
        _cached_gpu_chunk_multiplier_results[cache_key] = tuned_multiplier
        return tuned_multiplier


def get_tuned_gpu_worker_count(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
) -> int:
    if _autotune_disabled():
        return DEFAULT_GPU_WORKERS

    cache_key = (
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
        gpu_chunk_multiplier,
    )
    cached_workers = _cached_gpu_worker_results.get(cache_key)
    if cached_workers is not None:
        return cached_workers

    with _autotune_lock:
        cached_workers = _cached_gpu_worker_results.get(cache_key)
        if cached_workers is not None:
            return cached_workers

        cached_workers = _load_cached_gpu_worker_count(
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
        )
        if cached_workers is not None:
            _cached_gpu_worker_results[cache_key] = cached_workers
            return cached_workers

        tuned_workers = _benchmark_gpu_worker_count(
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
        )
        _save_cached_gpu_worker_count(
            tuned_workers,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
        )
        _cached_gpu_worker_results[cache_key] = tuned_workers
        return tuned_workers


def _autotune_disabled() -> bool:
    raw_value = os.environ.get("UNCCOIN_DISABLE_MINING_AUTOTUNE", "")
    return raw_value.lower() in {"1", "true", "yes", "on"}


def _worker_signature(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
    gpu_worker_count: int,
) -> dict[str, object]:
    return {
        "version": AUTOTUNE_VERSION,
        "system": platform.system(),
        "machine": platform.machine(),
        "cpu_count": max(1, os.cpu_count() or 1),
        "default_workers": default_workers,
        "gpu_enabled": gpu_enabled,
        "gpu_batch_size": gpu_batch_size,
        "gpu_nonces_per_thread": gpu_nonces_per_thread,
        "gpu_threads_per_group": gpu_threads_per_group,
        "gpu_chunk_multiplier": gpu_chunk_multiplier,
        "gpu_worker_count": gpu_worker_count,
    }


def _gpu_signature(gpu_batch_size: int) -> dict[str, object] | None:
    gpu_launch_properties = native_gpu_properties()
    if gpu_launch_properties is None:
        return None

    thread_execution_width, max_threads_per_threadgroup = gpu_launch_properties
    return {
        "version": AUTOTUNE_VERSION,
        "system": platform.system(),
        "machine": platform.machine(),
        "cpu_count": max(1, os.cpu_count() or 1),
        "gpu_batch_size": gpu_batch_size,
        "thread_execution_width": thread_execution_width,
        "max_threads_per_threadgroup": max_threads_per_threadgroup,
    }


def _gpu_chunk_multiplier_signature(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
) -> dict[str, object] | None:
    signature = _gpu_signature(gpu_batch_size)
    if signature is None:
        return None
    return signature | {
        "gpu_nonces_per_thread": gpu_nonces_per_thread,
        "gpu_threads_per_group": gpu_threads_per_group,
    }


def _gpu_worker_signature(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
) -> dict[str, object] | None:
    signature = _gpu_chunk_multiplier_signature(
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
    )
    if signature is None:
        return None
    return signature | {
        "gpu_chunk_multiplier": gpu_chunk_multiplier,
    }


def _load_cached_autotune_payload() -> dict[str, object]:
    try:
        payload = json.loads(AUTOTUNE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

    if isinstance(payload, dict):
        return payload
    return {}


def _save_cached_autotune_payload(payload: dict[str, object]) -> None:
    try:
        AUTOTUNE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        return


def _autotune_signature_key(signature: dict[str, object]) -> str:
    return json.dumps(signature, sort_keys=True, separators=(",", ":"))


def _load_cached_tuning_entry(
    section_name: str,
    signature: dict[str, object],
) -> dict[str, object] | None:
    payload = _load_cached_autotune_payload()
    section = payload.get(section_name)
    if not isinstance(section, dict):
        return None

    entry = section.get(_autotune_signature_key(signature))
    if isinstance(entry, dict):
        candidate = entry
    else:
        candidate = section

    for key, expected_value in signature.items():
        if candidate.get(key) != expected_value:
            return None
    return candidate


def _save_cached_tuning_entry(
    section_name: str,
    signature: dict[str, object],
    result: dict[str, object],
) -> None:
    payload = _load_cached_autotune_payload()
    section = payload.get(section_name)
    if not isinstance(section, dict):
        section = {}

    if any(key in section for key in signature):
        section = {}

    section[_autotune_signature_key(signature)] = signature | result
    payload[section_name] = section
    _save_cached_autotune_payload(payload)


def _load_cached_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
    gpu_worker_count: int,
) -> int | None:
    worker_payload = _load_cached_tuning_entry(
        "worker_tuning",
        _worker_signature(
            default_workers,
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        ),
    )
    if worker_payload is None:
        return None

    tuned_workers = worker_payload.get("tuned_workers")
    if not isinstance(tuned_workers, int) or tuned_workers < 1:
        return None
    return tuned_workers


def _save_cached_worker_count(
    tuned_workers: int,
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
    gpu_worker_count: int,
) -> None:
    _save_cached_tuning_entry(
        "worker_tuning",
        _worker_signature(
            default_workers,
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        ),
        {
            "tuned_workers": tuned_workers,
        },
    )


def _load_cached_gpu_launch_config(gpu_batch_size: int) -> tuple[int, int] | None:
    signature = _gpu_signature(gpu_batch_size)
    if signature is None:
        return None

    gpu_payload = _load_cached_tuning_entry("gpu_tuning", signature)
    if gpu_payload is None:
        return None

    nonces_per_thread = gpu_payload.get("nonces_per_thread")
    threads_per_group = gpu_payload.get("threads_per_group")
    if (
        not isinstance(nonces_per_thread, int)
        or not isinstance(threads_per_group, int)
        or nonces_per_thread < 1
        or threads_per_group < 1
    ):
        return None
    return nonces_per_thread, threads_per_group


def _save_cached_gpu_launch_config(
    tuned_config: tuple[int, int],
    gpu_batch_size: int,
) -> None:
    signature = _gpu_signature(gpu_batch_size)
    if signature is None:
        return

    _save_cached_tuning_entry(
        "gpu_tuning",
        signature,
        {
            "nonces_per_thread": tuned_config[0],
            "threads_per_group": tuned_config[1],
        },
    )


def _load_cached_gpu_chunk_multiplier(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
) -> int | None:
    signature = _gpu_chunk_multiplier_signature(
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
    )
    if signature is None:
        return None

    payload = _load_cached_tuning_entry("gpu_chunk_multiplier_tuning", signature)
    if payload is None:
        return None

    multiplier = payload.get("gpu_chunk_multiplier")
    if not isinstance(multiplier, int) or multiplier < 1:
        return None
    return multiplier


def _save_cached_gpu_chunk_multiplier(
    tuned_multiplier: int,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
) -> None:
    signature = _gpu_chunk_multiplier_signature(
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
    )
    if signature is None:
        return

    _save_cached_tuning_entry(
        "gpu_chunk_multiplier_tuning",
        signature,
        {
            "gpu_chunk_multiplier": tuned_multiplier,
        },
    )


def _load_cached_gpu_worker_count(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
) -> int | None:
    signature = _gpu_worker_signature(
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
        gpu_chunk_multiplier,
    )
    if signature is None:
        return None

    payload = _load_cached_tuning_entry("gpu_worker_tuning", signature)
    if payload is None:
        return None

    gpu_workers = payload.get("gpu_workers")
    if not isinstance(gpu_workers, int) or gpu_workers < 1:
        return None
    return gpu_workers


def _save_cached_gpu_worker_count(
    tuned_workers: int,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
) -> None:
    signature = _gpu_worker_signature(
        gpu_batch_size,
        gpu_nonces_per_thread,
        gpu_threads_per_group,
        gpu_chunk_multiplier,
    )
    if signature is None:
        return

    _save_cached_tuning_entry(
        "gpu_worker_tuning",
        signature,
        {
            "gpu_workers": tuned_workers,
        },
    )


def _default_gpu_launch_config() -> tuple[int, int]:
    properties = native_gpu_properties()
    if properties is None:
        return DEFAULT_GPU_NONCES_PER_THREAD, 0

    thread_execution_width, max_threads_per_threadgroup = properties
    if thread_execution_width <= 0:
        return DEFAULT_GPU_NONCES_PER_THREAD, 1

    return DEFAULT_GPU_NONCES_PER_THREAD, min(
        max(1, thread_execution_width),
        max(1, max_threads_per_threadgroup),
    )


def _benchmark_worker_count(
    default_workers: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
    gpu_worker_count: int,
) -> int:
    candidate_workers = _candidate_worker_counts(default_workers)
    benchmark_seconds = DEFAULT_MINING_AUTOTUNE_SECONDS

    if gpu_enabled:
        native_gpu_available()

    scores = {
        workers: _measure_hash_rate(
            workers,
            gpu_enabled,
            gpu_batch_size,
            benchmark_seconds,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
        )
        for workers in candidate_workers
    }

    top_candidates = sorted(scores, key=scores.get, reverse=True)[:2]
    for workers in top_candidates:
        scores[workers] = _measure_hash_rate(
            workers,
            gpu_enabled,
            gpu_batch_size,
            benchmark_seconds * 2.0,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
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


def _benchmark_gpu_launch_config(gpu_batch_size: int) -> tuple[int, int]:
    default_config = _default_gpu_launch_config()
    properties = native_gpu_properties()
    if properties is None:
        return default_config

    thread_execution_width, max_threads_per_threadgroup = properties
    if thread_execution_width <= 0 or max_threads_per_threadgroup <= 0:
        return default_config

    candidate_threads_per_group = _candidate_threads_per_group(
        thread_execution_width,
        max_threads_per_threadgroup,
    )
    candidate_nonces_per_thread = (4, 8, 16, 32, 64)
    benchmark_seconds = DEFAULT_MINING_AUTOTUNE_SECONDS
    representative_worker_count = _representative_gpu_tuning_worker_count()

    scores = {
        (nonces_per_thread, threads_per_group): _measure_hash_rate(
            representative_worker_count,
            True,
            gpu_batch_size,
            benchmark_seconds,
            nonces_per_thread,
            threads_per_group,
            DEFAULT_GPU_CHUNK_MULTIPLIER,
            DEFAULT_GPU_WORKERS,
        )
        for nonces_per_thread in candidate_nonces_per_thread
        for threads_per_group in candidate_threads_per_group
    }

    top_candidates = sorted(scores, key=scores.get, reverse=True)[:8]
    for nonces_per_thread, threads_per_group in top_candidates:
        gpu_score = statistics.median(
            [
                _measure_hash_rate(
                    0,
                    True,
                    gpu_batch_size,
                    benchmark_seconds * 2.0,
                    nonces_per_thread,
                    threads_per_group,
                    DEFAULT_GPU_CHUNK_MULTIPLIER,
                    DEFAULT_GPU_WORKERS,
                )
                for _ in range(2)
            ]
        )
        hybrid_score = statistics.median(
            [
                _measure_hash_rate(
                    representative_worker_count,
                    True,
                    gpu_batch_size,
                    benchmark_seconds * 2.0,
                    nonces_per_thread,
                    threads_per_group,
                    DEFAULT_GPU_CHUNK_MULTIPLIER,
                    DEFAULT_GPU_WORKERS,
                )
                for _ in range(2)
            ]
        )
        scores[(nonces_per_thread, threads_per_group)] = (
            hybrid_score,
            gpu_score,
        )

    best_config = max(
        scores,
        key=lambda config: (
            scores[config]
            if isinstance(scores[config], tuple)
            else (0.0, scores[config]),
            config[0],
            config[1],
        ),
    )
    best_score = scores[best_config]
    if isinstance(best_score, tuple):
        if best_score[0] <= 0.0 and best_score[1] <= 0.0:
            return default_config
        return best_config
    if best_score <= 0.0:
        return default_config
    return best_config


def _benchmark_gpu_chunk_multiplier(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
) -> int:
    benchmark_seconds = DEFAULT_MINING_AUTOTUNE_SECONDS
    representative_worker_count = _representative_gpu_tuning_worker_count()
    candidate_multipliers = (1, 2, 4, 8, 16, 32)

    scores = {
        multiplier: _measure_hash_rate(
            representative_worker_count,
            True,
            gpu_batch_size,
            benchmark_seconds,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            multiplier,
            DEFAULT_GPU_WORKERS,
        )
        for multiplier in candidate_multipliers
    }

    top_candidates = sorted(scores, key=scores.get, reverse=True)[:3]
    for multiplier in top_candidates:
        scores[multiplier] = statistics.median(
            [
                _measure_hash_rate(
                    representative_worker_count,
                    True,
                    gpu_batch_size,
                    benchmark_seconds * 2.0,
                    gpu_nonces_per_thread,
                    gpu_threads_per_group,
                    multiplier,
                    DEFAULT_GPU_WORKERS,
                )
                for _ in range(2)
            ]
        )

    best_multiplier = max(candidate_multipliers, key=lambda multiplier: (scores[multiplier], multiplier))
    if scores[best_multiplier] <= 0.0:
        return DEFAULT_GPU_CHUNK_MULTIPLIER
    return best_multiplier


def _benchmark_gpu_worker_count(
    gpu_batch_size: int,
    gpu_nonces_per_thread: int,
    gpu_threads_per_group: int,
    gpu_chunk_multiplier: int,
) -> int:
    benchmark_seconds = DEFAULT_MINING_AUTOTUNE_SECONDS
    representative_worker_count = _representative_gpu_tuning_worker_count()
    candidate_gpu_workers = tuple(
        worker_count
        for worker_count in (1, 2)
        if worker_count <= max(1, os.cpu_count() or 1)
    )

    scores = {
        gpu_workers: _measure_hash_rate(
            representative_worker_count,
            True,
            gpu_batch_size,
            benchmark_seconds,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_workers,
        )
        for gpu_workers in candidate_gpu_workers
    }

    top_candidates = sorted(scores, key=scores.get, reverse=True)[:2]
    for gpu_workers in top_candidates:
        scores[gpu_workers] = statistics.median(
            [
                _measure_hash_rate(
                    representative_worker_count,
                    True,
                    gpu_batch_size,
                    benchmark_seconds * 2.0,
                    gpu_nonces_per_thread,
                    gpu_threads_per_group,
                    gpu_chunk_multiplier,
                    gpu_workers,
                )
                for _ in range(2)
            ]
        )

    best_workers = max(candidate_gpu_workers, key=lambda gpu_workers: (scores[gpu_workers], -gpu_workers))
    if scores[best_workers] <= 0.0:
        return DEFAULT_GPU_WORKERS
    return best_workers


def _representative_gpu_tuning_worker_count() -> int:
    cpu_count = max(1, os.cpu_count() or 1)
    return max(1, (cpu_count * 3) // 4)


def _candidate_threads_per_group(
    thread_execution_width: int,
    max_threads_per_threadgroup: int,
) -> tuple[int, ...]:
    max_multiple = max(1, max_threads_per_threadgroup // max(1, thread_execution_width))
    candidates = {
        max(1, thread_execution_width),
        min(max_threads_per_threadgroup, thread_execution_width * 2),
        min(max_threads_per_threadgroup, thread_execution_width * 4),
        min(max_threads_per_threadgroup, thread_execution_width * 8),
        min(max_threads_per_threadgroup, thread_execution_width * 16),
        min(max_threads_per_threadgroup, thread_execution_width * max_multiple),
    }
    return tuple(sorted(candidate for candidate in candidates if candidate > 0))


def _measure_hash_rate(
    worker_count: int,
    gpu_enabled: bool,
    gpu_batch_size: int,
    benchmark_seconds: float,
    gpu_nonces_per_thread: int = 0,
    gpu_threads_per_group: int = 0,
    gpu_chunk_multiplier: int | None = None,
    gpu_worker_count: int = DEFAULT_GPU_WORKERS,
) -> float:
    prefix = GPU_TUNING_PREFIX if gpu_enabled else CPU_TUNING_PREFIX
    start_nonce = GPU_TUNING_START_NONCE if gpu_enabled else 0

    try:
        result = run_chunked_mining(
            prefix,
            256,
            start_nonce,
            worker_count,
            get_cpu_chunk_size(),
            gpu_enabled,
            gpu_batch_size,
            gpu_nonces_per_thread,
            gpu_threads_per_group,
            gpu_chunk_multiplier,
            gpu_worker_count,
            cancel_after_seconds=benchmark_seconds,
        )
    except Exception:
        return 0.0

    if result.winner is not None:
        return 0.0
    if gpu_enabled and result.gpu_failed:
        return 0.0
    if not result.cancelled:
        return 0.0

    return result.attempts / max(result.elapsed, 1e-9)
