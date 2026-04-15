import importlib.util
import argparse
import os
import platform
import subprocess
import sysconfig
from pathlib import Path

from config import DEFAULT_GPU_BATCH_SIZE
from core.opencl_pow import gpu_available as opencl_gpu_available
from core.opencl_pow import mine_pow_gpu as opencl_mine_pow_gpu
from core.opencl_pow import request_cancel as request_opencl_cancel
from core.opencl_pow import reset_cancel as reset_opencl_cancel


MODULE_NAME = "native_pow"
ROOT_DIR = Path(__file__).resolve().parents[1]
NATIVE_DIR = ROOT_DIR / "native"
SOURCE_PATH = NATIVE_DIR / "powmodule.c"
METAL_SOURCE_PATH = NATIVE_DIR / "powmetal.m"
METAL_HEADER_PATH = NATIVE_DIR / "powmetal.h"
EXTENSION_PATH = ROOT_DIR / f"{MODULE_NAME}{sysconfig.get_config_var('EXT_SUFFIX')}"
_native_pow_module = None


def mine_pow(
    prefix: str,
    difficulty_bits: int,
    start_nonce: int = 0,
    progress_interval: int = 0,
    nonce_step: int = 1,
) -> tuple[int, str, bool]:
    module = _load_native_pow_module()
    return module.mine_pow(
        prefix,
        difficulty_bits,
        start_nonce,
        progress_interval,
        nonce_step,
    )


def gpu_available() -> bool:
    module = _load_native_pow_module()
    return bool(module.gpu_available()) or opencl_gpu_available()


def mine_pow_gpu(
    prefix: str,
    difficulty_bits: int,
    start_nonce: int = 0,
    progress_interval: int = 0,
    batch_size: int = DEFAULT_GPU_BATCH_SIZE,
    nonce_step: int = 1,
) -> tuple[int, str, bool]:
    module = _load_native_pow_module()
    if bool(module.gpu_available()):
        return module.mine_pow_gpu(
            prefix,
            difficulty_bits,
            start_nonce,
            progress_interval,
            batch_size,
            nonce_step,
        )
    return opencl_mine_pow_gpu(
        prefix,
        difficulty_bits,
        start_nonce,
        progress_interval,
        batch_size,
        nonce_step,
    )


def request_pow_cancel() -> None:
    module = _load_native_pow_module()
    module.request_cancel()
    request_opencl_cancel()


def reset_pow_cancel() -> None:
    module = _load_native_pow_module()
    module.reset_cancel()
    reset_opencl_cancel()


def build_native_pow_extension(force: bool = False) -> Path:
    if force or _extension_needs_rebuild():
        _build_native_pow_extension()
    return EXTENSION_PATH


def _load_native_pow_module():
    global _native_pow_module

    if _native_pow_module is not None:
        return _native_pow_module

    build_native_pow_extension()

    spec = importlib.util.spec_from_file_location(MODULE_NAME, EXTENSION_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load native proof-of-work module.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _native_pow_module = module
    return module


def _extension_needs_rebuild() -> bool:
    if not EXTENSION_PATH.exists():
        return True

    source_paths = [SOURCE_PATH]
    if platform.system() == "Darwin":
        source_paths.extend([METAL_SOURCE_PATH, METAL_HEADER_PATH])

    return any(path.stat().st_mtime > EXTENSION_PATH.stat().st_mtime for path in source_paths)


def _build_native_pow_extension() -> None:
    include_dir = sysconfig.get_paths()["include"]
    platform_include_dir = sysconfig.get_paths().get("platinclude")
    system = platform.system()

    if system == "Darwin":
        sdk_path = subprocess.check_output(
            ["xcrun", "--show-sdk-path"],
            text=True,
        ).strip()
        compile_command = [
            "clang",
            "-O3",
            "-Werror",
            "-Wall",
            "-Wextra",
            "-std=c11",
            "-fobjc-arc",
            "-bundle",
            "-undefined",
            "dynamic_lookup",
            "-arch",
            platform.machine(),
            "-isysroot",
            sdk_path,
            "-I",
            include_dir,
        ]
        if platform_include_dir:
            compile_command.extend(["-I", platform_include_dir])
        compile_command.extend(
            [
                str(METAL_SOURCE_PATH),
                "-o",
                str(EXTENSION_PATH),
                str(SOURCE_PATH),
                "-framework",
                "Foundation",
                "-framework",
                "Metal",
            ]
        )
    elif system == "Linux":
        compiler = os.environ.get("CC", "cc")
        compile_command = [
            compiler,
            "-O3",
            "-Werror",
            "-Wall",
            "-Wextra",
            "-std=c11",
            "-shared",
            "-fPIC",
            "-I",
            include_dir,
        ]
        if platform_include_dir:
            compile_command.extend(["-I", platform_include_dir])
        compile_command.extend(
            [
                "-o",
                str(EXTENSION_PATH),
                str(SOURCE_PATH),
            ]
        )
    elif system == "Windows":
        compiler = os.environ.get("CC", "cl")
        compile_command = [
            compiler,
            "/O2",
            "/W4",
            "/WX",
            "/LD",
            f"/I{include_dir}",
        ]
        if platform_include_dir:
            compile_command.append(f"/I{platform_include_dir}")
        compile_command.extend(
            [
                str(SOURCE_PATH),
                "/link",
                f"/OUT:{EXTENSION_PATH}",
            ]
        )
    else:
        raise RuntimeError(f"Unsupported platform for native proof-of-work build: {system}")

    subprocess.run(compile_command, check=True, cwd=ROOT_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or load the native proof-of-work module.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild the native module even if it looks up to date.",
    )
    args = parser.parse_args()

    extension_path = build_native_pow_extension(force=args.force)
    print(f"Native proof-of-work module ready at {extension_path}")


if __name__ == "__main__":
    main()
