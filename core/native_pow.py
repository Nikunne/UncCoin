import importlib.util
import platform
import subprocess
import sysconfig
from pathlib import Path


MODULE_NAME = "native_pow"
ROOT_DIR = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT_DIR / "native" / "powmodule.c"
EXTENSION_PATH = ROOT_DIR / f"{MODULE_NAME}{sysconfig.get_config_var('EXT_SUFFIX')}"
_native_pow_module = None


def mine_pow(
    prefix: str,
    difficulty_bits: int,
    start_nonce: int = 0,
    progress_interval: int = 0,
) -> tuple[int, str]:
    module = _load_native_pow_module()
    return module.mine_pow(prefix, difficulty_bits, start_nonce, progress_interval)


def _load_native_pow_module():
    global _native_pow_module

    if _native_pow_module is not None:
        return _native_pow_module

    if _extension_needs_rebuild():
        _build_native_pow_extension()

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

    return SOURCE_PATH.stat().st_mtime > EXTENSION_PATH.stat().st_mtime


def _build_native_pow_extension() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("Native proof-of-work build currently supports only macOS.")

    include_dir = sysconfig.get_paths()["include"]
    platform_include_dir = sysconfig.get_paths().get("platinclude")
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
            "-o",
            str(EXTENSION_PATH),
            str(SOURCE_PATH),
        ]
    )

    subprocess.run(
        compile_command,
        check=True,
        cwd=ROOT_DIR,
    )
