# Huawei P60 Pro: boot-scoped ADB-shell-to-UID0 chain

**Research provenance:** This result was obtained with OpenAI's GPT-6-Sol model at `High effort`. After the process was described in two prompts, a 1-hour-10-minute research goal led to a UID 0 shell.

With a matching local boot map, this package reproduces a **temporary interactive UID 0 shell with full Linux capabilities** on the tested Huawei P60 Pro. The shell remains in `u:r:shell:s0` while SELinux is Enforcing. It is not a persistent or unrestricted root environment.

## Tested target

The chain was tested on a Huawei P60 Pro (model `MNA-LX9`) running EMUI `14.2.0`.

| Field | Value |
| --- | --- |
| Model | Huawei P60 Pro `MNA-LX9` (`MNA-L29` product) |
| EMUI | `14.2.0` |
| Public GPU vulnerability used | [CVE-2025-21479](https://docs.qualcomm.com/product/publicresources/securitybulletin/june-2025-bulletin.html) |
| Fingerprint | `HUAWEI/MNA-L29/HWMNA:12/HUAWEIMNA-L29/104.2.0.208C432:user/release-keys` |
| Android | 12 / API 31 |
| Security patch property | `2022-08-01` |

The public repository omits the device serial, boot ID, live pointer, proof logs, and generated binaries. For a local authorized device, `device/init_task_next.bin` must contain the eight-byte `init_task.tasks` pointer from the **same boot** as `device/boot_id.txt`. A reboot invalidates the map. The code still contains offsets from the tested build; a different build or boot needs its own validated kernel/task map. See [device setup](device/README.md).

## Reproduce

Requirements: Python 3, Android Platform Tools (`adb`), Android NDK with `aarch64-linux-android28-clang`, authorized USB debugging, and a locally prepared map for the current boot. Set `ANDROID_NDK_HOME` if the NDK is not discoverable from the local Android SDK installation. `P60_ADB_SERIAL` is required so multiple connected devices cannot be confused.

```sh
cd vrp-root-shell-submission
adb devices -l
export P60_ADB_SERIAL=YOUR_DEVICE_SERIAL
adb -s "$P60_ADB_SERIAL" shell cat /proc/sys/kernel/random/boot_id > device/boot_id.txt
# Prepare device/init_task_next.bin from this boot's verified kernel/task map.
ANDROID_NDK_HOME=/path/to/android-ndk python3 probe/reproduce_uid0.py --build-only
ANDROID_NDK_HOME=/path/to/android-ndk python3 probe/reproduce_uid0.py --full-caps
```

The script uses only `P60_ADB_SERIAL`, verifies model and boot ID, and refuses a missing or malformed pointer. Changing the serial alone is insufficient because the saved pointer and build layout must also match.

Inside the resulting interactive shell:

```sh
id
cat /proc/self/status
getenforce
exit
```

On the tested boot, `id` reported UID/GID 0; `CapPrm`, `CapEff`, and `CapBnd` were `000003ffffffffff`. `getenforce` remained `Enforcing`, and the process context remained `u:r:shell:s0`. The script deletes its temporary target-specific patch binary and remote helper files when the session ends. Running an ordinary new ADB shell does not inherit UID 0.

For the narrower UID/GID-only variant, omit `--full-caps`; that variant has no effective/permitted capabilities.

## Chain and preflight

1. `probe/out/cred_target` starts from ADB shell UID 2000 and creates a separate credential object for one disposable process.
2. `probe/task_walk.py` uses a GPU read probe to find that process in the live kernel task list and locate its credential object. It checks the PID, process name, credential pointer, reference count, eight UID/GID fields, securebits, and capability fields before any write.
3. `probe/native/cred_patch_once.c` is compiled with that **newly found** physical credential address. Its preflight independently reads the target fields.
4. A single KGSL GPU submission writes UID/GID 0, full permitted/effective/bounding capability masks, and `securebits=0` to that isolated credential object. A separate GPU read confirms the fields before the target executes `/system/bin/sh`.

The GPU primitive follows public CVE-2025-21479 research. The device-specific perf physical-address observation, task map, credential checks, and shell chain are documented here; this package does **not** claim a new GPU CVE or an application-origin exploit. No kernel text is modified. The `--full-caps` path does not change the global SELinux state.

If `Boot changed`, `PID/cred changed`, `preflight refused`, or a GPU completion error appears, the script stops. Do not substitute saved physical addresses by hand. The boot-specific map must be regenerated for a new boot.

## Contents

| Path | Purpose |
| --- | --- |
| `probe/reproduce_uid0.py` | Device selection, checks, compilation, GPU write, interactive shell, cleanup |
| `probe/task_walk.py` | Read-only live task and credential lookup |
| `probe/native/cred_target.c` | Disposable UID 2000 target source; binary built locally |
| `probe/native/cred_patch_once.c` | Target-address-specific GPU credential patch source |
| `probe/native/kgsl_bulk_dump.c` | GPU physical read probe source; binary built locally |
| `device/README.md` | Local boot-map format and release boundary |
| `references/vivo-iqoo-9t/tools/device/` | Upstream GPU helper source, license, and original revision in `UPSTREAM_COMMIT` |

The script compiles the two helpers from source with `PAGES=64`, `REQUIRE_IMAGE_MAGIC=0`, and `DUMP_PATH="/data/local/tmp/p60_phys_probe.bin"`; the resulting hashes matched the previously validated helper binaries. The target-specific patch binary is built only after live preflight because it embeds a per-process physical address. `probe/out/` and `device/*.txt` / `device/*.bin` are ignored and remain local.

Run `shasum -a 256 -c SHA256SUMS` in this directory to verify the committed source files. `--build-only` checks that both static AArch64 helpers compile without contacting the device.

## Scope of the evidence

This is an ADB-shell-started chain. It does not demonstrate execution from an ordinary application sandbox. SELinux still restricts the root shell. A separate process-specific SELinux experiment exists in the wider research, but it is not part of this root-shell reproducer and has not been combined into a stable unrestricted interactive shell.

The upstream helper is GPL-3.0 licensed; its license and source are included in `references/vivo-iqoo-9t/tools/device/`. The supplied GPU read and credential patch sources include local research changes for this device.
