# Local boot map

This directory intentionally contains no device-specific data in the public repository. The reproducer reads two **local, ignored** files:

- `boot_id.txt`: one text line from `adb -s "$P60_ADB_SERIAL" shell cat /proc/sys/kernel/random/boot_id`.
- `init_task_next.bin`: exactly eight bytes, little-endian, holding the live `init_task.tasks.next` virtual pointer from the same boot.

The `INIT_TASK_VA`, `TASKS_OFF`, `PID_OFF`, `CRED_OFF`, and direct-map constants in `probe/task_walk.py` came from the tested build and must be checked against any other build or boot. The script checks the model, boot ID, pointer length, task PID/name, credential pointers, reference count, UID/GID fields, and capabilities before writing. A reboot requires a fresh map. This repository does not include an automated kernel-map discovery step, so a fresh clone cannot reproduce the shell until those local inputs are prepared.

Proof transcripts from the private VRP package are also omitted here. They are not runtime inputs.
