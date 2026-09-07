# Galaxy A55 5G `SM-A556B` / `A556BXXSBCYK2`

This is the port record for the Galaxy A55 profile
`a55x-A556BXXSBCYK2`. It is tied to the exact firmware identified from
the device via ADB. The native payload has been built and verified against
the recovered kernel ELF.

## Firmware identity

```text
model: SM-A556B
device: a55x
region: EUX
AP/PDA: A556BXXSBCYK2
CSC: A556BOXMBCYK2
CP: A556BXXSBCYK2
composite build: BP4A.251205.006.A556BXXSBCYK2
Android / SDK: 16 / 36
security patch: 2025-11-01
kernel: 6.1.138-android14-11
page size: 4096
board: s5e8845
```

## Firmware provenance

```text
factory ZIP: SM-A556B_EUX_A556BXXSBCYK2.zip
firmware file: SM-A556B_3_20251111185301_yh62b1qeaa_fac.zip
```

## Image recovery

```text
boot.img: 67108864 bytes
sboot.bin: 5260080 bytes
raw Image kernel: 37452288 bytes
kernel version: 6.1.138-android14-11
ARM64 text_offset: 0x0
ARM64 flags: 0xa
```

The kernel was extracted from the AP tar.md5 (lz4 compressed) and analyzed
with vmlinux-to-elf. The recovered kernel reports Android clang 17.0.2
and `6.1.138-android14-11`.

Raw BTF was validated at a single blob, then dumped to both raw and C forms.
Relevant BTF sizes/fields are:

```text
file_operations: 0x110; ioctl 0x50; compat_ioctl 0x58; mmap 0x60;
  open 0x70; release 0x80; splice_read 0xc8; show_fdinfo 0xe0
page: 0x40; compound_head 0x08; slab_cache 0x18; page_type 0x30
work_struct: 0x30; data 0x00; entry 0x08; func 0x18
task_struct: 0x12c0; usage 0x40; prio 0x84; normal_prio 0x8c;
  sched_task_group 0x348; pi_lock 0x924; pi_waiters 0x938;
  pi_top_task 0x948; pi_blocked_on 0x950
mm_struct: 0x3c0; selected SLUB stride: 0x400; order: 3
rt_mutex_waiter: 0x58; pi_tree_entry 0x18; task 0x30; lock 0x38;
  wake_state 0x40; prio 0x44; deadline 0x48; ww_ctx 0x50
configfs_buffer: page 0x10; needs_read_fill 0x50; bin_buffer 0x58;
  bin_buffer_size 0x60; cb_max_size 0x64
workqueue_struct: dfl_pwq 0xb0; pool_workqueue: pool 0x00, wq 0x08;
  work_color 0x10; refcnt 0x18; nr_in_flight 0x1c; nr_active 0x5c;
  max_active 0x60
worker_pool: worklist 0x28; nr_idle 0x3c
miscdevice.fops: 0x10; skb_shared_info: 0x158
```

The embedded IKCONFIG confirms `CONFIG_ARM64_MTE=y`,
`CONFIG_KASAN_HW_TAGS=y`, `CONFIG_MODVERSIONS=y`, `CONFIG_DEBUG_INFO_BTF=y`,
`CONFIG_KDP=y`, `CONFIG_RKP=y`, `CONFIG_SLUB=y`, and 4 KiB pages.

## Derived target constants

The following values are taken from the recovered symbol table, BTF, or raw
image pointer checks; they are not copied from a model-name template.

```text
call_usermodehelper_exec_work      0x000d37a8
worker_thread -> schedule LR       0x000db0c4
noop_llseek                        0x0039c6c8
generic_file_splice_read           0x003ea1fc
configfs_read_iter                 0x0046a06c
configfs_bin_write_iter            0x0046a59c
ashmem_ioctl                       0x00cc85c0
compat_ashmem_ioctl                0x00cc8ef8
ashmem_mmap                        0x00cc8f50
ashmem_open                        0x00cc9170
ashmem_release                     0x00cc91f8
ashmem_show_fdinfo                 0x00cc9318
anon_pipe_buf_ops                  0x01199790
ashmem_fops                        0x01320048
kmalloc_caches                     0x016bf978
system_unbound_wq                  0x021aae60
nfulnl_logger                      0x021b29d8
init_task                          0x021bf700
ashmem_miscs.fops                  0x023385f0
root_task_group                    0x023c4d40
selinux_state.enforcing            0x024991a8
sysctl_bootid                      0x0253f3d8
nfnetlink_log string               0x15dd16a
```

The `nfulnl_logger.name` pointer resolves to the unique `nfnetlink_log` string;
the selected `random_table` pointer resolves to `sysctl_bootid`; and
`ashmem_miscs + 0x10` points to `ashmem_fops`.

The target kernel computes the futex hash table size as
`roundup_pow_of_two(256 * num_possible_cpus())`.
Live topology is `possible=0-7`, so the effective size is `0x800`.

`__event_sched_blocked_reason - __start_ftrace_events = 0x2b0`, so event
index 86 plus `__TRACE_LAST_TYPE == 20` gives event ID 106.

The `unix_stream_sendmsg` path uses a 0xe80 linear head and an order-3,
page-aligned 0x8000 data fragment for the 0x8e80 maximum chunk. The resulting
payload bias is `SKB_DATA_DELTA=-0x1000`.

The `sboot.bin` (5260080 bytes, identical size to A556E's) confirms the same
Exynos s5e8845 SoC with `P0_PHYS_OFFSET=0x80000000` and
`P0_KERNEL_PHYS_LOAD=0x80000000`. The AArch64 VA geometry gives the shared
`0xffffff8000000000` direct map and `0xfffffffe00000000` vmemmap base.

`SLIDE_PSELECT_WORD_SHIFT=3` follows the compact 6.1 stack layout used by the
same `do_select` sequence; all ten waiter words therefore land in the three
fd-set arrays. The P0 probe offset is `0x1f0000`.

## Build and audit results

```sh
make TARGET=a55x-A556BXXSBCYK2 \
  ANDROID_NDK_HOME=/path/to/android-ndk-r29 \
  clean all release
```

The release payload is an AArch64 shared object, exactly 104128 bytes.

## Validation state

The support feed entry is present for `SM-A556B` + kernel `6.1.138` and marks
the profile as requiring one fresh same-process P0 session.

TODO: Live ADB validation on SM-A556B hardware pending.
