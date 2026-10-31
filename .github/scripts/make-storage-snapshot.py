#!/usr/bin/env python3
"""Produce build/darwinboot-storage-native-metadata/gdb-stop.json for sheng.

audit-storage-interface.py reads a QEMU/GDB snapshot of two IOKit metaclasses and
the live system registers, but nothing in the repositories writes one: the audit
reader exists, the writer does not. This tool builds an ESP, boots the supplied
prelink candidate under QEMU through the existing scripts/qemu-entry/gdb-stop.py,
reads exactly the two addresses the audit derives, and writes the report it wants.

The addresses are not recomputed here. The derivation section of
scripts/audit-storage-interface.py is executed up to the statement that would
read the snapshot, so this tool follows the audit instead of duplicating it: if
the audit changes how it finds the metaclass, this keeps matching.

Requires, all from an earlier build of the same tree:
  build/<config>/package UniXNU.efi, build/DarwinBoot/.../DarwinBoot.efi
  build/xnu-prelink/native-apfs-load-positive.macho and its .json report
  scripts/qemu-entry/{make-dt.py,gdb-stop.py}
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

AUDIT = 'scripts/audit-storage-interface.py'
# The audit reads its own snapshot at this statement. Everything above it is the
# static derivation of the two metaclass addresses, which is what we need.
CUT = "d = json.loads((ROOT / 'build/darwinboot-storage-native-metadata/gdb-stop.json').read_text())"


def package_output(root):
    """UniXNU.efi, located the way unixnu.package.output_dir locates it."""
    sys.path.insert(0, str(root / 'scripts'))
    try:
        from unixnu.package import output_dir
    except ImportError:
        output_dir = None
    directories = [output_dir(root)] if output_dir else []
    directories += [root.parent / 'package/Build/Out' / 'AARCH64-DEBUG',
                    root / 'package/Build/Out' / 'AARCH64-DEBUG']
    for directory in directories:
        exe = directory / 'UniXNU.efi'
        if exe.is_file():
            return exe
    for directory in directories:
        found = sorted(directory.rglob('UniXNU.efi'))
        if found:
            return found[0]
    raise SystemExit(f'UniXNU.efi not found under {", ".join(str(d) for d in directories)}: '
                     f'build the package before generating the snapshot')


def darwinboot(root):
    """DarwinBoot.efi, building it with the repository script when absent."""
    def locate():
        for base in ('build', 'Build'):
            found = sorted((root / base).rglob('DarwinBoot.efi')) if (root / base).is_dir() else []
            if found:
                return found[0]
        return None

    found = locate()
    if found:
        return found
    script = root / 'scripts/build-darwinboot.sh'
    if not script.is_file():
        raise SystemExit('DarwinBoot.efi is missing and scripts/build-darwinboot.sh is absent')

    # build-darwinboot.sh drives EDK II but never builds BaseTools, and it assumes
    # GenFw is already there. Build it first when the tree has only the sources.
    tools = root / 'refer/edk2' / 'BaseTools'
    if not (tools / 'MdePkg').exists() and (root / 'package/Mu_Basecore/BaseTools').is_dir():
        tools = root / 'package/Mu_Basecore/BaseTools'
    if (tools / 'Source/C').is_dir() and not (tools / 'Source/C/bin/GenFw').is_file():
        print(f'BaseTools have no GenFw yet: building {tools / "Source/C"}')
        built = subprocess.run(['make', '-C', str(tools / 'Source/C'), f'-j{os.cpu_count() or 4}'],
                               capture_output=True, text=True)
        if built.returncode:
            print(built.stdout[-4000:], file=sys.stderr)
            print(built.stderr[-4000:], file=sys.stderr)
            raise SystemExit('building BaseTools failed')

    print('DarwinBoot.efi is missing: building it with scripts/build-darwinboot.sh')
    print(f'  CLANG_BIN={os.environ.get("CLANG_BIN", "(unset)")}')
    print(f'  BaseTools={tools}')
    built = subprocess.run(['bash', str(script)], cwd=root, capture_output=True, text=True)
    if built.returncode:
        # The script's own output is the only way to see which tool EDK II could not run.
        print('--- build-darwinboot.sh stdout ---', file=sys.stderr)
        print(built.stdout[-8000:], file=sys.stderr)
        print('--- build-darwinboot.sh stderr ---', file=sys.stderr)
        print(built.stderr[-8000:], file=sys.stderr)
        raise SystemExit(f'scripts/build-darwinboot.sh exited {built.returncode}')
    found = locate()
    if not found:
        raise SystemExit('DarwinBoot.efi is still missing after scripts/build-darwinboot.sh')
    return found


def derive(root):
    """Run the audit's own derivation and stop before it wants the snapshot."""
    source = root / AUDIT
    if not source.is_file():
        raise SystemExit(f'{AUDIT} is missing from {root}')
    text = source.read_text()
    if CUT not in text:
        raise SystemExit('audit-storage-interface.py no longer reads the snapshot at the expected '
                         'statement; update CUT in this tool before trusting its output')
    head = text[:text.index(CUT)]
    namespace = {'__file__': str(source), '__name__': '__audit_derivation__'}
    try:
        exec(compile(head, str(source), 'exec'), namespace)
    except SystemExit as error:
        raise SystemExit(f'the audit derivation stopped early: {error}')
    for name in ('meta', 'service_meta', 'by_name'):
        if name not in namespace:
            raise SystemExit(f'the audit derivation did not define {name}')
    return namespace


def build_esp(root, kernel, output, memory_mib, platform, accel='tcg'):
    esp = output / 'esp' if accel == 'tcg' else output / f'esp-{accel}'
    payloads = esp / 'EFI/UniXNU/Payloads'
    payloads.mkdir(parents=True, exist_ok=True)
    (esp / 'EFI/BOOT').mkdir(parents=True, exist_ok=True)
    (esp / 'EFI/UniXNU').mkdir(parents=True, exist_ok=True)

    shutil.copyfile(package_output(root), esp / 'EFI/BOOT/BOOTAA64.EFI')
    shutil.copyfile(darwinboot(root), payloads / 'DarwinBoot.efi')
    shutil.copyfile(kernel, payloads / 'kernel.macho')

    dt = ['python3', str(root / 'scripts/qemu-entry/make-dt.py'),
          '--output', str(payloads / 'kernel.macho.adt'),
          '--dram-size', str(memory_mib * 1024 ** 2),
          '--qemu-accel', accel, '--armvirt']
    if platform:
        dt += ['--platform-compatible', platform]
    subprocess.run(dt, check=True)

    # Same layout cli_payload.py writes for a board whose [payload] loader is not
    # "firmware". DarwinBoot is a UEFI driver that installs UNIXNU_LOADER_PROTOCOL,
    # and an entry of type "xnu" cannot start without it: UniXNU answers "no loader
    # protocol installed" and the menu entry returns Unsupported. A shipped board
    # gets the loader from its firmware volume; the QEMU firmware volume is a stock
    # edk2 build, so here the loader has to come from the ESP.
    # serial=3 is the only channel that reports how far the guest got; boot-progress
    # is absent on purpose, the bring-up configuration leaves it off.
    (esp / 'EFI/UniXNU/unixnu.toml').write_text(
        'version = 1\n[boot]\ntimeout = 0\ndefault = "xnu"\n[kits]\nautoload = false\n'
        '[[driver]]\npath = "Payloads/DarwinBoot.efi"\n'
        '[[entry]]\nid = "xnu"\ntitle = "UniXNU"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\nargs = "-v serial=3"\n')
    return esp


def serial_tail(path, count=400):
    if not path.is_file():
        return b''
    with path.open('rb') as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - count))
        return stream.read()


def run_guest(root, kernel, output, accel, seconds, memory_mib, platform,
              stop, requests, ramfb=False):
    """One QEMU boot. Returns (report, fixture) or (None, fixture) on refusal."""
    fixture = output / f'qemu-{accel}'
    fixture.mkdir(parents=True, exist_ok=True)
    for stale in ('gdb-stop.json', 'gdb-failure.json', 'gdb-uart.log'):
        (fixture / stale).unlink(missing_ok=True)
    esp = build_esp(root, kernel, output, memory_mib, platform, accel)

    command = ['python3', str(root / 'scripts/qemu-entry/gdb-stop.py'), hex(stop),
               '--fixture', str(fixture), '--esp', str(esp), '--kernel', str(kernel),
               '--system-registers', '--timeout', str(seconds),
               '--qemu-accel', accel, '--qemu-memory-mib', str(memory_mib)]
    if ramfb:
        # DarwinBoot reads the framebuffer from GOP before it builds boot_args.
        # A -display none guest has no GPU, so this is off until the serial log
        # shows DarwinBoot refusing to hand off without it.
        command += ['--qemu-ramfb']
    for request in requests:
        command += ['--read-memory', request]
    print('running:', ' '.join(command), flush=True)

    # The guest runs for tens of minutes, so report where it is instead of
    # blocking on a silent child: the serial log is the only progress signal,
    # and a frozen byte count means the guest stopped making forward progress.
    uart = fixture / 'gdb-uart.log'
    started, seen_size = time.monotonic(), -1
    process = subprocess.Popen(command)
    while process.poll() is None:
        time.sleep(15)
        size = uart.stat().st_size if uart.is_file() else 0
        elapsed = time.monotonic() - started
        if size == seen_size:
            print(f'  [{accel}] {elapsed:6.0f}s  serial {size} B, no new output', flush=True)
            continue
        seen_size = size
        lines = serial_tail(uart).decode(errors='replace').strip().splitlines()
        print(f'  [{accel}] {elapsed:6.0f}s  serial {size} B | '
              f'{lines[-1][:160] if lines else "(nothing yet)"}', flush=True)
    returncode = process.wait()
    print(f'  [{accel}] exited {returncode} after {time.monotonic() - started:.0f}s', flush=True)

    if uart.is_file():
        print(f'[{accel}] guest serial log: {uart.stat().st_size} bytes')
    report_path = fixture / 'gdb-stop.json'
    if returncode or not report_path.is_file():
        failure = fixture / 'gdb-failure.json'
        if failure.is_file():
            print(failure.read_text(), file=sys.stderr)
        return None, fixture
    return json.loads(report_path.read_text()), fixture


def describe_serial(fixture, tail_bytes=6000):
    uart = fixture / 'gdb-uart.log'
    if not uart.is_file() or not uart.stat().st_size:
        print('the guest wrote nothing to its serial port', file=sys.stderr)
        return
    tail = uart.read_bytes()[-tail_bytes:]
    print('--- guest serial (tail) ---', file=sys.stderr)
    print(tail.decode(errors='replace'), file=sys.stderr)
    print('--- end guest serial ---', file=sys.stderr)


def judge(report, requests, registers_needed):
    """Return None when the snapshot qualifies, else the reason it does not."""
    if report.get('bounded_timeout_interrupted'):
        return (f'the guest did not reach _panic before the deadline '
                f'(stopped at pc {report.get("pc")})')
    memory = report.get('memory') or {}
    absent = [request for request in requests
              if not memory.get(request) or memory[request].startswith('E')]
    if absent:
        return (f'cannot read {", ".join(absent)}: the guest stopped before IOKit '
                f'initialised these metaclasses (pc {report.get("pc")})')
    registers = report.get('system_registers') or {}
    missing = [name for name in registers_needed if name not in registers]
    if missing:
        return f'the snapshot lacks {", ".join(missing)}'
    tcr = int(registers['TCR_EL1'], 16)
    if tcr >> 14 & 3 or tcr >> 30 & 3 != 2 or not int(registers['SCTLR_EL1'], 16) & 1:
        return (f'TCR_EL1 {registers["TCR_EL1"]} / SCTLR_EL1 {registers["SCTLR_EL1"]} '
                f'is not the enabled native 4K configuration the audit requires')
    for name in ('TTBR0_EL1', 'TTBR1_EL1'):
        if not int(registers[name], 16):
            return (f'{name} is zero: the guest stopped before XNU built its own tables, '
                    f'so the snapshot cannot qualify live 4K translation')
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=ROOT, help='assembled build tree')
    parser.add_argument('--kernel', type=Path,
                        help='prelink candidate (default: build/xnu-prelink/native-apfs-load-positive.macho)')
    parser.add_argument('--output', type=Path,
                        help='output directory (default: build/darwinboot-storage-native-metadata)')
    parser.add_argument('--timeout', type=float, default=1800.0,
                        help='guest deadline in seconds; TCG must run EDK II, UniXNU and DarwinBoot '
                             'before XNU reaches IOKit, which takes tens of minutes, not seconds')
    parser.add_argument('--accel', choices=['tcg'], default='tcg',
                        help='guest accelerator; the macOS runners offer TCG only')
    parser.add_argument('--qemu-memory-mib', type=int, choices=[1024, 2048, 4096, 8192], default=1024)
    parser.add_argument('--platform-compatible', default='xiaomi,sheng',
                        help='DT platform compatible string for QEMU (empty to omit)')
    parser.add_argument('--qemu-ramfb', action='store_true',
                        help='attach QEMU ramfb so the guest has a GOP framebuffer for DarwinBoot')
    parser.add_argument('--log-dir', type=Path,
                        help='keep the guest serial log and the raw GDB reports here; without it the '
                             'only record of where the guest stopped is deleted with the fixture')
    args = parser.parse_args()

    root = args.root.resolve()
    kernel = (args.kernel or root / 'build/xnu-prelink/native-apfs-load-positive.macho').resolve()
    output = (args.output or root / 'build/darwinboot-storage-native-metadata').resolve()
    if not kernel.is_file():
        raise SystemExit(f'prelink candidate not found: {kernel}')
    if not kernel.with_suffix('.json').is_file():
        raise SystemExit(f'prelink report not found: {kernel.with_suffix(".json")}')

    derived = derive(root)
    meta, service_meta = derived['meta'], derived['service_meta']
    by_name = derived['by_name']
    stop = by_name.get('_panic')
    if not stop:
        raise SystemExit('the candidate exports no _panic to stop at')
    print(f'IOBlockStorageDevice metaclass {meta:#x}')
    print(f'IOService metaclass           {service_meta:#x}')
    print(f'stop                          _panic {stop:#x}')
    if not by_name.get('__ZN9IOService10gMetaClassE'):
        raise SystemExit('IOService gMetaClass is not in the candidate exports')

    # Both slots at 0x50 bytes: the audit reads exactly that much from each.
    requests = [f'{meta:x}:50', f'{service_meta:x}:50']
    output.mkdir(parents=True, exist_ok=True)
    for stale in ('gdb-stop.json', 'gdb-failure.json'):
        (output / stale).unlink(missing_ok=True)

    registers_needed = ('TCR_EL1', 'SCTLR_EL1', 'TTBR0_EL1', 'TTBR1_EL1')

    # TCG is the only accelerator the macOS runners allow here: HVF is not
    # available to them, so the guest emulates every arm64 instruction of EDK II,
    # UniXNU and DarwinBoot before XNU starts. The deadline therefore has to be
    # tens of minutes, and the serial log is what shows the guest is advancing.
    report, fixture = run_guest(root, kernel, output, args.accel, args.timeout,
                                args.qemu_memory_mib, args.platform_compatible,
                                stop, requests, args.qemu_ramfb)

    # The fixture dies with the runner, so keep what the guest itself said.
    if args.log_dir:
        args.log_dir.mkdir(parents=True, exist_ok=True)
        for name in ('gdb-uart.log', 'gdb-stop.json', 'gdb-failure.json'):
            source = fixture / name
            if source.is_file():
                target = args.log_dir / f'snapshot-{name}'
                shutil.copyfile(source, target)
                # Only *.log reaches the uploaded artifact, so mirror the JSON
                # reports as text: a serial tail cannot explain a stop alone.
                if source.suffix == '.json':
                    shutil.copyfile(source, target.with_suffix('.json.log'))

    problem = 'gdb-stop wrote no report' if report is None else judge(
        report, requests, registers_needed)
    if not problem and report.get('kernel_sha256') != derived['plan']['candidate_sha256']:
        problem = 'the snapshot identifies a different kernel than the audit checks'
    if problem:
        describe_serial(fixture)
        raise SystemExit(problem)

    # The audit reads exactly this path.
    report_path = output / 'gdb-stop.json'
    shutil.copyfile(fixture / 'gdb-stop.json', report_path)

    registers, memory = report['system_registers'], report['memory']
    tcr = int(registers['TCR_EL1'], 16)
    print(f'{args.accel}: TCR_EL1 {registers["TCR_EL1"]} (T0SZ={tcr >> 14 & 3}, TG0={tcr >> 30 & 3})')
    print(f'{args.accel}: TTBR0_EL1 {registers["TTBR0_EL1"]}  TTBR1_EL1 {registers["TTBR1_EL1"]}')
    uart = fixture / 'gdb-uart.log'
    if uart.is_file() and uart.stat().st_size:
        lines = uart.read_bytes().decode(errors='replace').splitlines()
        print(f'guest serial: {len(lines)} lines')
        for line in lines[-15:]:
            print(f'  | {line}')
    print(f'memory slots captured: {len(memory)}')
    print(f'PASS: {report_path}')
    print(f'      storage metaclass {memory[requests[0]][:32]}...')
    print(f'      service metaclass {memory[requests[1]][:32]}...')


if __name__ == '__main__':
    main()
