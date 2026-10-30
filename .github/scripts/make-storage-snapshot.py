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


def build_esp(root, kernel, output, memory_mib, platform):
    esp = output / 'esp'
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
          '--qemu-accel', 'tcg', '--armvirt']
    if platform:
        dt += ['--platform-compatible', platform]
    subprocess.run(dt, check=True)

    (esp / 'EFI/UniXNU/unixnu.toml').write_text(
        'version = 1\n\n[boot]\ntimeout = 0\ndefault = "xnu"\n\n[kits]\nautoload = false\n\n'
        '[[entry]]\nid = "xnu"\ntitle = "UniXNU"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\nargs = "-v serial=3 boot-progress=0"\n')
    return esp


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=ROOT, help='assembled build tree')
    parser.add_argument('--kernel', type=Path,
                        help='prelink candidate (default: build/xnu-prelink/native-apfs-load-positive.macho)')
    parser.add_argument('--output', type=Path,
                        help='output directory (default: build/darwinboot-storage-native-metadata)')
    parser.add_argument('--timeout', type=float, default=180.0, help='guest deadline in seconds')
    parser.add_argument('--qemu-memory-mib', type=int, choices=[1024, 2048, 4096, 8192], default=1024)
    parser.add_argument('--platform-compatible', default='xiaomi,sheng',
                        help='DT platform compatible string for QEMU (empty to omit)')
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

    esp = build_esp(root, kernel, output, args.qemu_memory_mib, args.platform_compatible)
    command = ['python3', str(root / 'scripts/qemu-entry/gdb-stop.py'), hex(stop),
               '--fixture', str(output), '--esp', str(esp), '--kernel', str(kernel),
               '--system-registers', '--timeout', str(args.timeout),
               '--qemu-accel', 'tcg', '--qemu-memory-mib', str(args.qemu_memory_mib)]
    for request in requests:
        command += ['--read-memory', request]
    print('running:', ' '.join(command))
    result = subprocess.run(command)
    report_path = output / 'gdb-stop.json'
    if result.returncode or not report_path.is_file():
        failure = output / 'gdb-failure.json'
        if failure.is_file():
            print(failure.read_text(), file=sys.stderr)
        raise SystemExit(f'gdb-stop did not produce {report_path} (exit {result.returncode})')

    report = json.loads(report_path.read_text())
    memory = report.get('memory') or {}
    missing = [request for request in requests if request not in memory]
    if missing:
        raise SystemExit(f'the snapshot lacks {", ".join(missing)}: '
                         f'the guest stopped before IOKit initialised these metaclasses')
    if report.get('bounded_timeout_interrupted'):
        raise SystemExit('the guest hit its deadline before the breakpoint: raise --timeout')
    if report.get('kernel_sha256') != derived['plan']['candidate_sha256']:
        raise SystemExit('the snapshot identifies a different kernel than the audit will check')

    registers = report.get('system_registers') or {}
    needed = ('TCR_EL1', 'SCTLR_EL1', 'TTBR0_EL1', 'TTBR1_EL1')
    absent = [name for name in needed if name not in registers]
    if absent:
        raise SystemExit(f'the snapshot lacks {", ".join(absent)}')
    tcr = int(registers['TCR_EL1'], 16)
    print(f'TCR_EL1 {registers["TCR_EL1"]} (T0SZ={tcr >> 14 & 3}, TG0={tcr >> 30 & 3})')
    print(f'memory slots captured: {len(memory)}')
    print(f'PASS: {report_path}')
    print(f'      storage metaclass {memory[requests[0]][:32]}...')
    print(f'      service metaclass {memory[requests[1]][:32]}...')


if __name__ == '__main__':
    main()
