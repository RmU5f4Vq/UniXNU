#!/usr/bin/env python3
"""Produce build/verified-root-os-xnu-bundle/libVerifiedRootProbe.a from the pinned IPSW.

The stage-2 kernel links that archive for CONFIG_XNU_VERIFIED_ROOT_PROBE, and
scripts/build-verified-root-probe.py refuses to build it without two fully
verified original policies under one owner key. None of the prerequisites has a
producer in the upstream repositories, so this tool supplies them in the order
the checks demand:

  1. owner RSA-3072 key pair the manifest header is signed with
  2. kits/VerifiedRoot compiled into the host dylib its verification step loads
  3. sign + block-verify the OS member (scripts/build-owner-os-policy.py logic)
  4. sign + block-verify the Cryptex1,SystemOS member the same way
  5. run scripts/build-verified-root-probe.py --component os --include-systemos

The DMG inputs come from `unixnu ipsw fetch OS "Cryptex1,SystemOS"` (HTTP range
requests into out/ipsw/<build>/, no whole-IPSW download). Their compressed SHA-256
pins come from profiles/os/<profile>/profile.toml [ipsw.sha256]; the OS volume
UUID matches board.toml [payload.adt] root_match_volume_uuid. Failing either pin
means the restore image is not the exact iPad7,1 input the kernel policy pins.

Usage (macOS only; needs hdiutil, diskutil, openssl@3, Xcode):
  python3 unixnu-verified-root.py --root TREE --os-dmg DMG --systemos-dmg DMG
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid as uuidlib


# Pins from profiles/os/ipados-17.7.11-21H461/profile.toml [ipsw.sha256] and
# board.toml [payload.adt] root_match_volume_uuid. These are the identity of the
# exact Apple members the kernel's owner-root policy binds to.
OS_COMPRESSED_SHA256 = '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d'
OS_VOLUME_UUID = '04769D26-2CA0-4825-B443-E2E5F88300F2'
SYSTEMOS_COMPRESSED_SHA256 = 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f'

# What scripts/build-verified-root-probe.py --component os --include-systemos
# will later require; failing them here stops before the expensive parts.
OS_IMAGE_SHA256 = 'e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2'
OS_BLOCKS_VERIFIED = 1483785
SYSTEMOS_IMAGE_SHA256 = 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f'
SYSTEMOS_BLOCKS_VERIFIED = 806400

# kits/VerifiedRoot submodule commit the tree pins (unixtree.json). The probe
# records this revision; keep the build honest about which source it used.
VERIFIED_ROOT_REVISION = 'def026642c6c6e71be0dea267d989df1d29ddc64'


class Failure(SystemExit):
    pass


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs)


def log(message):
    print(f'[verified-root] {message}', flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_keys(root):
    """Owner RSA-3072 pair; exponent 65537 is openssl's default and is required."""
    keys = root / 'build/verified-root-host/keys'
    private, public = keys / 'owner.pem', keys / 'owner-public.pem'
    if private.is_file() and public.is_file():
        log(f'owner keys already present: {keys}')
        return keys
    keys.mkdir(parents=True, exist_ok=True)
    log('generating owner RSA-3072 key pair')
    run(['openssl', 'genrsa', '-out', str(private), '3072'])
    run(['openssl', 'rsa', '-in', str(private), '-pubout', '-out', str(public)])
    private.chmod(0o600)
    text = run(['openssl', 'rsa', '-pubin', '-in', str(public), '-text', '-noout']).stdout
    if 'Exponent: 65537' not in text:
        raise Failure('owner key exponent must be 65537')
    return keys


def ensure_host_dylib(root):
    """verified-root.dylib: vr_open/vr_verify_block + OpenSSL-3 host wrappers.

    macOS ships LibreSSL without openssl/param_build.h, so this needs Homebrew
    openssl@3; the workflow's host-tools step installs it.
    """
    host = root / 'build/verified-root-host'
    dylib = host / 'verified-root.dylib'
    if dylib.is_file():
        log(f'host dylib already present: {dylib}')
        return dylib
    prefix = run(['brew', '--prefix', 'openssl@3']).stdout.strip()
    include = Path(prefix) / 'include'
    if not (include / 'openssl/param_build.h').is_file():
        raise Failure(f'openssl@3 headers not found under {include}; brew install openssl@3')
    kit = root / 'kits/VerifiedRoot'
    for rel in ('include/verified_root.h', 'src/verified_root.c', 'tests/openssl_provider.c'):
        if not (kit / rel).is_file():
            raise Failure(f'{kit / rel} is missing; run unixnu fetch so kits/VerifiedRoot is checked out')
    host.mkdir(parents=True, exist_ok=True)
    log('compiling verified-root.dylib (verified_root.c + openssl_provider.c)')
    run(['clang', '-dynamiclib', '-O2', '-fPIC',
         '-I', str(kit / 'include'), '-I', str(include),
         '-o', str(dylib),
         str(kit / 'src/verified_root.c'), str(kit / 'tests/openssl_provider.c'),
         '-L', str(Path(prefix) / 'lib'), '-lcrypto'])
    return dylib


class VrView(ctypes.Structure):
    _fields_ = [('hashes', ctypes.c_void_p), ('image_bytes', ctypes.c_uint64),
                ('block_count', ctypes.c_uint64), ('generation', ctypes.c_uint64),
                ('volume_uuid', ctypes.c_uint8 * 16), ('image_sha256', ctypes.c_uint8 * 32)]


def load_verifier(dylib):
    native = ctypes.CDLL(str(dylib))
    native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                    ctypes.c_uint64, ctypes.POINTER(VrView)]
    native.vr_host_block.argtypes = [ctypes.POINTER(VrView), ctypes.c_uint64,
                                     ctypes.c_void_p, ctypes.c_size_t]
    return native


def attach_readonly(dmg):
    """Attach read-only without mounting, the way scripts/unixnu/userdata.py does.

    Returns (whole_raw, whole_node). Mounting is wrong here for two reasons:
    the raw device of a mounted APFS volume is not readable without root
    (Errno 13), and diskutil then reports the volume's size, which is 67 sectors
    smaller than the logical disk the manifest must cover. -nomount exposes the
    same bytes hdiutil would give /dev/rdiskN, with no privileges needed.
    """
    out = run(['hdiutil', 'attach', '-nomount', '-readonly', '-noverify', '-noautofsck',
               str(dmg)]).stdout
    for line in out.splitlines():
        # -nomount prints "TYPE<spaces>/dev/diskN[ ...]"; accept end of line too.
        match = re.search(r'(/dev/disk\d+)(?:\s|$)', line)
        if match:
            node = Path(match[1])
            return Path('/dev/r' + node.name), node
    raise Failure(f'could not find the attached disk device in: {out}')


def logical_size(dmg):
    """Size Information.Total Bytes: the logical disk, independent of mounting."""
    info = plistlib.loads(run(['hdiutil', 'imageinfo', '-plist', str(dmg)]).stdout.encode())
    return info['Size Information']['Total Bytes']


def detach(disk):
    node = str(disk).replace('/dev/r', '/dev/')
    subprocess.run(['hdiutil', 'detach', node], check=False, capture_output=True)


def read_volume_uuid(node):
    """Volume UUID of the (single) volume on the attached image.

    The attach is -nomount so the raw disk stays unprivileged. Volume UUIDs live
    in each volume's superblock, which diskutil reads without mounting; only the
    APFS container listing needs the Containers nesting resolved first.
    """
    listing = plistlib.loads(run(['diskutil', 'list', '-plist', str(node)]).stdout.encode())
    candidates = []
    for container in listing.get('Containers', []):
        candidates.extend(container.get('APFSVolumes', []))
    candidates.extend(listing.get('APFSVolumes', []))
    candidates.extend(listing.get('Partitions', []))
    identifiers = [e['DeviceIdentifier'] for e in candidates if e.get('DeviceIdentifier')]
    if len(identifiers) != 1:
        raise Failure(f'expected exactly one volume under {node}, got {identifiers} from {listing}')
    device = f'/dev/{identifiers[0]}'
    info = plistlib.loads(run(['diskutil', 'info', '-plist', device]).stdout.encode())
    return info.get('VolumeUUID')


def import_manifest_tool(root):
    tool = root / 'kits/VerifiedRoot/tools/manifest.py'
    if not tool.is_file():
        raise Failure(f'{tool} is missing; run unixnu fetch so kits/VerifiedRoot is checked out')
    spec = importlib.util.spec_from_file_location('verified_manifest', tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sign_and_verify(root, name, dmg, compressed_sha, expected_uuid, dylib):
    """One original member: pin -> attach -> manifest.make -> per-block C verify."""
    log(f'--- {name} ---')
    if not dmg.is_file():
        raise Failure(f'{name} member not found at {dmg}; run unixnu ipsw fetch first')
    digest = sha256_file(dmg)
    if digest != compressed_sha:
        raise Failure(f'{dmg.name} sha256 {digest} != pinned {compressed_sha}; wrong restore member')
    log(f'{dmg.name}: compressed sha256 matches the profile pin')

    out = root / f'build/verified-root-{name}'
    keys = root / 'build/verified-root-host/keys'
    manifest = import_manifest_tool(root)
    native = load_verifier(dylib)

    disk, node = attach_readonly(dmg)
    try:
        total = logical_size(dmg)
        # The authenticated extent is the logical disk image, exactly what
        # scripts/build-owner-os-policy.py reads from the attached whole device:
        # 6077580800 bytes for OS (final block 1536), 3303014400 for SystemOS.
        # hdiutil imageinfo reports it without mounting, unlike diskutil, whose
        # TotalSize depends on which node is asked and whether a volume is mounted.
        if not total or total % 512:
            raise Failure(f'{name}: logical image size {total} is not sector aligned')
        # Only the volume UUID needs the volume mounted; reading it does not touch
        # the raw device, so it stays unprivileged.
        volume_uuid = read_volume_uuid(node)
        if expected_uuid and str(volume_uuid).upper() != expected_uuid:
            raise Failure(f'{name}: volume UUID {volume_uuid} != expected {expected_uuid}')
        if not volume_uuid:
            raise Failure(f'{name}: no VolumeUUID found on the attached member')
        log(f'{name}: extent {disk} size {total} bytes, volume UUID {volume_uuid}')

        log(f'{name}: signing every 4096-byte block hash with the owner key')
        with disk.open('rb', buffering=1024 * 1024) as stream:
            record = manifest.make(stream, total, keys / 'owner.pem', keys / 'owner-public.pem',
                                   volume_uuid, 1, out)

        encoded = ctypes.create_string_buffer((out / 'manifest.bin').read_bytes())
        anchor = ctypes.create_string_buffer((out / 'trusted-key.bin').read_bytes())
        view = VrView()
        if native.vr_host_open(encoded, len(encoded) - 1, anchor, 1, ctypes.byref(view)):
            raise Failure(f'{name}: real C signature authentication failed')
        if bytes(view.volume_uuid) != uuidlib.UUID(str(volume_uuid)).bytes:
            raise Failure(f'{name}: authenticated volume UUID mismatch')

        complete = hashlib.sha256()
        samples, lengths = [], []
        wanted = {0, 1, view.block_count // 2, view.block_count - 1}
        log(f'{name}: verifying {view.block_count} blocks with the real C/RSA path')
        started = time.monotonic()
        with disk.open('rb', buffering=1024 * 1024) as stream:
            for index in range(view.block_count):
                block = stream.read(min(4096, view.image_bytes - index * 4096))
                if native.vr_host_block(ctypes.byref(view), index, block, len(block)) != 0:
                    raise Failure(f'{name}: C block verification failed at {index}')
                complete.update(block)
                if index in wanted:
                    samples.append(block.ljust(4096, b'\0'))
                    lengths.append(len(block))
                if index and index % 200000 == 0:
                    elapsed = time.monotonic() - started
                    log(f'{name}: {index}/{view.block_count} blocks, {elapsed:.0f}s')
            if stream.read(1):
                raise Failure(f'{name}: media exceeds its authenticated bounds')
        if complete.digest() != bytes(view.image_sha256) or complete.hexdigest() != record['image_sha256']:
            raise Failure(f'{name}: complete digest differs from the authenticated one')
    finally:
        detach(disk)

    (out / 'original-samples.bin').write_bytes(b''.join(samples))
    report = dict(image_bytes=view.image_bytes, blocks_verified=view.block_count,
                  image_sha256=complete.hexdigest(), volume_uuid=str(volume_uuid).upper(),
                  generation=view.generation, source_compressed_sha256=digest, source_format='UDIF',
                  host_bus_protocol='Disk Image', host_media_writable=False,
                  trusted_key_sha256=record['trusted_key_sha256'],
                  actual_sample_indices=[0, 1, view.block_count // 2, view.block_count - 1],
                  actual_sample_lengths=lengths,
                  real_c_signature_and_block_verification=True,
                  original_image_modified=False, host_only=True, boot_root_authenticated=False,
                  qemu_tested=False, hardware_tested=False,
                  source_revision=VERIFIED_ROOT_REVISION)
    (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    log(f'{name}: PASS {view.block_count} blocks, image_sha256 {complete.hexdigest()[:16]}…')
    return report


def cross_check(report, name, expected_image_sha, expected_blocks):
    """Fail before the probe does, with the member name attached."""
    if report['image_sha256'] != expected_image_sha:
        raise Failure(f'{name}: decompressed image sha256 {report["image_sha256"]} != '
                      f'the value scripts/build-verified-root-probe.py pins ({expected_image_sha}); '
                      f'the restore member is not the exact original image')
    if report['blocks_verified'] != expected_blocks:
        raise Failure(f'{name}: block count {report["blocks_verified"]} != {expected_blocks}')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, required=True, help='assembled build tree')
    parser.add_argument('--os-dmg', type=Path, required=True, help='OS member from unixnu ipsw fetch')
    parser.add_argument('--systemos-dmg', type=Path, required=True,
                        help='Cryptex1,SystemOS member from unixnu ipsw fetch')
    parser.add_argument('--keep-dmgs', action='store_true',
                        help='keep the extracted members (default deletes them after verification)')
    args = parser.parse_args()

    root = args.root.resolve()
    for rel in ('kits/VerifiedRoot', 'scripts/build-verified-root-probe.py',
                'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o.json'):
        if not (root / rel).is_file() and not (root / rel).is_dir():
            raise Failure(f'{root / rel} is missing; the stage-1 tree is not assembled')

    ensure_keys(root)
    dylib = ensure_host_dylib(root)

    os_report = sign_and_verify(root, 'os', args.os_dmg, OS_COMPRESSED_SHA256, OS_VOLUME_UUID, dylib)
    cross_check(os_report, 'os', OS_IMAGE_SHA256, OS_BLOCKS_VERIFIED)
    # The SystemOS volume UUID is not pinned anywhere upstream; it is recorded so
    # the probe can bind the two members under the one owner anchor it checks.
    systemos_report = sign_and_verify(root, 'systemos', args.systemos_dmg,
                                      SYSTEMOS_COMPRESSED_SHA256, None, dylib)
    cross_check(systemos_report, 'systemos', SYSTEMOS_IMAGE_SHA256, SYSTEMOS_BLOCKS_VERIFIED)

    key = root / 'build/verified-root-os/trusted-key.bin'
    if (root / 'build/verified-root-systemos/trusted-key.bin').read_bytes() != key.read_bytes():
        raise Failure('the two members must be verified under the same owner anchor')

    if not args.keep_dmgs:
        for dmg in (args.os_dmg, args.systemos_dmg):
            if dmg.is_file():
                dmg.unlink()
                log(f'removed {dmg.name} to free runner disk')

    log('running scripts/build-verified-root-probe.py --component os --include-systemos')
    result = subprocess.run(['python3', str(root / 'scripts/build-verified-root-probe.py'),
                             '--component', 'os', '--include-systemos'], cwd=root)
    if result.returncode:
        raise Failure(f'build-verified-root-probe.py exited {result.returncode}')

    archive = root / 'build/verified-root-os-xnu-bundle/libVerifiedRootProbe.a'
    if not archive.is_file():
        raise Failure(f'{archive} was not produced')
    log(f'PASS: {archive}')


if __name__ == '__main__':
    main()
