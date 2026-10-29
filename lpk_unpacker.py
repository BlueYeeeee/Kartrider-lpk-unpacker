"""List, verify, or unpack supported KartRider LPK v4 archives."""
import argparse
from pathlib import Path, PurePosixPath
import struct
import sys
import zlib

from lpk_v4 import DEFAULT_MIXING, LpkError, decode, extract, parameters


def output_path(root, name):
    """Keep archive paths inside the output directory, including on Windows."""
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '\\' in name or ':' in name:
        raise LpkError(f'Unsafe archive path: {name}')
    if any(part in ('', '.', '..') for part in name.split('/')):
        raise LpkError(f'Unsafe archive path: {name}')
    target = root.joinpath(*path.parts).resolve()
    if not target.is_relative_to(root.resolve()):
        raise LpkError(f'Archive path escapes output directory: {name}')
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='one .lpk file or a directory of .lpk files')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--list', action='store_true', help='list paths and decoded sizes')
    action.add_argument('--verify', action='store_true', help='verify all selected files without writing them')
    parser.add_argument('-o', '--output', type=Path, help='extraction directory; existing files are never overwritten')
    parser.add_argument('--path', help='extract/list/verify one exact archive path')
    parser.add_argument('--mixing', default=DEFAULT_MIXING, help='override the recovered P3563 v4 format string')
    args = parser.parse_args(argv)
    if args.input.is_dir():
        sources = sorted(p for p in args.input.iterdir() if p.is_file() and p.suffix.lower() == '.lpk')
    elif args.input.is_file() and args.input.suffix.lower() == '.lpk':
        sources = [args.input]
    else:
        raise LpkError('Input must be an existing .lpk file or directory')
    if not sources:
        raise LpkError('No .lpk files found')
    indexes = [(source, decode(source, args.mixing)) for source in sources]
    selected = []
    for source, index in indexes:
        rows = [r for r in index['records'] if args.path is None or r['path'] == args.path]
        selected.append((source, index, rows))
    count = sum(len(rows) for _, _, rows in selected)
    if not count:
        raise LpkError('No matching archive path')
    if args.list:
        for source, _, rows in selected:
            for record in rows:
                print(f"{source.name}\t{record['dsize']}\t{record['path']}")
        print(f'{len(sources)} archive(s), {count} file(s)')
        return 0
    targets = {}
    seen_targets = set()
    if not args.verify:
        output = args.output or args.input.with_name(args.input.stem + '.unpacked')
        for source, _, rows in selected:
            for record in rows:
                target = output_path(output, record['path'])
                if target in seen_targets or target.exists():
                    raise LpkError(f'Output already exists or has duplicate paths: {target}')
                targets[(source, record['path'])] = target
                seen_targets.add(target)
    digits, nonce = parameters(args.mixing)
    passed = failed = total_bytes = 0
    for source, index, rows in selected:
        if not rows:
            continue
        disk = source.read_bytes()
        for record in rows:
            try:
                data = extract(disk, {**record, 'dataBegin': index['dataBegin']}, digits, nonce)
                if not args.verify:
                    target = targets[(source, record['path'])]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('xb') as file:
                        file.write(data)
                passed += 1
                total_bytes += len(data)
            except (OSError, ValueError, struct.error, zlib.error) as error:
                failed += 1
                print(f'ERROR {source.name}: {record["path"]}: {error}', file=sys.stderr)
        print(f'{source.name}: passed={passed}, failed={failed}')
    print(f'Files={count}, passed={passed}, failed={failed}, decoded_bytes={total_bytes}')
    return 1 if failed else 0


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='backslashreplace')
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error, zlib.error) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
