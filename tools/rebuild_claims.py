#!/usr/bin/env python3
"""Local, atomic ownership leases for PS2 reconstruction; never a progress claim."""
from pathlib import Path
import sys

# tools/dis.py is an analysis CLI, not Python's standard-library dis module.
if __name__ == '__main__':
    sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != Path(__file__).resolve().parent]

import argparse
import json
import os
import time

ROOT = Path(__file__).resolve().parents[1]


def address(value):
    try:
        number = int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError('Use a hexadecimal function entry address.')
    if number < 0x100000 or number >= 0x3e6000 or number % 4:
        raise argparse.ArgumentTypeError('Expected an aligned address in the executable code range.')
    return f'{number:08x}'


def update(folder, action, entry, owner, minutes=240, now=None):
    if not owner.strip() or len(owner) > 120:
        raise ValueError('Provide a nonempty owner name of at most 120 characters.')
    if not 1 <= minutes <= 240:
        raise ValueError('A lease lasts between 1 and 240 minutes.')
    now = time.time() if now is None else now
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / '.lock'
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError('Another claim update is in progress. Retry; do not remove its lock.')
    try:
        path = folder / (entry + '.json')
        current = json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
        if action == 'release':
            if current is None:
                raise ValueError('No lease exists for this function.')
            if current['owner'] != owner:
                raise ValueError('Only the recorded owner may release this lease.')
            path.unlink()
            return {'released': entry, 'owner': owner}
        if current and current['expires_at'] > now and current['owner'] != owner:
            raise ValueError(f"Function {entry} is claimed by {current['owner']}.")
        record = {'entry': entry, 'owner': owner, 'claimed_at': now,
                  'expires_at': now + minutes * 60}
        # Global mkdir lock serializes writers; replace makes readers see complete JSON.
        temporary = folder / (entry + '.tmp')
        temporary.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        os.replace(temporary, path)
        return record
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list')
    for name in ('claim', 'release'):
        p = sub.add_parser(name)
        p.add_argument('entry', type=address)
        p.add_argument('--owner', required=True)
        if name == 'claim':
            p.add_argument('--minutes', type=int, default=240)
    args = parser.parse_args()
    folder = ROOT / 'work' / 'rebuild' / 'claims'
    try:
        if args.action == 'list':
            now = time.time()
            records = []
            for path in sorted(folder.glob('*.json')):
                record = json.loads(path.read_text(encoding='utf-8'))
                record['active'] = record['expires_at'] > now
                records.append(record)
            print(json.dumps(records, indent=2))
        else:
            print(json.dumps(update(folder, args.action, args.entry, args.owner,
                                    getattr(args, 'minutes', 240)), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f'Claim failed: {exc}\n')


if __name__ == '__main__':
    main()
