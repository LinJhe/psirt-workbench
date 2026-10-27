#!/usr/bin/env python3
"""Read-only PSIRT collection or offline reports. No system scheduler required."""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT/'src', ROOT/'scripts'):
    sys.path.insert(0, str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=['live','snapshot-replay','report-rebuild'])
    parser.add_argument('--scope', type=Path, help='Explicit scope JSON required for live collection')
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--result-file', type=Path, help='Exclusive per-attempt receipt for the Windows launcher')
    parser.add_argument('--presentation', type=Path, help='Local report-only meeting/exclusion configuration')
    parser.add_argument('--report-date', help='Weekly report date YYYY-MM-DD; defaults to this run local date')
    parser.add_argument('--retry-salesforce', action='store_true', help='Explicitly recheck blocked Salesforce authentication (live only)')
    parser.add_argument('--trigger', choices=['cli', 'direct', 'page-manual', 'page-auto', 'salesforce-retry', 'page-rebuild'],
                        default='cli', help='Record how this run was requested; does not enable collection or scheduling')
    args = parser.parse_args()
    if (args.mode == 'snapshot-replay') != bool(args.snapshot):
        parser.error('--snapshot is required only for snapshot-replay')
    if args.mode == 'live' and args.scope is None:
        parser.error('--scope is required for live collection; see scripts/psirt_ops/scope.example.json')
    if args.retry_salesforce and args.mode != 'live':
        parser.error('--retry-salesforce is supported only for live collection')
    # Resolve assets consistently; credentials come only from the process environment.
    os.chdir(ROOT)
    from psirt_ops.pipeline import run, encoded, write_new, no_symlinks
    receipt = None
    if args.result_file:
        # Reserve before any API work. A reused receipt must never open an old report.
        no_symlinks(args.result_file)
        receipt = args.result_file.open('xb')
    try:
        cfg = json.loads(args.scope.read_text()) if args.mode == 'live' else None
        result = run(args.output_dir, args.mode, cfg, args.snapshot, args.presentation, args.report_date,
                     retry_sf=args.retry_salesforce, trigger=args.trigger)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except BlockingIOError:
        result = {'error_type':'AlreadyRunning','completed':False,'exit_code':75}
        print('PSIRT is already running. No second collection started.', file=sys.stderr)
    except Exception as exc:
        # Do not print exception strings that may contain credentials or response bodies.
        result = {'error_type': type(exc).__name__, 'completed': False, 'exit_code':2}
        print(json.dumps(result), file=sys.stderr)
    if receipt is not None:
        with receipt:
            receipt.write(encoded(result))
            receipt.flush()
            os.fsync(receipt.fileno())
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
