#!/usr/bin/env python3
"""Run each synthetic test module in a separate process (offline hooks persist)."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pattern', default='test_*.py')
    args = parser.parse_args()
    report = ROOT / 'runtime/test-evidence'
    report.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'scripts') + os.pathsep + str(ROOT / 'tests/unit'),
               PYTHONDONTWRITEBYTECODE='1')
    modules = sorted((ROOT / 'tests/unit').glob(args.pattern))
    if not modules:
        parser.error('No test modules matched')
    results = []
    for module in modules:
        command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests/unit', '-p', module.name]
        try:
            run = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
            log, code = run.stdout + run.stderr, run.returncode
        except subprocess.TimeoutExpired:
            log, code = 'Test process exceeded 120 seconds.\n', 124
        (report / (module.stem + '.log')).write_text(log, encoding='utf-8')
        count = re.search(r'Ran (\d+) tests?', log)
        tests = int(count.group(1)) if count else 0
        skipped_match = re.search(r'skipped=(\d+)', log)
        skipped = int(skipped_match.group(1)) if skipped_match else 0
        status = 'PASS' if code == 0 and tests else 'FAIL'
        results.append({'module': module.name, 'tests': tests, 'status': status, 'exit_code': code, 'skipped': skipped})
        print(f'{status} {module.name}: {tests} tests', flush=True)
    summary = {'schema': 'psirt-package-tests/1', 'generated_at': datetime.now(timezone.utc).isoformat(),
               'tests': sum(r['tests'] for r in results), 'skipped': sum(r['skipped'] for r in results), 'modules': results,
               'passed': all(r['status'] == 'PASS' for r in results)}
    (report / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f"{summary['tests']} tests; all passed: {summary['passed']}; evidence: {report.relative_to(ROOT)}")
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
