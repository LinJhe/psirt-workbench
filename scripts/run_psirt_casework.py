#!/usr/bin/env python3
"""Open/stop a single-user local workbench. Never refreshes company sources."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from psirt_casework.service import DEFAULT, start, stop, inspect, public, serve, rebuild, ServiceVersionMismatch

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['start','stop','status','serve','rebuild'])
    parser.add_argument('--output-dir',type=Path,default=DEFAULT)
    parser.add_argument('--result-file',type=Path)
    args=parser.parse_args();receipt=None
    if args.result_file:
        from psirt_daily.pipeline import no_symlinks
        no_symlinks(args.result_file);receipt=args.result_file.open('x')
    try:
        if args.action=='serve':serve(args.output_dir);return 0
        if args.action=='start':result=start(args.output_dir)
        elif args.action=='stop':result=stop(args.output_dir)
        elif args.action=='rebuild':result=rebuild(args.output_dir)
        else:
            r=inspect(args.output_dir);result=public(r,True) if r else {'exit_code':1,'running':False}
    except ServiceVersionMismatch as exc:
        result={'exit_code':2,'error_type':type(exc).__name__,'error_code':exc.code,
                'completed':False,'message':'程式已更新；請先停止舊工作台服務，再重新開啟。已保存紀錄保留，未刷新來源。'}
    except Exception as exc:
        result={'exit_code':2,'error_type':type(exc).__name__,'completed':False}
    if receipt:
        with receipt:json.dump(result,receipt,ensure_ascii=False)
    print(json.dumps(result,ensure_ascii=False))
    return result.get('exit_code',0)

if __name__=='__main__':raise SystemExit(main())
