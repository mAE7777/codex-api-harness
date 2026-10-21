"""Read-only triage plus explicit, stopped-environment reconciliation receipts."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from guard import Denied, Ledger, atomic_json, read_quota, readonly_database


def inspect(root):
    profile = json.loads((root/'verification.json').read_text()).get('openai', {})
    result = {'verified':False, 'requests':[], 'safety_stop':(root/'state/safety-stop.json').exists()}
    try:
        read_quota(root/'state', profile.get('daily_token_limits', {}))
        result['verified'] = True
    except Denied as error: result['state_error'] = error.code or 'quota_state_unavailable'
    with readonly_database(root/'state') as db:
        db.execute('BEGIN')
        rows = db.execute("SELECT id,scope,period,reserved,phase FROM requests WHERE phase IN ('reserved','unknown','rejected') ORDER BY created").fetchall()
        result['requests'] = [dict(zip(('id','scope','period','reserved_tokens','phase'), row)) for row in rows]
    return result


def template(root, request_id):
    view = inspect(root)
    if not view['verified']: raise Denied('The ledger must verify before a reconciliation receipt can be prepared')
    matches = [row for row in view['requests'] if row['id'] == request_id]
    if len(matches) != 1: raise Denied('No matching unconfirmed request')
    row = matches[0]
    receipt = {'version':1, 'resolution_id':uuid.uuid4().hex, 'request_id':request_id,
               'expected_phase':row['phase'], 'expected_reserved_tokens':row['reserved_tokens'],
               'action':'record_actual', 'actual_tokens':None,
               'evidence':{'kind':'operator_verified_provider_usage', 'reference':'REPLACE_WITH_VERIFIED_EVIDENCE_REFERENCE', 'request_finished':False}}
    directory = root/'reconciliation'
    if directory.is_symlink(): raise Denied('Unexpected reconciliation directory')
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory/('review-'+receipt['resolution_id']+'.json')
    atomic_json(path, receipt)
    return path


def apply(root, filename):
    path = Path(filename)
    directory = root/'reconciliation'
    if directory.is_symlink() or path.parent.resolve() != directory.resolve():
        raise Denied('Use a receipt in the private host reconciliation directory, outside the shared workspace')
    def pairs(items):
        output = {}
        for key,value in items:
            if key in output: raise Denied('Duplicate receipt field')
            output[key] = value
        return output
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 16384 or info.st_mode & 0o077:
            raise Denied('Receipt must be an owner-only private host file (0600), not a symlink')
        content = source.read(16385)
        if len(content) > 16384: raise Denied('Receipt exceeds the size limit')
    plan = json.loads(content, object_pairs_hook=pairs)
    with (root/'session.lock').open('a+b') as lease:
        try: fcntl.flock(lease, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Denied('Exit the active API Codex session before applying a receipt')
        if not (root/'paused').exists() or (root/'gateway-process.json').exists():
            raise Denied('Run codex-api stop before applying a receipt; no usage was changed')
        ledger = Ledger(root/'state')
        try: return ledger.reconcile(plan)
        finally: ledger.close()


def command(root, args):
    parser = argparse.ArgumentParser(prog='codex-api reconcile')
    parser.add_argument('--json', action='store_true')
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('--template', metavar='REQUEST_ID')
    operation.add_argument('--apply', metavar='PRIVATE_RECEIPT')
    parser.add_argument('--dry-run', action='store_true', help='inspect only; this is the default')
    parsed = parser.parse_args(args)
    if parsed.dry_run and parsed.apply: raise Denied('--dry-run cannot be combined with --apply')
    if parsed.template:
        if parsed.dry_run: raise Denied('Use --template without --dry-run to create a private review file')
        path = template(root, parsed.template)
        print('Review file: '+str(path))
        print('Fill confirmed usage and evidence, then run codex-api reconcile --apply FILE. Never place keys or prompts in evidence.')
        return {}
    result = apply(root, parsed.apply) if parsed.apply else inspect(root)
    if parsed.json: print(json.dumps(result, indent=2))
    elif parsed.apply:
        print('Reconciliation '+('applied.' if result['applied'] else 'already applied; usage was not counted twice.'))
        if result.get('safety_stop_preserved'): print('The usage safety stop remains; investigate the count discrepancy before resuming.')
    else:
        print('Reconciliation: read-only; no provider requests or accounting changes.')
        if not result['verified']: print('Ledger verification: unavailable ['+result.get('state_error','quota_state_unavailable')+']; no automatic repair.')
        if not result['requests']: print('No unconfirmed requests.')
        for row in result['requests']:
            print(f"{row['id']} | {row['scope']} | {row['period']} | {row['phase']} | {row['reserved_tokens']:,} tokens held")
        if result['requests']: print('Create a private review file with: codex-api reconcile --template REQUEST_ID')
        if result['safety_stop']: print('A usage safety stop is present. This command does not remove it automatically.')
    return result
