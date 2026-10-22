#!/usr/bin/env python3
"""Guest user commands. No provider keys, model calls, or owner administration."""
import argparse
import json
import os
import re
import runpy
import sys
import urllib.error
import urllib.request
import uuid


def request_more(args):
    parser=argparse.ArgumentParser(prog='codex-api team request',description='Ask the organization owner for more of today\'s shared quota.')
    parser.add_argument('--group',required=True,);parser.add_argument('--tokens',required=True)
    options=parser.parse_args(args)
    if not re.fullmatch(r'[1-9][0-9]{0,12}',options.tokens):parser.error('--tokens must be a positive whole number.')
    amount=int(options.tokens)
    try:policy=runpy.run_path('/etc/codex-api/preferences.py')['model_policy']()
    except (OSError,ValueError,KeyError):
        print('The protected quota policy is unavailable. Run codex-api doctor in the host terminal.',file=sys.stderr);return 1
    ceilings={g:r['daily_tokens']*(100-policy['safety_margin_percent'])//100 for g,r in policy['pools'].items()}
    if options.group not in ceilings or amount>ceilings[options.group]:parser.error('--group and --tokens must fit the approved daily pools.')
    token=os.environ.get('CODEX_GATEWAY_TOKEN','')
    if not token:
        print('API Codex quota: gateway credential is unavailable.',file=sys.stderr);return 1
    request_id=uuid.uuid4().hex
    payload={'group':options.group,'amount':amount,'request_id':request_id}
    request=urllib.request.Request('http://host.docker.internal:49187/v1/quota/request',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request,timeout=10) as response:data=response.read(32769)
        if len(data)>32768:raise ValueError()
        result=json.loads(data)
        if not isinstance(result,dict) or not isinstance(result.get('request_id'),str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,80}',result['request_id']) or result.get('state') not in {'pending','approved'}:raise ValueError()
        accepted_amount=result.get('amount',amount)
        if type(accepted_amount) is not int or not 0<accepted_amount<=ceilings[options.group]:raise ValueError()
        prefix='Existing quota request' if result.get('replayed') is True else 'Quota request submitted'
        suffix='The owner decides; your limit is unchanged until approval.' if result['state']=='pending' else 'This request has already been approved.'
        print(prefix+': '+result['request_id']+' (Group '+options.group+', '+str(accepted_amount)+' tokens; '+result['state']+'). '+suffix)
        return 0
    except urllib.error.HTTPError as error:
        if 400<=error.code<500:
            try:
                body=error.read(16385)
                details=json.loads(body) if len(body)<=16384 else {}
                code=details.get('error',{}).get('code')
            except (OSError,ValueError,TypeError,AttributeError):code=None
            messages={'endpoint_disabled':'Quota requests are available only in shared mode.',
                      'team_request_invalid':'Choose an approved pool and a valid positive whole token amount.',
                      'team_member_revoked':'Shared access was revoked. Contact the organization owner.',
                      'team_operation_conflict':'This request conflicts with an existing request. Check with the owner.'}
            print(messages.get(code,'Quota request was rejected. Run codex-api doctor in the host terminal.'),file=sys.stderr)
        else:print('Quota request could not be confirmed. Request ID: '+request_id+'. Check with the owner before submitting again.',file=sys.stderr)
        return 1
    except (OSError,ValueError,KeyError,TypeError,urllib.error.URLError):
        print('Quota request could not be confirmed. Request ID: '+request_id+'. Check with the owner before submitting again.',file=sys.stderr)
        return 1


def main(args):
    if args[:2]==['team','request']:return request_more(args[2:])
    if args in (['extensions','list'], ['extensions','list','--json']):
        try:
            skills=runpy.run_path('/etc/codex-api/preferences.py')['managed_extensions']()
            if '--json' in args:print(json.dumps({'version':1,'skills':skills},indent=2))
            elif not skills:print('No managed skills are approved.')
            else:
                for skill in skills:print('$'+skill['name']+' | '+skill['description'])
            return 0
        except (OSError,ValueError,KeyError,TypeError):
            print('Managed skill verification failed. Return to the host terminal and run codex-api extensions verify.',file=sys.stderr)
            return 1
    if args not in ([], ['usage'], ['usage','--json'], ['help'], ['--help']):
        print('Guest command supports: codex-api usage [--json], codex-api extensions list [--json], codex-api team request --group POOL --tokens N. Use the host terminal for maintenance.', file=sys.stderr)
        return 2
    if args in (['help'], ['--help']):
        print('codex-api usage [--json] — read local daily quota without a model request.\ncodex-api extensions list [--json] — show approved managed skills.\ncodex-api team request --group POOL --tokens N — ask the shared organization owner for more quota.')
        return 0
    token = os.environ.get('CODEX_GATEWAY_TOKEN', '')
    if not token:
        print('API Codex quota: gateway credential is unavailable.', file=sys.stderr); return 1
    request = urllib.request.Request('http://host.docker.internal:49187/v1/quota', headers={'Authorization':'Bearer '+token})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            data = response.read(32769)
        if len(data) > 32768: raise ValueError()
        result = json.loads(data)
        lines = result['usage_lines']
        if not isinstance(lines,list) or not 1<=len(lines)<=8 or not all(isinstance(line,str) and line.isascii() and '\n' not in line and '\r' not in line for line in lines): raise ValueError()
        pools=result.get('daily_pools',{})
        if not isinstance(pools,dict) or len(pools)!=len(lines) or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,15}',g) for g in pools):raise ValueError()
        if any(not line.startswith(g+' (') for g,line in zip(pools,lines)):raise ValueError()
        print(json.dumps(result, indent=2) if '--json' in args else '\n'.join(lines))
        return 0
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        print('API Codex quota: local gateway is unavailable; check codex-api doctor in the host terminal.', file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main(sys.argv[1:]))
