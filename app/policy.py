"""One owner-approved model, quota and service-tier contract; no account discovery.

This module is also shipped read-only to the guest. It never reads credentials.
Legacy constants exist only to interpret pre-policy installations and opt-in presets.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_TOKENS = 10**12
MAX_POOLS = 8
TIERS = {'default', 'fast', 'flex', 'ultrafast'}
EFFORTS = {'none','minimal','low','medium','high','xhigh','max','ultra'}
LEGACY_MODELS = {'gpt-6-astra':'A','gpt-6.1-sol':'A','gpt-6-luna':'A','gpt-5.6-terra':'B','gpt-5.6-luna':'B'}
LEGACY_LIMITS = {'A':237500,'B':2375000}
LEGACY_LABELS = {'A':'6.1 Sol / 6 Astra / 6 Luna','B':'5.6 Terra / 5.6 Luna'}

class PolicyError(ValueError): pass

def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def digest(value): return hashlib.sha256(canonical(validate(value))).hexdigest()

def fail(message): raise PolicyError(message)

def integer(value, low, high, name):
    if type(value) is not int or not low<=value<=high:fail(name+' must be an integer between '+str(low)+' and '+str(high)+'.')
    return value

def tier(value):
    # Never inherit a project's potentially chargeable auto default.
    if value=='priority':return 'fast'
    if not isinstance(value,str) or value not in TIERS:fail('Choose default (Standard), fast, flex, or ultrafast; auto and unknown tiers are disabled.')
    return value

def validate(value, *, allow_empty=False):
    keys={'version','reset','safety_margin_percent','warning_percent','pools','models','defaults'}
    if not isinstance(value,dict) or set(value)!=keys or type(value['version']) is not int or value['version']!=1:fail('Invalid policy schema or unknown policy field.')
    out=copy.deepcopy(value)
    if out['reset']!='daily_utc':fail('Only daily UTC budgets are supported; do not substitute a monthly or local-time allowance.')
    margin=integer(out['safety_margin_percent'],0,50,'Safety margin')
    integer(out['warning_percent'],1,99,'Warning percentage')
    pools,models,defaults=out['pools'],out['models'],out['defaults']
    if allow_empty and pools=={} and models=={} and defaults=={}:return out
    if not isinstance(pools,dict) or not 1<=len(pools)<=MAX_POOLS:fail('Choose one to eight quota pools.')
    for group,row in pools.items():
        if not isinstance(group,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,15}',group) or group=='metered':fail('Invalid quota pool identifier.')
        if not isinstance(row,dict) or set(row)!={'label','daily_tokens'}:fail('Each pool needs a label and its actual daily_tokens allowance.')
        if not isinstance(row['label'],str) or not 1<=len(row['label'])<=96 or not row['label'].isascii() or any(ord(c)<32 for c in row['label']):fail('Pool labels must be short printable English text.')
        n=integer(row['daily_tokens'],1,MAX_TOKENS,'Daily token allowance')
        if n*(100-margin)//100<1:fail('The margin leaves no usable tokens.')
    if not isinstance(models,dict) or not 1<=len(models)<=32:fail('Choose one to 32 approved Responses/local-tool models.')
    for name,row in models.items():
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',name):fail('Invalid model identifier.')
        if not isinstance(row,dict) or set(row)!={'pool','context_window','max_output_tokens','reasoning_efforts','service_tiers','reference'}:fail('Each model needs its pool and reviewed Responses/local-tool capabilities.')
        if not isinstance(row['pool'],str) or row['pool'] not in pools:fail('Every model must belong to an existing quota pool.')
        integer(row['context_window'],1024,10**7,'Context window')
        integer(row['max_output_tokens'],1,min(row['context_window'],10**6),'Model output limit')
        efforts=row['reasoning_efforts'];tiers=row['service_tiers']
        if not isinstance(efforts,list) or not efforts or any(not isinstance(e,str) or e not in EFFORTS for e in efforts) or len(set(efforts))!=len(efforts):fail('Invalid model reasoning efforts.')
        if not isinstance(tiers,list) or not tiers or any(not isinstance(t,str) for t in tiers):fail('Invalid model service tiers.')
        row['service_tiers']=[tier(t) for t in tiers]
        if len(set(row['service_tiers']))!=len(tiers):fail('Duplicate service tier or priority alias.')
        ref=row['reference']
        if not isinstance(ref,str) or len(ref)>512 or not re.fullmatch(r'https://(?:developers\.openai\.com|platform\.openai\.com)/[A-Za-z0-9_./?#=&%+-]+',ref):fail('Provide the official model capability reference; availability is still checked by the provider.')
    if {m['pool'] for m in models.values()}!=set(pools):fail('Every pool must have at least one selected model.')
    if not isinstance(defaults,dict) or set(defaults)!={'model','reasoning_effort','service_tier','output_token_cap','request_deadline_seconds'}:fail('Invalid policy defaults.')
    if not isinstance(defaults['model'],str) or defaults['model'] not in models:fail('Default model is outside the approved model list.')
    if not isinstance(defaults['reasoning_effort'],str) or defaults['reasoning_effort'] not in models[defaults['model']]['reasoning_efforts']:fail('Default reasoning effort is unsupported by the selected model.')
    defaults['service_tier']=tier(defaults['service_tier'])
    if any(defaults['service_tier'] not in m['service_tiers'] for m in models.values()):fail('The selected service tier must be reviewed and supported for every selected model. Remove incompatible models or select another tier.')
    integer(defaults['output_token_cap'],1,min(m['max_output_tokens'] for m in models.values()),'Output reservation cap')
    integer(defaults['request_deadline_seconds'],30,900,'Request deadline')
    return out

def empty():
    return {'version':1,'reset':'daily_utc','safety_margin_percent':5,'warning_percent':90,'pools':{},'models':{},'defaults':{}}

def limits(policy):
    p=validate(policy);return {g:r['daily_tokens']*(100-p['safety_margin_percent'])//100 for g,r in p['pools'].items()}

def labels(policy):return {g:r['label'] for g,r in validate(policy)['pools'].items()}
def model_pools(policy):return {m:r['pool'] for m,r in validate(policy)['models'].items()}
def usage_lines(policy,pools):
    return [f"{g} ({p['label']}): {pools[g]['remaining']:,} / {pools[g]['limit']:,} tokens remaining" for g,p in validate(policy)['pools'].items()]

def legacy(receipt=None):
    receipt=receipt or {};p=empty();p['pools']={g:{'label':LEGACY_LABELS[g],'daily_tokens':(receipt.get('daily_token_limits',LEGACY_LIMITS).get(g,LEGACY_LIMITS[g])*100+94)//95} for g in LEGACY_LIMITS}
    for name,group in LEGACY_MODELS.items():
        efforts=['low','medium','high','xhigh','max']+([] if name in {'gpt-6-luna','gpt-5.6-luna'} else ['ultra'])
        p['models'][name]={'pool':group,'context_window':272000,'max_output_tokens':16384,'reasoning_efforts':efforts,'service_tiers':['default'],'reference':'https://developers.openai.com/api/docs/models/'+name}
    p['defaults']={'model':'gpt-5.6-terra','reasoning_effort':'medium','service_tier':'default','output_token_cap':receipt.get('output_token_cap',16384),'request_deadline_seconds':600}
    return validate(p)

def recommended():
    # A proposal, never an installed allowance or proof of account access.
    p=empty();p['pools']={'Daily':{'label':'Selected models','daily_tokens':100000}}
    p['models']={'gpt-6.1-sol':{'pool':'Daily','context_window':272000,'max_output_tokens':128000,'reasoning_efforts':['low','medium','high','xhigh','max'],'service_tiers':['default','fast','flex','ultrafast'],'reference':'https://developers.openai.com/api/docs/models/gpt-6.1-sol'}}
    p['defaults']={'model':'gpt-6.1-sol','reasoning_effort':'medium','service_tier':'default','output_token_cap':16384,'request_deadline_seconds':600}
    return validate(p)

def read_json(path, *, private=False, maximum=131072):
    path=Path(path)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as src:
        info=os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>maximum or (private and (info.st_uid!=os.getuid() or info.st_mode&0o077)):fail('Policy input must be a bounded ordinary file with safe permissions.')
        def pairs(items):
            out={}
            for k,v in items:
                if k in out:fail('Duplicate policy field.')
                out[k]=v
            return out
        try:return json.loads(src.read(maximum+1),object_pairs_hook=pairs,parse_constant=lambda _:fail('Non-finite policy number.'))
        except (UnicodeError,ValueError) as e:raise PolicyError('Policy JSON is invalid.') from e

def load(root, *, allow_empty=False, allow_pending=False):
    root=Path(root)
    if not allow_pending and any((root/n).exists() or (root/n).is_symlink() for n in ('policy-pending.json','policy-render-pending.json')):fail('A policy change is pending. Repeat the reviewed policy command or run prepare to finish rendering; no requests are allowed.')
    client=root/'team-client.json'
    if client.exists() or client.is_symlink():
        config=read_json(client,private=True)
        return validate(config['policy'],allow_empty=allow_empty) if 'policy' in config else legacy()
    verification=read_json(root/'verification.json',private=True)
    receipt=verification.get('openai',{})
    if 'policy' in receipt:return validate(receipt['policy'],allow_empty=allow_empty)
    # Backward-compatible interpretation only; never overwrite legacy state.
    return from_receipt(receipt)

def from_receipt(receipt):
    if 'policy' in receipt:return validate(receipt['policy'])
    old=receipt.get('daily_token_limits',LEGACY_LIMITS)
    if not isinstance(old,dict) or set(old)!=set(LEGACY_LIMITS) or any(type(n) is not int or not 0<n<=LEGACY_LIMITS[g] for g,n in old.items()):fail('Invalid configured daily limit in the legacy profile; use a reviewed policy change.')
    return legacy(receipt)

def guest(path=Path('/etc/codex-api/runtime-policy.json')):
    return validate(read_json(path))

def render(root, kit_directory=None, *, policy=None):
    """Generate every guest choice from the same policy. No code execution."""
    root=Path(root);kit=Path(kit_directory) if kit_directory else (root/'kit').resolve(strict=True)
    p=validate(policy) if policy is not None else load(root)
    template=json.loads((kit/'model-template.json').read_text())
    models=[]
    for i,(name,row) in enumerate(p['models'].items()):
        item=copy.deepcopy(template)
        item.update(slug=name,display_name=name,description='Owner-approved API model',priority=i,
            context_window=row['context_window'],max_context_window=row['context_window'],
            default_reasoning_level=p['defaults']['reasoning_effort'] if p['defaults']['reasoning_effort'] in row['reasoning_efforts'] else row['reasoning_efforts'][0],
            supported_reasoning_levels=[{'effort':e,'description':e.title()+' reasoning'} for e in row['reasoning_efforts']])
        models.append(item)
    base=(kit/'config.toml').read_text()
    values={'model':p['defaults']['model'],'model_reasoning_effort':p['defaults']['reasoning_effort'],'service_tier':p['defaults']['service_tier']}
    for key,value in values.items():
        pattern=r'^'+key+r'\s*=.*$'
        if len(re.findall(pattern,base,re.M))!=1:fail('The guest configuration template has an ambiguous '+key+'.')
        base=re.sub(pattern,lambda _:key+' = '+json.dumps(value),base,flags=re.M)
    from guard import atomic_json
    atomic_json(kit/'models.json',{'models':models});atomic_json(kit/'runtime-policy.json',p)
    fd=os.open(kit/'config.toml',os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
    with os.fdopen(fd,'w') as out:out.write(base);out.flush();os.fsync(out.fileno())
    return digest(p)

def verify_guest(root):
    p=load(root);kit=Path(root)/'kit'
    if guest(kit/'runtime-policy.json')!=p:fail('Guest policy differs from host policy. Run codex-api prepare; no requests are allowed.')
    import tomllib
    config=tomllib.loads((kit/'config.toml').read_text());catalog=read_json(kit/'models.json')
    if any(config.get(k)!=p['defaults'][v] for k,v in [('model','model'),('model_reasoning_effort','reasoning_effort'),('service_tier','service_tier')]):fail('Guest defaults differ from the owner policy.')
    if [m.get('slug') for m in catalog.get('models',[])]!=list(p['models']):fail('Guest model catalog differs from the approved models.')
    for item in catalog['models']:
        row=p['models'][item['slug']]
        if item.get('context_window')!=row['context_window'] or item.get('max_context_window')!=row['context_window'] or [x.get('effort') for x in item.get('supported_reasoning_levels',[])]!=row['reasoning_efforts']:fail('Guest model capabilities differ from the owner policy.')
    return p
