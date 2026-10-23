"""Offline review hints, never a security certification or remote scanner."""
import hashlib
import re
from guard import canonical

VERSION=1
RULES=(
 ('instruction_override','high',r'(?i)ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|bypass\s+(?:the\s+)?(?:approval|sandbox|quota|permission)', 'Attempts to override instruction or permission boundaries.'),
 ('credential_path','high',r'(?i)(?:\.ssh/|\.aws/|\.codex/auth|\.env\b|cookies\.sqlite|login\s+keychain)', 'References sensitive credential or browser storage.'),
 ('download_execute','high',r'(?i)(?:curl|wget)[^\n]{0,500}\|\s*(?:sh|bash|python)|eval\s*\(|exec\s*\(.*(?:decode|base64)', 'Downloads or decodes content for execution.'),
 ('destructive_operation','high',r'(?i)rm\s+-[a-z]*r[a-z]*f\b|git\s+(?:reset\s+--hard|clean\s+-[a-z]*f)|shutil\.rmtree', 'Can delete files or discard existing work.'),
 ('environment_inventory','medium',r'(?i)\b(?:printenv|os\.environ|process\.env|env\s*\|)', 'Inspects process environment; check for credential exposure.'),
 ('network_transfer','medium',r'(?i)\b(?:requests\.(?:post|put)|fetch\s*\(|curl\s|wget\s|urllib\.request)', 'Makes network requests; references do not grant network permission.'),
)


def scan(files, bundle_digest):
    findings=[]
    for path,raw in sorted(files.items()):
        text=raw.decode('utf-8')
        for rule,severity,pattern,message in RULES:
            for match in list(re.finditer(pattern,text))[:16]:
                findings.append({'file':path,'line':text.count('\n',0,match.start())+1,'rule':rule,'severity':severity,'message':message})
    value={'version':VERSION,'rules_digest':hashlib.sha256(canonical(RULES)).hexdigest(),'bundle_digest':bundle_digest,
           'findings':findings,'requires_risk_acknowledgement':any(f['severity']=='high' for f in findings),
           'provider_requests':0,'certifies_safety':False}
    value['review_digest']=hashlib.sha256(canonical(value)).hexdigest()
    return value
