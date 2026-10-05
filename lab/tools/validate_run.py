#!/usr/bin/env python3
"""Read-only validation of one real lab run against Azure Monitor Logs.

Runs actual KQL, checks required source telemetry, compares declared rule hits,
and looks for EventKey-matched Sentinel alerts. Does NOT execute Windows tests,
change Azure resources, deploy rules, claim negative alert absence, or create incidents.
Local unit tests test this Python tool only; they do not execute KQL or Sentinel.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'ps_positive': ['DVL-001'], 'ps_negative': [],
    'task_positive': ['DVL-002'], 'task_negative': [],
    'admin_positive': ['DVL-003', 'DVL-006'], 'admin_negative': [],
    'runkey_positive': ['DVL-004'], 'runkey_negative': [],
    'decode_positive': ['DVL-005'], 'decode_negative': [],
    'chain_positive': ['DVL-003', 'DVL-006'], 'chain_negative': [],
}

def utc(value: str) -> datetime:
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('UTC timestamps must include Z or an explicit timezone offset.')
    return d.astimezone(timezone.utc)

def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat().replace('+00:00','Z')

def validate_manifest(m: dict[str, Any]) -> None:
    required = ('run_id','case_id','computer','started_utc','ended_utc',
                'execution_ok','cleanup_ok','anchor','expected_rule_ids','telemetry_requirements')
    for key in required:
        if key not in m:
            raise ValueError(f'Manifest is missing {key}')
    if m['case_id'] not in EXPECTED:
        raise ValueError('Unknown case ID')
    if sorted(m['expected_rule_ids']) != sorted(EXPECTED[m['case_id']]):
        raise ValueError('Manifest expectations differ from the declared case catalog')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', m['computer']):
        raise ValueError('Invalid computer name')
    if not isinstance(m['anchor'],str) or not 1 <= len(m['anchor']) <= 4096:
        raise ValueError('Invalid evidence anchor')
    if not isinstance(m['execution_ok'],bool) or not isinstance(m['cleanup_ok'],bool):
        raise ValueError('Execution and cleanup values must be JSON booleans')
    if utc(m['ended_utc']) < utc(m['started_utc']):
        raise ValueError('End time precedes start time')
    if not m['telemetry_requirements'] and m['execution_ok']:
        raise ValueError('Successful runs must declare required source telemetry')

def render_query(text: str, m: dict[str, Any]) -> str:
    begin = utc(m['started_utc']) - timedelta(seconds=1)
    end = utc(m['ended_utc']) + timedelta(seconds=1)
    replacement = (f'// DVL PARAMETERS BEGIN\nlet StartTime = datetime({iso(begin)});\n'
                   f'let EndTime = datetime({iso(end)});\n'
                   f'let HostFilter = {json.dumps(m["computer"])};\n// DVL PARAMETERS END')
    pattern = r'// DVL PARAMETERS BEGIN.*?// DVL PARAMETERS END'
    if len(re.findall(pattern, text, flags=re.S)) != 1:
        raise ValueError('Expected exactly one parameter block')
    text = re.sub(pattern, lambda _:replacement, text, flags=re.S)
    # Attribution belongs in the validation harness, NOT in deployed detection logic.
    return text.rstrip() + '\n| where Evidence contains ' + json.dumps(m['anchor']) + '\n'

def missing_requirements(rows: list[dict], requirements: list[dict]) -> list[dict]:
    missing = []
    for req in requirements:
        found = any(
            row.get('SourceFamily') == req['source_family']
            and int(row.get('EventID',-1)) == int(req['event_id'])
            and (not req.get('image_suffix') or
                 str(row.get('Image','')).lower().endswith(req['image_suffix'].lower()))
            for row in rows)
        if not found:
            missing.append(req)
    return missing

def assess(m: dict, raw: list[dict], matches: dict[str,list[dict]], alerts: list[dict]) -> dict:
    missing = missing_requirements(raw,m['telemetry_requirements'])
    observed = sorted(rule for rule,rows in matches.items() if rows)
    expected = sorted(m['expected_rule_ids'])
    correlated = {}
    unresolved_keys = []
    for rule,rows in matches.items():
        for row in rows:
            key = str(row.get('EventKey',''))
            found = sorted({str(a['SystemAlertId']) for a in alerts
                if key and key in json.dumps(a.get('ExtendedProperties',{}),default=str)
                and str(a.get('AlertName','')).startswith(rule) and a.get('SystemAlertId')})
            if found:
                correlated[key] = found
            elif key:
                unresolved_keys.append(key)
    if not m['execution_ok']:
        status='EXECUTION_FAILED'
    elif not m['cleanup_ok']:
        status='CLEANUP_FAILED'
    elif missing:
        status='MISSING_REQUIRED_TELEMETRY'
    elif observed != expected:
        status='QUERY_MISMATCH'
    elif not expected:
        status='NEGATIVE_QUERY_PASS_ALERT_REVIEW_REQUIRED'
    elif unresolved_keys or any(not row.get('EventKey') for rs in matches.values() for row in rs):
        status='QUERY_PASS_ALERT_PENDING_OR_UNRESOLVED'
    else:
        status='POSITIVE_QUERY_AND_ALERT_VALIDATED'
    return {
        'status': status,'expected_rule_ids':expected,'observed_rule_ids':observed,
        'missing_telemetry_requirements':missing,
        'unique_matching_event_counts':{r:len({x.get('EventKey') for x in rs}) for r,rs in matches.items()},
        'event_key_to_alert_ids':correlated,'unresolved_event_keys':sorted(set(unresolved_keys)),
        'incident_review':'MANUAL: open the matching alert in the portal and record incident membership.',
        'negative_review':'A zero-row control requires healthy scheduled-rule execution and a completed observation window; absence alone is not a pass.',
    }

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--workspace',required=True,help='Log Analytics workspace ID (GUID), not Azure resource ID')
    p.add_argument('--out',type=Path,required=True,help='A NEW output directory for this observation')
    args=p.parse_args()
    created_output=False
    try:
        m=json.loads(args.manifest.read_text(encoding='utf-8-sig'))
        validate_manifest(m)
        if args.out.exists():
            raise ValueError('Output directory exists. Use a new directory to preserve earlier observations.')
        args.out.mkdir(parents=True)
        created_output=True
        if not m['execution_ok'] or not m['cleanup_ok']:
            result={'run_id':m['run_id'],'status':'INVALID_RUN_EXECUTION_OR_CLEANUP_FAILED','manifest':m}
            (args.out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result,indent=2)); return 2
        # Optional dependencies are imported only for a live query, not for local unit tests.
        from azure.identity import AzureCliCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus
        credential=AzureCliCredential()
        client=LogsQueryClient(credential)
        start=utc(m['started_utc'])-timedelta(seconds=1)
        end=utc(m['ended_utc'])+timedelta(seconds=1)
        query_hashes={}
        def query(text: str, name: str, span: tuple[datetime,datetime]) -> list[dict]:
            (args.out/(name+'.kql')).write_text(text,encoding='utf-8')
            query_hashes[name]=hashlib.sha256(text.encode()).hexdigest()
            response=client.query_workspace(args.workspace,text,timespan=span,server_timeout=120)
            if response.status != LogsQueryStatus.SUCCESS:
                raise RuntimeError(f'{name}: partial/error response, not a valid zero-result test: {response.partial_error}')
            rows=[]
            for table in response.tables:
                rows.extend(dict(zip(table.columns,row)) for row in table.rows)
            (args.out/(name+'.json')).write_text(json.dumps(rows,indent=2,default=str)+'\n',encoding='utf-8')
            return rows
        raw=query(render_query((ROOT/'queries/00-raw-evidence.kql').read_text(),m),'raw',(start,end))
        matches={}
        for d in json.loads((ROOT/'config/detections.json').read_text()):
            matches[d['id']]=query(render_query((ROOT/'queries'/d['file']).read_text(),m),d['id'],(start,end))
        alert_error=None
        try:
            alerts=query('SecurityAlert\n| where AlertName startswith "DVL-"\n'
                '| summarize arg_max(TimeGenerated, *) by SystemAlertId\n'
                '| project TimeGenerated, AlertName, SystemAlertId, ExtendedProperties, Entities\n',
                'alerts',(start,datetime.now(timezone.utc)+timedelta(minutes=1)))
        except Exception as exc:
            alerts=[];alert_error=str(exc)
        result=assess(m,raw,matches,alerts)
        result.update({'run_id':m['run_id'],'case_id':m['case_id'],'observed_at_utc':iso(datetime.now(timezone.utc)),
            'query_hashes':query_hashes,'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            'alert_query_error':alert_error,'executed_in':'user Azure workspace via read-only API queries'})
        (args.out/'summary.json').write_text(json.dumps(result,indent=2,default=str)+'\n',encoding='utf-8')
        print(json.dumps(result,indent=2,default=str))
        client.close();credential.close()
        return 0 if result['status']=='POSITIVE_QUERY_AND_ALERT_VALIDATED' else 2
    except Exception as exc:
        error={'status':'TOOL_OR_QUERY_ERROR','error':str(exc)}
        # Never overwrite an existing report if the initial output-directory check failed.
        if created_output:
            (args.out/'error.json').write_text(json.dumps(error,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(error,indent=2),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
