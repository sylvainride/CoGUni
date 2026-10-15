"""GitHub Actions public-synthetic adapter; no credentials or target writer.

Provider context is trusted only inside the reviewed workflow. Local environment
variables are not an authenticator. Requests and result logs are PUBLIC. Actions
storage is ephemeral; durable local sessions use mission_cli separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from universal.core import GuardError
from universal.mission_cli import MissionClient
from universal.mission_contracts import _read, canonical, fingerprint

REQUEST = 'tests/fixtures_mvp_transport/request.json'
TARGETS = 'tests/fixtures_mvp_transport/targets'
_ALLOWED_DIFF = {REQUEST, TARGETS + '/synthetic-A/result.txt', TARGETS + '/synthetic-B/result.txt'}
_SHA = re.compile(r'[0-9a-f]{40}\Z')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, timeout=20)


def provider_context():
    required = {'GITHUB_REPOSITORY': 'sylvainride/CoGUni', 'GITHUB_REPOSITORY_ID': '1418009675',
                'GITHUB_REPOSITORY_OWNER_ID': '265171248', 'GITHUB_ACTOR_ID': '265171248',
                'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_EVENT_NAME': 'push'}
    if any(os.environ.get(k) != v for k, v in required.items()):
        raise GuardError('provider identity not authorized')
    ref, sha = os.environ.get('GITHUB_REF', ''), os.environ.get('GITHUB_SHA', '')
    if not ref.startswith('refs/heads/work/mvp-mission-transport-') or not _SHA.fullmatch(sha):
        raise GuardError('unqualified branch/source')
    run = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not run.isdigit() or not attempt.isdigit() or len(run) > 15 or len(attempt) > 4:
        raise GuardError('invalid provider run')
    if git('rev-parse', 'HEAD').decode().strip() != sha:
        raise GuardError('checkout differs from provider source')
    return {'repository_id': 1418009675, 'owner_id': 265171248, 'actor_id': 265171248,
            'request_commit': sha, 'ref': ref, 'provider_run_id': int(run), 'run_attempt': int(attempt)}


def _fetch_commit(sha):
    if type(sha) is not str or not _SHA.fullmatch(sha):
        raise GuardError('invalid code pin')
    try:
        git('cat-file', '-e', sha + '^{commit}')
    except subprocess.CalledProcessError:
        git('-c', 'core.hooksPath=/dev/null', 'fetch', '--no-tags', '--depth=1',
            'https://github.com/sylvainride/CoGUni.git', sha)


def verify_code_pin(request, context):
    pin = request['code_ref']
    _fetch_commit(pin)
    # A public request commit can change only fixture data relative to reviewed
    # code. It cannot inject a command, another workflow, source or owner policy.
    changed = git('diff', '--name-only', pin, context['request_commit']).decode().splitlines()
    if not set(changed) <= _ALLOWED_DIFF:
        raise GuardError('request commit changed executable source')
    if len(changed) > 3:
        raise GuardError('unbounded fixture change')
    # Both sides must retain ordinary files, never symlink/submodule targets.
    for target in _ALLOWED_DIFF - {REQUEST}:
        line = git('ls-tree', context['request_commit'], '--', target).decode()
        if not line.startswith('100644 blob '):
            raise GuardError('synthetic target is not ordinary text')


def verify_predecessor(predecessor, context, code_ref=None):
    if predecessor is None:
        return None
    if type(predecessor) is not dict or set(predecessor) != {'request_commit', 'provider_run_id', 'artifact_sha256'}:
        raise GuardError('invalid predecessor receipt')
    commit, run = predecessor['request_commit'], predecessor['provider_run_id']
    _fetch_commit(commit)
    if type(run) is not int or not 0 < run < 10**15:
        raise GuardError('invalid predecessor run')
    # Fixed official read-only endpoint; no token, arbitrary URI or redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open('https://api.github.com/repos/sylvainride/CoGUni/actions/runs/' + str(run), timeout=20) as response:
        data = response.read(131073)
    if len(data) > 131072:
        raise GuardError('provider reply too large')
    observed = json.loads(data)
    if (observed['head_sha'] != commit or observed['conclusion'] != 'success'
            or observed['status'] != 'completed'
            or observed['head_branch'] != context['ref'].removeprefix('refs/heads/')
            or observed['event'] != 'push' or observed['repository']['id'] != 1418009675
            or observed['actor']['id'] != 265171248
            or observed['path'] != '.github/workflows/ci.yml'):
        raise GuardError('predecessor CI source not qualified')
    with opener.open('https://api.github.com/repos/sylvainride/CoGUni/actions/runs/' + str(run) + '/jobs?per_page=100', timeout=20) as response:
        data = response.read(262145)
    if len(data) > 262144:
        raise GuardError('provider jobs reply too large')
    jobs = json.loads(data)
    if jobs['total_count'] != len(jobs['jobs']):
        raise GuardError('incomplete provider jobs')
    sandbox = [j for j in jobs['jobs'] if j['name'] == 'sandbox-runtime' and j['head_sha'] == commit and j['conclusion'] == 'success']
    if len(sandbox) != 1 or not any(step['name'] == 'Process an owner public synthetic mission on the qualified host' and step['status'] == 'completed' and step['conclusion'] == 'success' for step in sandbox[0]['steps']):
        raise GuardError('predecessor mission step not proven')
    old = _read(git('show', commit + ':' + REQUEST))
    first = old['request']
    if first['code_ref'] != code_ref:
        raise GuardError('predecessor executed different reviewed code')
    verify_code_pin(first, {**context, 'request_commit': commit})
    if first['envelope']['project']['id'] != 'synthetic-A':
        raise GuardError('predecessor is not project A')
    expected = first['payload'].upper() if first['action'] == 'uppercase' else hashlib.sha256(first['payload'].encode()).hexdigest()
    prior_target = git('show', commit + ':' + TARGETS + '/synthetic-A/result.txt')
    prior_sha = hashlib.sha256(prior_target).hexdigest()
    if prior_sha != first['envelope']['project']['base_version'] or hashlib.sha256(expected.encode()).hexdigest() == prior_sha:
        raise GuardError('A has no proven target change from admitted base')
    target = ROOT / TARGETS / 'synthetic-A' / 'result.txt'
    if target.is_symlink() or target.read_bytes() != expected.encode() or hashlib.sha256(expected.encode()).hexdigest() != predecessor['artifact_sha256']:
        raise GuardError('independent A target readback failed; B remains blocked')
    return {'provider_run_id': run, 'request_commit': commit,
            'owner_readback_sha256': predecessor['artifact_sha256'], 'state': 'ACCEPTED_SCOPED_PUBLIC_FIXTURE'}


def run(request_path, out):
    context = provider_context()
    if request_path != REQUEST:
        raise GuardError('only fixed public fixture path accepted')
    path = ROOT / REQUEST
    if not path.exists():
        result = {**context, 'state': 'NOT_SUBMITTED', 'chat_connected': False}
    else:
        if path.is_symlink() or path.stat().st_size > 16384:
            raise GuardError('invalid request file')
        packet = _read(path.read_bytes())
        if set(packet) != {'schema_version', 'request', 'predecessor'} or type(packet['schema_version']) is not int or packet['schema_version'] != 1:
            raise GuardError('invalid public request packet')
        req = packet['request']
        verify_code_pin(req, context)
        project = req['envelope']['project']['id']
        if (project == 'synthetic-A' and packet['predecessor'] is not None) or (project == 'synthetic-B' and packet['predecessor'] is None):
            raise GuardError('invalid two-mission dependency')
        predecessor = verify_predecessor(packet['predecessor'], context, req['code_ref'])
        with tempfile.TemporaryDirectory(prefix='coguni-public-mission-') as tmp:
            root = Path(tmp)
            targets = root / 'targets'; targets.mkdir(mode=0o700)
            for name in ('synthetic-A', 'synthetic-B'):
                (targets / name).mkdir()
                data = git('show', context['request_commit'] + ':' + TARGETS + '/' + name + '/result.txt')
                if len(data) > 1024:
                    raise GuardError('synthetic target size exceeded')
                (targets / name / 'result.txt').write_bytes(data)
            with MissionClient(root / 'state', targets, '265171248') as client:
                submitted = client.submit(req)
                completed = client.execute(project, req['envelope']['mission_id'])
                if completed['state'] != 'COMPLETED' or not completed['artifact']['accepted_for_gate']:
                    raise GuardError('isolated computation not verified')
                result = {**context, 'transport': 'GITHUB_ACTIONS_PUBLIC_SYNTHETIC',
                          'request_sha256': fingerprint(packet), 'predecessor': predecessor,
                          'result': completed, 'state': 'RESULT_READY',
                          'target_applied_by_coguni': False, 'chat_connected': False,
                          'persistent_service': False,
                          'persistence': 'REQUEST_GIT_AND_PROVIDER_LOG_RETENTION_ONLY',
                          'observed_unix': int(time.time())}
    out = Path(out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True) + '\n')
    print(json.dumps({'public_mission_receipt': result}, sort_keys=True))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', default=REQUEST)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    run(args.request, args.out)
