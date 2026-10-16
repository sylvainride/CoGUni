"""Manual, bounded research probe. Never qualifies P5 or authorizes a host.

Default: passive source/runtime observations only. --probe-exec explicitly
opts in to up to four short, fixed Python executions, with no descendants,
network, journal, guardian, core dumps or resident-memory stress. Stop after
the first failure. No raw child output, stderr, PIDs or paths leave this tool.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from tools.android_termux_p5_qualification import source_pins
from universal.host_config import implementation_sha256

TTL_SECONDS = 3600
CASES = ('baseline', 'postexec', 'preexec', 'enforcement')
# The controller is already running before AS is changed. os.execve replaces
# that SAME process: the parent always waits for its own direct child. These
# are research controls, not the production guardian or an equivalent sandbox.
READER = r'''
import os
os.write(1, b'{"stage":"READER_PYTHON"}\n')
import errno, json, mmap, resource, sys
mode, limit = sys.argv[1], int(sys.argv[2])
def emit(stage, **values):
    print(json.dumps(dict(stage=stage, **values)), flush=True)
def sample():
    with open('/proc/self/statm', 'rb') as source:
        fields = source.read(256).split()
    page = os.sysconf('SC_PAGE_SIZE')
    emit('MEMORY_SAMPLE', vm_kib=int(fields[0])*page//1024,
         rss_kib=int(fields[1])*page//1024)
try:
    sample()
    if mode == 'enforcement':
        control = mmap.mmap(-1, limit + os.sysconf('SC_PAGE_SIZE'),
                            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=0)
        control.close()
        emit('UNLIMITED_RESERVATION_OK')
    if mode in ('postexec', 'enforcement'):
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        if resource.getrlimit(resource.RLIMIT_AS) != (limit, limit):
            raise ValueError('limit readback differs')
        emit('AS_POSTEXEC_SET')
        sample()
    if mode == 'enforcement':
        # Reserve address space above the hard AS limit without touching pages.
        # ENOMEM is required; success is a failed control, never hidden by exit 0.
        try:
            mapping = mmap.mmap(-1, limit + os.sysconf('SC_PAGE_SIZE'),
                                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=0)
        except OSError as exc:
            emit('ENFORCEMENT_DENIED' if exc.errno == errno.ENOMEM else 'ERROR',
                 errno=exc.errno if type(exc.errno) is int and 0 <= exc.errno <= 4095 else 0)
            if exc.errno != errno.ENOMEM:
                raise SystemExit(2)
        else:
            mapping.close()
            emit('ENFORCEMENT_NOT_PROVEN')
            raise SystemExit(2)
    emit('DONE')
except (OSError, ValueError, MemoryError):
    emit('ERROR')
    raise SystemExit(2)
'''
CONTROLLER = r'''
import resource
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
import os, sys
resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
os.write(1, b'{"stage":"PROBE_START"}\n')
import json
with open('/proc/self/statm', 'rb') as source:
    fields = source.read(256).split()
page = os.sysconf('SC_PAGE_SIZE')
print(json.dumps(dict(stage='PREEXEC_SAMPLE', vm_kib=int(fields[0])*page//1024,
                      rss_kib=int(fields[1])*page//1024)), flush=True)
mode, limit, reader = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    if mode == 'preexec':
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        if resource.getrlimit(resource.RLIMIT_AS) != (limit, limit):
            raise OSError(0, 'limit readback differs')
    os.write(1, b'{"stage":"RLIMIT_SETUP"}\n')
    os.write(1, b'{"stage":"READER_EXEC"}\n')
    os.execve(sys.executable, [sys.executable, '-B', '-P', '-c', reader, mode, str(limit)], dict(os.environ))
except OSError as exc:
    code = exc.errno if type(exc.errno) is int and 0 <= exc.errno <= 4095 else 0
    os.write(1, ('{"stage":"ERROR","errno":%d}\n' % code).encode('ascii'))
    raise SystemExit(2)
'''


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate evidence key')
        result[key] = value
    return result


def classify(case, returncode, output, *, timed_out=False):
    """A missing/forged/partial trace is UNKNOWN, never cleanup evidence."""
    unknown = {'case': case, 'classification': 'UNKNOWN', 'stages': []}
    if timed_out:
        return {**unknown, 'classification': 'TIMEOUT'}
    if case not in CASES or type(returncode) is not int or type(output) is not bytes or len(output) > 4096:
        return unknown
    try:
        rows = [json.loads(line, object_pairs_hook=_unique_pairs) for line in output.splitlines()]
        if not rows:
            return unknown
        stages, samples = [], []
        expected = ['PROBE_START', 'PREEXEC_SAMPLE', 'RLIMIT_SETUP', 'READER_EXEC', 'READER_PYTHON', 'MEMORY_SAMPLE']
        if case == 'enforcement':
            expected += ['UNLIMITED_RESERVATION_OK']
        if case in ('postexec', 'enforcement'):
            expected += ['AS_POSTEXEC_SET', 'MEMORY_SAMPLE']
        if case == 'enforcement':
            expected += ['ENFORCEMENT_DENIED']
        expected += ['DONE']
        for row in rows:
            if type(row) is not dict or type(row.get('stage')) is not str:
                return unknown
            stage = row['stage']
            keys = {'stage'}
            if stage in ('PREEXEC_SAMPLE', 'MEMORY_SAMPLE'):
                keys |= {'vm_kib', 'rss_kib'}
                if any(type(row.get(k)) is not int or not 0 <= row[k] <= 2**60 for k in keys - {'stage'}):
                    return unknown
                samples.append({k: row[k] for k in ('stage', 'vm_kib', 'rss_kib')})
            elif stage == 'ENFORCEMENT_DENIED':
                keys.add('errno')
                if type(row.get('errno')) is not int or row['errno'] != 12:
                    return unknown
            elif stage == 'ERROR':
                if 'errno' in row:
                    keys.add('errno')
                    if type(row['errno']) is not int or not 0 <= row['errno'] <= 4095:
                        return unknown
            if set(row) != keys:
                return unknown
            stages.append(stage)
        prefix = stages[:-1] if stages and stages[-1] == 'ERROR' else stages
        if prefix != expected[:len(prefix)] or len(prefix) > len(expected):
            return unknown
        result = {'case': case, 'stages': stages, 'samples': samples,
                  'returncode_kind': 'ZERO' if returncode == 0 else ('SIGNAL_%d' % -returncode if returncode < 0 else 'NONZERO')}
        if stages[-1] == 'ERROR' and 'errno' in rows[-1]:
            result['error_errno'] = rows[-1]['errno']
        if returncode < 0:
            # READER_EXEC records intent, not successful execve. Allocating
            # its arguments under AS may itself abort the controller. Only
            # the reader's own Python marker identifies a reader-stage abort.
            kind = ('READER_ABORT' if 'READER_PYTHON' in stages else
                    'EXEC_PATH_ABORT' if 'READER_EXEC' in stages else 'FAILED_BEFORE_READER')
        elif returncode != 0 or 'ERROR' in stages:
            kind = 'READER_FAILED' if 'READER_PYTHON' in stages else 'FAILED_BEFORE_READER'
        elif stages == expected:
            kind = 'PASS_SCOPED_RESEARCH'
        else:
            kind = 'UNKNOWN'
        return {**result, 'classification': kind}
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return unknown


def evidence_decision(evidence, fingerprint, now):
    """Freshness is a diagnostic filter, never an authorization or signature."""
    try:
        if (type(evidence) is not dict or set(evidence) != {
                'feature', 'evidence', 'fingerprint', 'last_verified_at', 'ttl_seconds'}
                or evidence['feature'] != 'RLIMIT_AS_EXEC_AND_DENIAL'
                or evidence['evidence'] != 'PASS_SCOPED_RESEARCH'
                or type(fingerprint) is not str or len(fingerprint) != 64
                or any(c not in '0123456789abcdef' for c in fingerprint)
                or type(evidence['fingerprint']) is not str or len(evidence['fingerprint']) != 64
                or any(c not in '0123456789abcdef' for c in evidence['fingerprint'])
                or type(evidence['ttl_seconds']) is not int or not 0 < evidence['ttl_seconds'] <= TTL_SECONDS
                or type(now) not in (int, float) or not math.isfinite(now)
                or type(evidence['last_verified_at']) not in (int, float)
                or not math.isfinite(evidence['last_verified_at'])):
            return 'UNKNOWN'
        if evidence['fingerprint'] != fingerprint:
            return 'BLOCKED_DRIFT'
        age = now - evidence['last_verified_at']
        if age < 0:
            return 'UNKNOWN'
        return 'CURRENT_RESEARCH_ONLY' if age < evidence['ttl_seconds'] else 'BLOCKED_EXPIRED'
    except (KeyError, TypeError, ValueError):
        return 'UNKNOWN'


def run_case(case, as_mib):
    if case not in CASES or type(as_mib) is not int or as_mib not in (512, 1024):
        raise ValueError('fixed research case and threshold required')
    try:
        result = subprocess.run(
            [sys.executable, '-B', '-P', '-c', CONTROLLER, case, str(as_mib * 1024**2), READER],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': os.defpath, 'LC_ALL': 'C', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
            close_fds=True, timeout=3, check=False)
        return classify(case, result.returncode, result.stdout)
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for this direct child on timeout.
        return classify(case, None, b'', timed_out=True)
    except (OSError, subprocess.SubprocessError):
        return classify(case, None, b'')


def diagnose(*, probe_exec=False, as_mib=512):
    now = time.time()
    scope = ('ANDROID_REPORTED' if sys.platform == 'android' or hasattr(sys, 'getandroidapilevel')
             else 'LINUX_REPORTED' if sys.platform == 'linux' else 'UNSUPPORTED')
    context = {'platform': scope, 'python': list(sys.version_info[:3]),
               'architecture': platform.machine() if platform.machine() in ('x86_64', 'aarch64', 'armv7l') else 'OTHER',
               'kernel_release_sha256': hashlib.sha256(platform.release().encode()).hexdigest(),
               'android_api': getattr(sys, 'getandroidapilevel', lambda: None)(),
               'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'implementation_sha256': implementation_sha256(), 'as_mib': as_mib}
    fingerprint = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
    report = {'schema': 1, 'created_utc': datetime.fromtimestamp(now, timezone.utc).isoformat(),
              'context': context, 'fingerprint': fingerprint, 'source': source_pins(), 'cases': [],
              'decision': 'RESEARCH_ONLY_NEEDS_OWNER', 'host_authorized': False,
              'p5_qualified': False, 'cleanup_verified': False, 'stop_reason': 'NOT_REQUESTED'}
    if report['source']['status'] != 'PASS':
        report['stop_reason'] = 'SOURCE_PIN_BLOCKED'
    elif scope == 'UNSUPPORTED':
        report['stop_reason'] = 'UNSUPPORTED_PLATFORM'
    elif probe_exec:
        report['stop_reason'] = 'COMPLETE'
        for case in CASES:
            row = run_case(case, as_mib)
            report['cases'].append(row)
            if row['classification'] != 'PASS_SCOPED_RESEARCH':
                report['stop_reason'] = row['classification']
                break  # no retry, threshold escalation or propagation after abort/UNKNOWN
    complete = report['stop_reason'] == 'COMPLETE' and len(report['cases']) == len(CASES)
    evidence = {'feature': 'RLIMIT_AS_EXEC_AND_DENIAL',
                'evidence': 'PASS_SCOPED_RESEARCH' if complete else 'UNKNOWN',
                'fingerprint': fingerprint, 'last_verified_at': time.time() if complete else None,
                'ttl_seconds': TTL_SECONDS}
    report['capability'] = {**evidence, 'decision': evidence_decision(evidence, fingerprint, time.time())}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe-exec', action='store_true', help='opt in to fixed AS exec/denial research; may SIGABRT')
    parser.add_argument('--as-mib', type=int, choices=(512, 1024), default=512, help='research only; never changes P5')
    args = parser.parse_args(argv)
    try:
        report = diagnose(probe_exec=args.probe_exec, as_mib=args.as_mib)
    except Exception:
        # CLI boundary: unexpected faults also stop with a fixed, redacted
        # UNKNOWN result. This is not an authorization or an automatic retry.
        report = {'schema': 1, 'decision': 'UNKNOWN', 'host_authorized': False, 'p5_qualified': False}
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2  # even a successful research probe never qualifies this host


if __name__ == '__main__':
    raise SystemExit(main())
