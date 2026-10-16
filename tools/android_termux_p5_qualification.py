"""Passive Termux checks; active P5 qualification is blocked on memory safety.

Never adapts the P5 security boundary. No app, timer, daemon, privileges, keys,
SQLite migration, mission submission or GitHub writes. Results are a sanitized
report only; CI or a desktop cannot certify an Android device. Legacy active
helpers remain available for reviewed tests, but qualify() never invokes them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASELINE_P6 = '4db2457c34e9dd83e96e4ec11ca8b3a5be9654c9'
PINS = {
    'universal/host_process.py': 'c1c0bdd3b91017a53dbf6bfe000d3effb1f99f6d',
    'universal/host_main.py': '41bdcc2bb1b93c15d6f6f866c69b4048f22572bc',
    'universal/host_github.py': 'c44eaae5e3671cf36327d6857b4733a2efcaf665',
    'universal/continuity.py': 'a7e75dd1c818affa1954fd494347b2a93798feec',
    'tests/test_host_process.py': 'c19ccede279587d9540b42b967c2e235f62d0cb8',
    'tests/test_host_main.py': '718ed28c23c541200e976fceb4fb9f6821184167',
}
# Public, immutable synthetic mission only. No token, private mission or write.
PUBLIC_SYNTHETIC_BINDING = {
    'repository_id': 1418009675, 'actor_id': 265171248,
    'run_id': 38791437019, 'attempt': 1,
    'commit': '0a070e653efd091a13164a86b4359d930c80d4ed',
    'branch': 'work/mvp-mission-transport-passe3-20261015-1910',
    'code_ref': 'd210e3f69cfbd6311dff077225d53fa31a9d36fb',
    'request_sha256': '4fb66e97826338e661777e83925d4b8db2d9f240d24fe7a0fa6f19589f192775',
}
GUARDIAN_BASIC = (
    'tests.test_host_process.HostProcessTests.test_success_bounded_input_and_same_cwd',
    'tests.test_host_process.HostProcessTests.test_blocked_reader_is_physically_dead_under_hard_bound',
)
GUARDIAN_DEEP = (
    'tests.test_host_process.HostProcessTests.test_term_ignoring_detached_descendant_is_killed_and_reaped',
    'tests.test_host_process.HostProcessTests.test_double_fork_orphan_after_success_is_not_qualified_ok',
    'tests.test_host_process.HostProcessTests.test_sigterm_host_cleans_reader_and_detached_descendant',
    'tests.test_host_process.HostProcessTests.test_sigkill_host_life_pipe_still_cleans_reader_and_orphan',
)
OWNER_RESTART = (
    'tests.test_host_main.HostMainTests.test_two_distinct_os_processes_resume_same_sqlite_and_stable_observation',
    'tests.test_host_main.HostMainTests.test_os_crash_after_sqlite_commit_recovers_receipt_without_new_read',
    'tests.test_host_main.HostMainTests.test_crash_after_intent_before_ack_does_not_retry_uncertain_read',
    'tests.test_host_main.HostMainTests.test_unknown_effect_does_not_read_recover_or_release_physical_resource',
)


def _row(status, detail):
    return {'status': status, 'detail': detail}


def device_scope():
    # The Android marker is informative, not a signed hardware attestation.
    prefix = os.environ.get('PREFIX', '')
    return (prefix == '/data/data/com.termux/files/usr'
            and platform.system() in ('Android', 'Linux'))


def source_pins():
    """Hash actual Git blobs without fetching, executing or modifying sources."""
    try:
        for rel, expected in PINS.items():
            p = ROOT / rel
            s = p.lstat()
            if not stat.S_ISREG(s.st_mode) or s.st_size > 500_000 or s.st_nlink != 1:
                return _row('BLOCKED', 'P5 source type, size or link count differs')
            raw = p.read_bytes()
            if len(raw) != s.st_size:
                return _row('BLOCKED', 'P5 source changed while checking')
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw).hexdigest()
            if blob != expected or p.lstat().st_mtime_ns != s.st_mtime_ns:
                return _row('BLOCKED', 'P5 pinned source differs')
        return _row('PASS', 'six critical P5 Git blobs match; not whole-tree attestation')
    except (OSError, ValueError):
        return _row('BLOCKED', 'P5 pinned source unavailable')


def proc_fallback():
    """Exercise P5's actual /proc stat walker; never replace it or weaken it."""
    try:
        from universal.host_process import _parents
        parents = _parents()
        if type(parents) is not dict or os.getpid() not in parents:
            return _row('BLOCKED', 'P5 /proc fallback cannot see current process')
        return _row('PASS', 'P5 /proc stat walker ran; child reaping still needs real guardian tests')
    except (OSError, RuntimeError, ValueError, PermissionError):
        return _row('BLOCKED', 'P5 /proc fallback refused under device permissions')


def run_real_tests(names):
    """Invoke P5's original unittest methods on this OS; never fake results."""
    result = unittest.TestResult()
    for name in names:
        suite = unittest.defaultTestLoader.loadTestsFromName(name)
        suite.run(result)
        if (result.failures or result.errors or result.skipped
                or result.expectedFailures or result.unexpectedSuccesses):
            break  # fail-closed: do not launch further physical process cases
    passed = (result.testsRun == len(names) and not result.failures
              and not result.errors and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses)
    return _row('PASS' if passed else 'BLOCKED',
                'real P5 methods: %d/%d executed; %d failures; %d errors; %d skips'
                % (result.testsRun, len(names), len(result.failures),
                   len(result.errors), len(result.skipped)))


def provider_four_gets():
    """Actual trusted P5 reader behind its existing guardian, opt-in only."""
    from universal.host_process import run_bounded
    from universal.host_github import validate_binding
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        if '@' in os.environ.get(key, ''):
            return _row('BLOCKED', 'credential-bearing proxy environment refused')
    binding = validate_binding(PUBLIC_SYNTHETIC_BINDING)
    args = [sys.executable, '-B', '-P', '-m', 'universal.host_github']
    wire = json.dumps(binding, sort_keys=True, separators=(',', ':')).encode()
    result = run_bounded(args, wire, timeout_seconds=24, max_output_bytes=16384)
    if result.state != 'OK' or not result.cleanup_verified:
        return _row('BLOCKED', 'P5 guarded public reader not cleanly completed')
    try:
        response = json.loads(result.stdout)
        if response.get('state') == 'UNAVAILABLE':
            return _row('UNKNOWN', 'P5 public read unavailable; no retry or authorization')
        provider, provenance = response['observation'], response['provenance']
        if (response.get('state') != 'OBSERVED'
                or provenance.get('get_count') != 4
                or provenance.get('caller_authenticated') is not False
                or provenance.get('ordinary_file_verified') is not True
                or any(provider.get(k) != v for k, v in binding.items())
                or any(provenance.get(k) != v for k, v in binding.items())):
            return _row('BLOCKED', 'P5 public read provenance mismatched')
        return _row('PASS', 'four real public GitHub GETs in P5 guardian; no applied effect proof')
    except (ValueError, KeyError, TypeError, AttributeError):
        return _row('BLOCKED', 'P5 public read response invalid')


def qualify(guardian=False, deep_guardian=False, resume=False, provider=False):
    checks = {
        'android_termux_scope': _row('BLOCKED', 'must execute on actual Termux device'),
        'p5_source_pins': _row('NOT_TESTED', 'requires inspected P5 source checkout'),
        'p5_proc_fallback': _row('NOT_TESTED', 'P5 original /proc walker not invoked'),
        'p5_memory_enforcement': _row('BLOCKED', 'Android equivalent memory enforcement not demonstrated'),
        'p5_guardian_basic': _row('NOT_TESTED', 'explicit --guardian required'),
        'p5_guardian_deep': _row('NOT_TESTED', 'explicit --deep-guardian required'),
        'p5_owner_resume': _row('NOT_TESTED', 'explicit --resume required'),
        'p5_guarded_github_gets': _row('NOT_TESTED', 'explicit --provider required'),
        'background_doze_boot': _row('NOT_TESTED', 'must use separate physical screen-off and boot gates'),
        'apk_ipc': _row('NOT_TESTED', 'companion IPC not implemented or authorized'),
    }
    if not device_scope():
        return {'schema': 1, 'scope': 'ANDROID_DEVICE_ONLY', 'checks': checks,
                'decision': 'BLOCKED_NON_TERMUX', 'service_installed': False,
                'autonomous_ai_installed': False}
    checks['android_termux_scope'] = _row('PASS', 'Termux marker; not cryptographic device proof')
    checks['p5_source_pins'] = source_pins()
    if checks['p5_source_pins']['status'] != 'PASS':
        return {'schema': 1, 'scope': 'ANDROID_DEVICE_ONLY', 'checks': checks,
                'decision': 'BLOCKED_SOURCE', 'service_installed': False,
                'autonomous_ai_installed': False}
    checks['p5_proc_fallback'] = proc_fallback()
    if checks['p5_proc_fallback']['status'] != 'PASS':
        return {'schema': 1, 'scope': 'ANDROID_DEVICE_ONLY', 'checks': checks,
                'decision': 'BLOCKED_PROC', 'service_installed': False,
                'autonomous_ai_installed': False}
    # No diagnostic or caller-supplied success can qualify a memory boundary.
    # Keep old flags recognizable, but suspend ALL active tests, including
    # synthetic journal/restart and network tests, until a reviewed change
    # demonstrates equivalent enforcement and the physical prerequisites.
    for selected, requested in (
            ('p5_guardian_basic', guardian or deep_guardian),
            ('p5_guardian_deep', deep_guardian),
            ('p5_owner_resume', resume), ('p5_guarded_github_gets', provider)):
        if requested:
            checks[selected] = _row('BLOCKED', 'Android memory prerequisite not qualified')
    return {'schema': 1, 'scope': 'ANDROID_DEVICE_ONLY', 'checks': checks,
            'decision': 'ANDROID_P5_BLOCKED_INVARIANT_NOT_EQUIVALENT', 'service_installed': False,
            'autonomous_ai_installed': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--guardian', action='store_true', help='suspended: Android memory prerequisite blocked')
    p.add_argument('--deep-guardian', action='store_true', help='suspended: no physical fork/kill tests')
    p.add_argument('--resume', action='store_true', help='suspended: no SQLite/restart tests')
    p.add_argument('--provider', action='store_true', help='suspended: no network tests')
    a = p.parse_args(argv)
    # The report always whitelists text, never PIDs, private paths or raw traces.
    report = qualify(a.guardian, a.deep_guardian, a.resume, a.provider)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2  # Android P5 remains blocked, independently of diagnostic success.


if __name__ == '__main__':
    raise SystemExit(main())
