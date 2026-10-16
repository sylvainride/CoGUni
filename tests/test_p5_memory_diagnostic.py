"""Negative contracts plus real Linux probes; no physical Android claims."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools import p5_memory_diagnostic as probe
from universal import host_process as host


class P5MemoryDiagnosticTests(unittest.TestCase):
    def test_android_refused_before_spawn_including_legacy_linux_marker(self):
        for name, api in (('android', False), ('android', True), ('linux', True), ('unsupported', False)):
            with self.subTest(platform=name, android_api=api), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, 'platform', name))
                if api:
                    stack.enter_context(patch.object(sys, 'getandroidapilevel', lambda: 36, create=True))
                spawn = stack.enter_context(patch.object(host.subprocess, 'Popen', side_effect=AssertionError('spawned')))
                result = host.run_bounded([sys.executable, '-c', 'pass'], b'', timeout_seconds=1)
                spawn.assert_not_called()
                self.assertEqual(result.state, 'FAILED')
                self.assertFalse(result.cleanup_verified)
                self.assertEqual(result.child_pid, 0)

    def test_direct_guardian_entry_also_refuses_legacy_android(self):
        source = "import sys,runpy;sys.getandroidapilevel=lambda:36;sys.argv=['x','--guardian'];runpy.run_module('universal.host_process',run_name='__main__')"
        result = subprocess.run([sys.executable, '-B', '-c', source], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')

    def test_resource_module_absent_never_launches_reader(self):
        with patch.dict(sys.modules, {'resource': None}), patch.object(
                host.subprocess, 'Popen', side_effect=AssertionError('reader started')):
            with self.assertRaises(ModuleNotFoundError):
                host._guardian()

    def test_real_reader_sigabrt_is_failed_and_physically_reaped(self):
        result = host.run_bounded([sys.executable, '-B', '-c', 'import os;os.abort()'],
                                  b'', timeout_seconds=2)
        self.assertEqual(result.state, 'FAILED')
        self.assertEqual(result.returncode, -6)
        self.assertTrue(result.cleanup_verified)
        self.assertGreater(result.child_pid, 1)
        self.assertFalse(Path('/proc/%d' % result.child_pid).exists())

    def test_guardian_abort_has_no_invented_pid_or_cleanup_proof(self):
        popen = subprocess.Popen
        def aborted(*args, **kwargs):
            return popen([sys.executable, '-B', '-c',
                          'import resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));import os;os.abort()'], **kwargs)
        with patch.object(host.subprocess, 'Popen', side_effect=aborted):
            result = host.run_bounded([sys.executable, '-c', 'pass'], b'', timeout_seconds=1)
        self.assertEqual(result.state, 'FAILED')
        self.assertFalse(result.cleanup_verified)
        self.assertEqual(result.child_pid, 0)
        self.assertIsNone(result.returncode)  # reader returncode is unknown

    def test_forged_ok_without_cleanup_never_passes(self):
        popen = subprocess.Popen
        wire = json.dumps({'state': 'OK', 'stdout': '', 'cleanup_verified': False,
                           'child_pid': 0, 'returncode': None})
        def forged(*args, **kwargs):
            return popen([sys.executable, '-B', '-c', 'print(%r)' % wire], **kwargs)
        with patch.object(host.subprocess, 'Popen', side_effect=forged):
            result = host.run_bounded([sys.executable, '-c', 'pass'], b'', timeout_seconds=1)
        self.assertEqual(result.state, 'FAILED')
        self.assertFalse(result.cleanup_verified)

    def test_missing_children_file_and_denied_fallback_do_not_mean_empty_tree(self):
        with patch('builtins.open', side_effect=FileNotFoundError), patch.object(
                host, '_parents', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                host._children(os.getpid())

    def test_cleanup_visibility_failure_is_unverified(self):
        class Exited:
            returncode = 0
            def poll(self):
                return 0
        with patch.object(host, '_tree', side_effect=PermissionError), patch.object(host, '_send') as send:
            self.assertFalse(host._cleanup(Exited()))
        send.assert_not_called()

    def test_real_linux_preexec_postexec_and_memory_denial(self):
        for case in probe.CASES:
            with self.subTest(case=case):
                row = probe.run_case(case, 512)
                self.assertEqual(row['classification'], 'PASS_SCOPED_RESEARCH', row)
                self.assertEqual(row['returncode_kind'], 'ZERO')
                self.assertEqual(row['samples'][0]['stage'], 'PREEXEC_SAMPLE')
                self.assertGreater(row['samples'][0]['vm_kib'], 0)
                if case == 'enforcement':
                    self.assertIn('ENFORCEMENT_DENIED', row['stages'])

    def test_passive_default_never_spawns_or_certifies(self):
        with patch.object(probe, 'run_case', side_effect=AssertionError('active probe')):
            report = probe.diagnose()
        self.assertEqual(report['cases'], [])
        self.assertFalse(report['host_authorized'])
        self.assertFalse(report['p5_qualified'])
        self.assertFalse(report['cleanup_verified'])
        self.assertEqual(report['capability']['decision'], 'UNKNOWN')

    def test_source_drift_and_unsupported_platform_block_active_probe(self):
        with patch.object(probe, 'source_pins', return_value={'status': 'BLOCKED'}), patch.object(
                probe, 'run_case', side_effect=AssertionError('active probe')):
            self.assertEqual(probe.diagnose(probe_exec=True)['stop_reason'], 'SOURCE_PIN_BLOCKED')
        with patch.object(sys, 'platform', 'unsupported'), patch.object(
                probe, 'run_case', side_effect=AssertionError('active probe')):
            self.assertEqual(probe.diagnose(probe_exec=True)['stop_reason'], 'UNSUPPORTED_PLATFORM')

    def test_abort_timeout_unknown_stop_without_retry_or_threshold_escalation(self):
        for failure in ('READER_ABORT', 'EXEC_PATH_ABORT', 'TIMEOUT', 'UNKNOWN'):
            with self.subTest(failure=failure), patch.object(probe, 'run_case', side_effect=[
                    {'classification': 'PASS_SCOPED_RESEARCH'}, {'classification': failure}]) as run:
                report = probe.diagnose(probe_exec=True)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args, ('postexec', 512))
            self.assertEqual(report['stop_reason'], failure)
            self.assertIsNone(report['capability']['last_verified_at'])
            self.assertEqual(report['capability']['decision'], 'UNKNOWN')

    def test_even_all_successes_never_qualify_android_or_any_host(self):
        with patch.object(sys, 'platform', 'android'), patch.object(probe, 'run_case', return_value={
                'classification': 'PASS_SCOPED_RESEARCH'}):
            report = probe.diagnose(probe_exec=True)
        self.assertEqual(report['capability']['decision'], 'CURRENT_RESEARCH_ONLY')
        self.assertFalse(report['host_authorized'])
        self.assertFalse(report['p5_qualified'])
        self.assertEqual(report['decision'], 'RESEARCH_ONLY_NEEDS_OWNER')

    def test_partial_malformed_duplicate_extra_or_forged_trace_is_unknown(self):
        for data in (b'', b'not-json', b'{"stage":"DONE"}', b'{"stage":"PROBE_START","pid":1}',
                     b'{"stage":"x","stage":"PROBE_START"}', b'{"stage":"PROBE_START"}', b'x'*4097):
            with self.subTest(data=data[:60]):
                self.assertEqual(probe.classify('baseline', 0, data)['classification'], 'UNKNOWN')
        self.assertEqual(probe.classify('baseline', -6, b'')['classification'], 'UNKNOWN')
        self.assertEqual(probe.classify('baseline', True, b'')['classification'], 'UNKNOWN')

    def test_signal_and_setup_errno_are_distinct_without_raw_data(self):
        stages = b'{"stage":"PROBE_START"}\n{"stage":"PREEXEC_SAMPLE","vm_kib":100,"rss_kib":10}\n'
        denied = probe.classify('preexec', 2, stages + b'{"stage":"ERROR","errno":12}\n')
        self.assertEqual(denied['classification'], 'FAILED_BEFORE_READER')
        self.assertEqual(denied['error_errno'], 12)
        aborted = probe.classify('preexec', -6, stages + b'{"stage":"RLIMIT_SETUP"}\n{"stage":"READER_EXEC"}\n')
        self.assertEqual(aborted['classification'], 'EXEC_PATH_ABORT')
        self.assertEqual(aborted['returncode_kind'], 'SIGNAL_6')
        self.assertNotIn('READER_PYTHON', aborted['stages'])
        reader_prefix = stages + b'{"stage":"RLIMIT_SETUP"}\n{"stage":"READER_EXEC"}\n{"stage":"READER_PYTHON"}\n'
        self.assertEqual(probe.classify('preexec', -6, reader_prefix)['classification'], 'READER_ABORT')
        failed_exec = stages + b'{"stage":"RLIMIT_SETUP"}\n{"stage":"READER_EXEC"}\n{"stage":"ERROR","errno":12}\n'
        self.assertEqual(probe.classify('preexec', 2, failed_exec)['classification'], 'FAILED_BEFORE_READER')

    def test_freshness_rejects_missing_unknown_expired_future_drift_and_invalid_types(self):
        fingerprint = 'a'*64
        evidence = dict(feature='RLIMIT_AS_EXEC_AND_DENIAL', evidence='PASS_SCOPED_RESEARCH',
                        fingerprint=fingerprint, last_verified_at=100, ttl_seconds=3600)
        self.assertEqual(probe.evidence_decision(evidence, fingerprint, 101), 'CURRENT_RESEARCH_ONLY')
        self.assertEqual(probe.evidence_decision(evidence, 'b'*64, 101), 'BLOCKED_DRIFT')
        self.assertEqual(probe.evidence_decision(evidence, fingerprint, 3700), 'BLOCKED_EXPIRED')
        for changes in ({'evidence': 'UNKNOWN'}, {'evidence': 'PASS'}, {'last_verified_at': None},
                        {'last_verified_at': 102}, {'last_verified_at': float('nan')},
                        {'ttl_seconds': True}, {'ttl_seconds': 0}, {'ttl_seconds': 3601},
                        {'fingerprint': None}, {'authorized': True}):
            with self.subTest(changes=changes):
                self.assertEqual(probe.evidence_decision({**evidence, **changes}, fingerprint, 101), 'UNKNOWN')
        self.assertEqual(probe.evidence_decision({}, fingerprint, 101), 'UNKNOWN')
        self.assertEqual(probe.evidence_decision(evidence, fingerprint, float('inf')), 'UNKNOWN')

    def test_case_threshold_and_arbitrary_command_are_not_configurable(self):
        for case, limit in (('shell', 512), ('baseline', 2048), ('baseline', True)):
            with self.assertRaises(ValueError):
                probe.run_case(case, limit)

    def test_cli_redacts_exceptions_and_returns_nonqualification(self):
        output = io.StringIO()
        with patch.object(probe, 'diagnose', side_effect=OSError('/private/secret-token')), contextlib.redirect_stdout(output):
            self.assertEqual(probe.main([]), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report['decision'], 'UNKNOWN')
        self.assertNotIn('secret-token', output.getvalue())
        self.assertFalse(report['p5_qualified'])


if __name__ == '__main__':
    unittest.main()
