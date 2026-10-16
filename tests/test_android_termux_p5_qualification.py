"""Off-device contract tests. They never certify Android or run P5 physically."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'tools/android_termux_p5_qualification.py'
spec = importlib.util.spec_from_file_location('android_gate', FILE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TermuxP5GateContractTests(unittest.TestCase):
    def test_default_off_device_is_blocked_and_no_device_tests_execute(self):
        with patch.object(gate, 'device_scope', return_value=False), patch.object(
                gate, 'run_real_tests', side_effect=AssertionError('OS tests should not run')):
            report = gate.qualify()
        self.assertEqual(report['decision'], 'BLOCKED_NON_TERMUX')
        self.assertFalse(report['service_installed'])
        self.assertEqual(report['checks']['p5_guardian_basic']['status'], 'NOT_TESTED')

    def test_termux_marker_alone_does_not_authorize_tests_or_service(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'verified')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'run_real_tests', side_effect=AssertionError('explicit opt-in missing')):
            report = gate.qualify()
        self.assertEqual(report['decision'], 'PARTIAL_DEVICE_QUALIFICATION')
        self.assertFalse(report['autonomous_ai_installed'])

    def test_source_drift_blocks_all_execution_even_when_requested(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('BLOCKED', 'changed')), patch.object(
                gate, 'provider_four_gets', side_effect=AssertionError('network called')), patch.object(
                gate, 'run_real_tests', side_effect=AssertionError('test called')):
            report = gate.qualify(True, True, True, True)
        self.assertEqual(report['decision'], 'BLOCKED_SOURCE')

    def test_provider_never_called_without_successful_guardian(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'provider_four_gets', side_effect=AssertionError('network called')):
            report = gate.qualify(provider=True)
        self.assertEqual(report['checks']['p5_guarded_github_gets']['status'], 'BLOCKED')

    def test_basic_failed_prevents_deep_and_provider_calls(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'run_real_tests', return_value=gate._row('BLOCKED', 'missing proc')) as real, patch.object(
                gate, 'provider_four_gets', side_effect=AssertionError('network called')):
            report = gate.qualify(deep_guardian=True, provider=True)
        real.assert_called_once_with(gate.GUARDIAN_BASIC)
        self.assertEqual(report['checks']['p5_guardian_deep']['status'], 'BLOCKED')

    def test_only_all_opt_in_successes_allow_next_physical_gate(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'run_real_tests', return_value=gate._row('PASS', 'real')) as real, patch.object(
                gate, 'provider_four_gets', return_value=gate._row('PASS', 'real')) as net:
            report = gate.qualify(deep_guardian=True, resume=True, provider=True)
        self.assertEqual(real.call_count, 3)
        net.assert_called_once()
        self.assertEqual(report['decision'], 'READY_FOR_BACKGROUND_QUALIFICATION')
        self.assertEqual(report['checks']['background_doze_boot']['status'], 'NOT_TESTED')
        self.assertFalse(report['service_installed'])

    def test_successful_basic_and_resume_are_insufficient_without_provider(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'run_real_tests', return_value=gate._row('PASS', 'real')):
            report = gate.qualify(guardian=True, resume=True)
        self.assertEqual(report['decision'], 'PARTIAL_DEVICE_QUALIFICATION')

    def test_source_pin_list_is_exact_and_public(self):
        self.assertEqual(len(gate.PINS), 6)
        self.assertEqual(set(gate.PINS), {
            'universal/host_process.py','universal/host_main.py','universal/host_github.py',
            'universal/continuity.py','tests/test_host_process.py','tests/test_host_main.py'})
        self.assertEqual(set(gate.PUBLIC_SYNTHETIC_BINDING), {
            'repository_id','actor_id','run_id','attempt','commit','branch','code_ref','request_sha256'})

    def test_proc_fallback_failure_blocks_existing_p5_tests(self):
        with patch.object(gate, 'device_scope', return_value=True), patch.object(
                gate, 'source_pins', return_value=gate._row('PASS', 'checked')), patch.object(
                gate, 'proc_fallback', return_value=gate._row('BLOCKED', 'denied')), patch.object(
                gate, 'run_real_tests', side_effect=AssertionError('unsafe test')):
            report = gate.qualify(guardian=True, resume=True)
        self.assertEqual(report['decision'], 'BLOCKED_PROC')
        self.assertEqual(report['checks']['p5_guardian_basic']['status'], 'NOT_TESTED')

    def test_provider_subprocess_arguments_are_in_existing_guardian(self):
        class Result:
            state = 'OK'
            cleanup_verified = True
            stdout = json.dumps({'state':'OBSERVED','observation':dict(gate.PUBLIC_SYNTHETIC_BINDING),
                'provenance':{**gate.PUBLIC_SYNTHETIC_BINDING,'get_count':4,
                              'caller_authenticated':False,'ordinary_file_verified':True}}).encode()
        with patch.dict('sys.modules', {'universal': None}):
            # Code construction is checked statically; off-device must not spoof P5 imports.
            self.assertIn('from universal.host_process import run_bounded', FILE.read_text())
            self.assertIn('from universal.host_github import validate_binding', FILE.read_text())
        self.assertEqual(Result.state,'OK')

    def test_no_background_activation_or_private_log_transport(self):
        source = FILE.read_text()
        for forbidden in ('systemctl enable', 'termux-wake-lock','termux-boot',
                          'os.system(', 'requests.post(', 'github_pat_', 'GITHUB_TOKEN=',
                          'sqlite3.connect(', 'subprocess.Popen(', 'chmod 777'):
            self.assertNotIn(forbidden, source)
        self.assertEqual(gate.qualify()['checks']['background_doze_boot']['status'], 'NOT_TESTED')


if __name__ == '__main__':
    unittest.main()
