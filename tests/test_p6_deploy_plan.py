"""P6 declaration-only negative tests; no service, Github HTTP or OS mutation."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from universal.host_deploy_plan import (
    decode_plan, validate_plan, render_examples, ProposalRejected, MAX_PLAN_BYTES,
    P5_COMMIT, P5_TREE,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / 'deploy/examples/p6_proposal.example.json'


class P6DeployPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = json.loads(EXAMPLE.read_bytes())

    def bad(self, key, value):
        obj = copy.deepcopy(self.good)
        obj[key] = value
        return obj

    def cli(self, path):
        return subprocess.run([sys.executable, '-B', '-m', 'tools.p6_deploy_preflight',
                               '--plan', str(path)], cwd=ROOT,
                              capture_output=True, text=True, timeout=8)

    def test_static_positive_is_never_os_proof_or_grant(self):
        result = validate_plan(self.good)
        self.assertEqual(result['status'], 'PREPARED_NOT_INSTALLED')
        self.assertEqual(result['authority'], 'NONE')
        self.assertEqual(result['allowed_external_effects'], [])
        self.assertEqual(result['backup_freshness'], 'NOT_RUN')
        self.assertTrue(result['human_approval_required'])
        self.assertFalse(result['external_scheduler_installed'])
        self.assertFalse(result['autonomous_ai_installed'])
        self.assertEqual(result['provider_live_get'], 'NOT_RUN')

    def test_fixed_owner_repo_source_and_tree_fail_on_drift(self):
        for key, value in (('repository', 'other/repo'), ('repository_id', 3),
                           ('repository_id', True), ('owner_id', 7), ('schema', 2),
                           ('source_commit', '0'*40), ('source_commit', P5_COMMIT[:-1]),
                           ('source_commit', P5_COMMIT.upper()), ('source_commit', 'branch-name'),
                           ('source_tree', '0'*40), ('source_tree', P5_TREE.upper())):
            with self.subTest(key=key, value=value), self.assertRaises(ProposalRejected):
                validate_plan(self.bad(key, value))

    def test_all_activation_and_authorization_flags_rejected(self):
        for name in ('scheduler_enabled', 'installed', 'service_enabled',
                     'timer_enabled', 'timer_persistent', 'github_write',
                     'autonomous_ai', 'paid_ai', 'deployment_authorized'):
            with self.subTest(flag=name), self.assertRaises(ProposalRejected):
                validate_plan(self.bad(name, True))

    def test_unknown_secret_write_url_and_evidence_fields_rejected(self):
        for name, value in (('token', 'ghp_not_a_real_secret'),
                            ('url', 'https://example.invalid'),
                            ('command', 'sh'), ('host_verified', True),
                            ('proof', 'PASS'), ('installation_receipt', 'PASS')):
            with self.subTest(key=name), self.assertRaises(ProposalRejected):
                validate_plan({**self.good, name:value})

    def test_scope_credentials_network_storage_and_owner_refusals(self):
        for key, value in (('scope','PRIVATE_PRODUCTION'),('host_type','CONTAINER_UNTRUSTED'),
                           ('network_scope','ANY_URL'), ('credentials','TOKEN'),
                           ('github_permissions','WRITE'), ('cost_eur',1),
                           ('cost_eur',False),('backup_freshness','VERIFIED'),
                           ('storage_kind','CLOUD_EPHEMERAL'),('owner_user','root'),
                           ('unit_basename','../../../evil')):
            with self.subTest(key=key), self.assertRaises(ProposalRejected):
                validate_plan(self.bad(key,value))

    def test_all_shell_and_systemd_path_injections_refused(self):
        examples=('/','/tmp','/var/tmp','/home/root','/root',
                  '/srv/coguni/source;touch /tmp/evil','/srv/coguni//source',
                  '/srv/coguni/../source','/srv/coguni/source/../../etc',
                  '/srv/coguni/source\nExecStart=/bin/sh','/srv/coguni/source$(id)',
                  'relative/path','/srv/coguni/source\x00evil','/srv/coguni/source\\escape',
                  '/var/lib/coguni-private')
        for key in ('source_dir','private_dir'):
            for value in examples:
                if self.good[key] == value: continue
                with self.subTest(key=key,path=repr(value)), self.assertRaises(ProposalRejected):
                    validate_plan(self.bad(key,value))

    def test_exact_fields_and_types_strict(self):
        bad=copy.deepcopy(self.good);bad.pop('private_dir')
        with self.assertRaises(ProposalRejected):validate_plan(bad)
        with self.assertRaises(ProposalRejected):validate_plan([])
        with self.assertRaises(ProposalRejected):validate_plan({**self.good,'p5_limits':[]})
        with self.assertRaises(ProposalRejected):validate_plan({**self.good,'cadence_seconds':True})
        with self.assertRaises(ProposalRejected):validate_plan({**self.good,'cadence_seconds':900.0})

    def test_bounded_cadence_max_ticks_and_physical_overhead(self):
        for v in (0,1,30,599,86401,True,'900',900.0):
            with self.subTest(cadence=v),self.assertRaises(ProposalRejected):
                validate_plan(self.bad('cadence_seconds',v))
        for limits in ({'hard_timeout_seconds':30,'max_ticks':2,'max_seconds':31,'interval_seconds':5},
                       {'hard_timeout_seconds':5,'max_ticks':17,'max_seconds':30,'interval_seconds':5},
                       {'hard_timeout_seconds':5,'max_ticks':2,'max_seconds':301,'interval_seconds':5},
                       {'hard_timeout_seconds':5,'max_ticks':2,'max_seconds':30,'interval_seconds':0},
                       {'hard_timeout_seconds':5,'max_ticks':True,'max_seconds':30,'interval_seconds':5},
                       {'hard_timeout_seconds':float('nan'),'max_ticks':2,'max_seconds':30,'interval_seconds':5}):
            with self.subTest(limits=limits),self.assertRaises(ProposalRejected):
                validate_plan(self.bad('p5_limits',limits))

    def test_p5_duration_and_cadence_cross_constraint(self):
        plan=self.bad('p5_limits', {'hard_timeout_seconds':30,'max_ticks':16,
                                   'max_seconds':300,'interval_seconds':60})
        plan['cadence_seconds']=600
        self.assertEqual(validate_plan(plan)['status'], 'PREPARED_NOT_INSTALLED')
        self.assertIn('TimeoutStartSec=313s',render_examples(plan)['coguni-observer.service.example'])
        plan['cadence_seconds']=329
        with self.assertRaises(ProposalRejected):validate_plan(plan)

    def test_strict_parser_rejects_duplicate_nonfinite_invalid_utf8(self):
        valid=json.dumps(self.good).encode()
        self.assertEqual(decode_plan(valid),self.good)
        for raw in (b'',b'{}',b'[]',b'null',b'NaN',b'Infinity',b'"string"',
                    b'{"schema":1,"schema":1}',valid+b'garbage',
                    b'\xff',b'\xef\xbb\xbf'+valid,b'0'* (MAX_PLAN_BYTES+1),
                    b'{"other":'+b'0'* (MAX_PLAN_BYTES+3)+b'}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ProposalRejected):
                decode_plan(raw)

    def test_parser_refuses_nested_duplicate_and_unknown_permissions(self):
        raw=json.dumps(self.good).replace('"max_ticks": 2','"max_ticks": 2, "max_ticks": 2')
        with self.assertRaises(ProposalRejected):decode_plan(raw.encode())
        raw=json.dumps({**self.good,'github_permissions':'WRITE'})
        with self.assertRaises(ProposalRejected):decode_plan(raw.encode())

    def test_template_service_is_disabled_and_hardens_filesystem(self):
        service=render_examples(self.good)['coguni-observer.service.example']
        self.assertNotIn('[Install]',service)
        self.assertIn('ConditionPathExists=/__COGUNI_P6_DISABLED_UNTIL_APPROVED__',service)
        for directive in ('Type=oneshot','NoNewPrivileges=yes','ProtectSystem=strict',
                          'ProtectHome=yes','PrivateTmp=yes','PrivateDevices=yes',
                          'UMask=0077','ReadWritePaths=/var/lib/coguni-private',
                          'KillMode=control-group','TimeoutStartSec=43s',
                          'StandardOutput=null','StandardError=null',
                          'RefuseManualStart=yes'):
            with self.subTest(directive=directive):self.assertIn(directive,service)
        self.assertEqual(service.count('ExecStart='),1)
        self.assertIn('universal.host_main observe-once',service)
        self.assertNotIn('ExecStartPre=',service)
        self.assertNotIn('User=root',service)
        self.assertNotIn('ReadWritePaths=/\n',service)

    def test_timer_is_disabled_no_catchup_no_install_section(self):
        timer=render_examples(self.good)['coguni-observer.timer.example']
        for directive in ('ConditionPathExists=/__COGUNI_P6_DISABLED_UNTIL_APPROVED__',
                          'OnUnitInactiveSec=900s','Persistent=false',
                          'RefuseManualStart=yes','Unit=coguni-observer.service'):
            self.assertIn(directive,timer)
        self.assertNotIn('[Install]',timer)
        self.assertNotIn('OnBootSec=',timer)

    def test_static_templates_match_renderer_byte_for_byte(self):
        for filename, rendered in render_examples(self.good).items():
            self.assertEqual((ROOT/'deploy/examples'/filename).read_text(),rendered)

    def test_dangerous_commands_and_secrets_absent_from_examples(self):
        for data in render_examples(self.good).values():
            for token in ('sudo ', 'systemctl ', 'enable --now', 'docker ',
                          'curl ', 'wget ', 'Environment=','ExecStartPre=',
                          'GITHUB_TOKEN=', 'ghp_', 'OAuth', 'github_pat_',
                          'PERSISTENT_AGENT_INSTALLED', 'AutonomousAI='):
                with self.subTest(token=token):self.assertNotIn(token,data)

    def test_cli_success_only_prepared_no_path_reflection(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'plan.json';file.write_text(json.dumps(self.good))
            previous=file.read_bytes()
            result=self.cli(file)
            self.assertEqual(result.returncode,0,result.stderr)
            verdict=json.loads(result.stdout)
            self.assertEqual(verdict['status'],'PREPARED_NOT_INSTALLED')
            self.assertNotIn(str(file),result.stdout)
            self.assertNotIn(self.good['private_dir'],result.stdout)
            self.assertEqual(file.read_bytes(),previous)
            self.assertEqual(list(Path(d).iterdir()),[file])

    def test_cli_rejects_symlinks_directory_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);bad=root/'bad.json';bad.write_bytes(b'{"schema":1,"schema":1}')
            symlink=root/'alias.json';symlink.symlink_to(bad)
            for target in (bad,symlink,root):
                with self.subTest(target=str(target)):
                    result=self.cli(target)
                    self.assertEqual(result.returncode,2)
                    self.assertEqual(json.loads(result.stdout)['status'],'REJECTED')

    def test_cli_unknown_option_cannot_render_or_install(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'plan.json';file.write_text(json.dumps(self.good))
            proc=subprocess.run([sys.executable,'-B','-m','tools.p6_deploy_preflight',
                                 '--plan',str(file),'--install'],cwd=ROOT,
                                capture_output=True,text=True,timeout=8)
            self.assertNotEqual(proc.returncode,0)
            self.assertEqual(set(Path(d).iterdir()),{file})

    def test_no_runtime_effect_imports_or_side_effect_calls(self):
        source=(ROOT/'universal/host_deploy_plan.py').read_text()
        cli=(ROOT/'tools/p6_deploy_preflight.py').read_text()
        for forbidden in ('import subprocess','from subprocess','import urllib',
                          'import requests','import socket','import sqlite3',
                          'import tempfile','os.system(', 'os.exec',
                          'subprocess.Popen','open("/etc', 'systemctl enable'):
            with self.subTest(forbidden=forbidden):self.assertNotIn(forbidden,source+cli)

    def test_repeated_validation_and_render_are_deterministic_and_pure(self):
        before=copy.deepcopy(self.good)
        values=[validate_plan(self.good) for _ in range(4)]
        self.assertEqual(values,[values[0]]*4)
        units=[render_examples(self.good) for _ in range(4)]
        self.assertEqual(units,[units[0]]*4)
        self.assertEqual(before,self.good)


if __name__=='__main__': unittest.main()
