"""Opt-in, flat Python mini-project profile. No shell, installs or self-tests.

Owner cases stay outside each fresh sandbox. Unsigned observations flow through
the existing GenerativeValidator, which alone rechecks and signs the snapshot.
"""
import ast
import hashlib
import math
import re
import time

from .policy_runner import (_json, _files, _static_checks, _run_case, _git_tree,
                            _criterion, _bound_observations, MAX_POLICY_BYTES,
                            MAX_CONTEXT_BYTES, MAX_RESULT_BYTES, _SAFE_IMPORTS,
                            _DANGEROUS_NAMES)
from .isolation import IsolationUnavailable

PROFILE = 'python-project-v1'
_MODULE = re.compile(r'project_[A-Za-z][A-Za-z0-9_]{0,40}\Z')
_FUNCTION = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')


def validate_project_policy(policy):
    copied, _ = _json(policy, MAX_POLICY_BYTES)
    fields = {'version', 'profile', 'tests', 'allowed_licenses', 'forbidden_markers', 'max_seconds'}
    if type(copied) is not dict or set(copied) != fields or type(copied['version']) is not int or copied['version'] != 1 or copied['profile'] != PROFILE:
        raise ValueError('invalid project policy')
    tests = copied['tests']
    if type(tests) is not list or not 1 <= len(tests) <= 20:
        raise ValueError('owner requires 1..20 independent cases')
    for case in tests:
        if type(case) is not dict or set(case) != {'module', 'function', 'args', 'expected'}:
            raise ValueError('invalid owner case')
        if type(case['module']) is not str or not _MODULE.fullmatch(case['module']) or type(case['function']) is not str or not _FUNCTION.fullmatch(case['function']):
            raise ValueError('invalid project entrypoint')
        if type(case['args']) is not list or len(case['args']) > 64:
            raise ValueError('invalid case arguments')
        _json(case['args'], MAX_RESULT_BYTES)
        _json(case['expected'], MAX_RESULT_BYTES)
    # Reuse the exact legacy license/marker/deadline contract without changing it.
    from .policy_runner import validate_policy
    legacy = {k: copied[k] for k in ('version', 'allowed_licenses', 'forbidden_markers', 'max_seconds')}
    legacy.update(entrypoint='candidate.py', function='check', tests=[{'args': [], 'expected': None}])
    validate_policy(legacy)
    return copied


def project_files(files):
    copied = _files(files)
    if len(copied) > 12 or sum(len(v.encode('utf-8')) for v in copied.values()) > 48000:
        raise ValueError('mini-project exceeds bounded IPC profile')
    modules = {}
    for name, text in copied.items():
        if name.endswith('.py') and _MODULE.fullmatch(name[:-3]):
            modules[name[:-3]] = text
        elif name not in {'LICENSE', 'README.md', 'test_worker.py'}:
            raise ValueError('unsupported project path')
    if not 1 <= len(modules) <= 8:
        raise ValueError('1..8 flat project modules required')
    return copied, modules


def run_project_checks(files, policy, context, *, timeout=10.0):
    start = time.monotonic()
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not .05 <= timeout <= 10:
        raise ValueError('invalid runner deadline')
    files, modules = project_files(files)
    policy = validate_project_policy(policy)
    if type(context) is not dict:
        raise ValueError('owner context required')
    _, context_bytes = _json(context, MAX_CONTEXT_BYTES)
    _, policy_bytes = _json(policy, MAX_POLICY_BYTES)
    deadline = start + min(timeout, policy['max_seconds'])
    # License and configured marker rules are shared. AST checks here allow
    # project modules in addition to the legacy standard-library allowlist.
    criteria, observations = _static_checks(files, {**policy, 'function': 'unused'})
    bad_syntax, dangerous = [], []
    for name, source in files.items():
        if not name.endswith('.py'):
            continue
        try:
            tree = ast.parse(source, filename=name)
            nodes = list(ast.walk(tree))
            if len(nodes) > 20000:
                raise ValueError('AST limit')
            compile(tree, name, 'exec', dont_inherit=True)
            for node in nodes:
                if isinstance(node, ast.Import) and any(a.name not in _SAFE_IMPORTS | modules.keys() for a in node.names):
                    dangerous.append(name)
                elif isinstance(node, ast.ImportFrom) and (node.level or node.module not in _SAFE_IMPORTS | modules.keys()):
                    dangerous.append(name)
                elif isinstance(node, ast.Name) and node.id in _DANGEROUS_NAMES:
                    dangerous.append(name)
                elif isinstance(node, ast.Attribute) and node.attr.startswith('__'):
                    dangerous.append(name)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            bad_syntax.append(name)
    criteria['lint'] = _criterion('FAIL' if bad_syntax else 'PASS', 'python_compile_only_no_build')
    markers = [name for name, text in files.items() if any(m in text for m in policy['forbidden_markers'])]
    criteria['security'] = _criterion('FAIL' if dangerous or markers else 'UNKNOWN' if bad_syntax else 'PASS', 'bounded_ast_and_literal_scan_not_exhaustive')
    observations.update(syntax_files=bad_syntax, security_files=sorted(set(dangerous + markers)),
                        project_profile=PROFILE, candidate_tests='inert_only', cases=[])
    context_digest = hashlib.sha256(context_bytes).hexdigest()
    result = {'schema': 'generative-policy-checks-v1', 'context_digest': context_digest,
              'policy_digest': hashlib.sha256(policy_bytes).hexdigest(), 'tree_sha': None,
              'criteria': criteria, 'observations': observations}
    try:
        result['tree_sha'] = _git_tree(files, deadline)
    except (IsolationUnavailable, TimeoutError, OSError):
        for name in ('tests', 'provenance', 'environment'):
            criteria[name] = _criterion('NOT_RUN', 'tree_unavailable')
        return result
    for index, case in enumerate(policy['tests']):
        if case['module'] not in modules:
            observations['cases'].append({'index': index, 'outcome': 'FAIL', 'reason': 'module_missing'})
        elif time.monotonic() >= deadline:
            observations['cases'].append({'index': index, 'outcome': 'NOT_RUN', 'reason': 'total_deadline'})
        else:
            observations['cases'].append(_run_case(files, policy, case['args'], index, result['tree_sha'],
                                                  context_digest, deadline, project=modules))
    outcomes = {c['outcome'] for c in observations['cases']}
    outcome = 'PASS' if outcomes == {'PASS'} else 'FAIL' if 'FAIL' in outcomes else 'UNKNOWN' if 'UNKNOWN' in outcomes else 'NOT_RUN'
    criteria['tests'] = _criterion(outcome, 'owner_external_project_cases')
    ready = all('ready' in c for c in observations['cases'])
    for name in ('provenance', 'environment'):
        criteria[name] = _criterion('PASS' if ready else 'NOT_RUN', 'fresh_confined_project_child' if ready else 'readiness_incomplete')
    _bound_observations(observations)
    return result
