"""Postfix install must never let `hostname` reach a shell (GHSA-mc93-rc3x-fpgq).

The original install concatenated hostname into a `bash -c` string run as
root. The fix validates the hostname and feeds debconf over stdin; these
tests pin both halves so the shell form cannot come back.
"""
import types

import pytest

from app.services import postfix_service as pf_module
from app.services.postfix_service import PostfixService


@pytest.fixture
def calls(monkeypatch):
    recorded = []

    def fake_run(cmd, **kwargs):
        recorded.append((cmd, kwargs))
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(pf_module, 'run_privileged', fake_run)
    monkeypatch.setattr(pf_module.PackageManager, 'detect', staticmethod(lambda: 'apt'))
    monkeypatch.setattr(pf_module.PackageManager, 'install',
                        staticmethod(lambda *a, **k: types.SimpleNamespace(returncode=1, stdout='', stderr='stop')))
    return recorded


@pytest.mark.parametrize('hostname', [
    '"; id > /tmp/serverkit-rce-poc; echo "',
    'mail.example.com; touch /tmp/pwned',
    'mail.example.com\n',
    'mail.example.com\npostfix postfix/main_mailer_type select No configuration',
    '$(id)',
    '`id`',
    'mail example.com',
])
def test_malicious_hostname_is_rejected_before_any_command(calls, hostname):
    result = PostfixService.install(hostname=hostname)

    assert result == {'success': False, 'error': 'Invalid hostname format'}
    assert calls == []


def test_valid_hostname_goes_to_debconf_via_stdin_not_a_shell(calls):
    PostfixService.install(hostname='mail.example.com')

    cmd, kwargs = calls[0]
    assert cmd == ['debconf-set-selections']
    assert 'postfix postfix/mailname string mail.example.com\n' in kwargs['input']
    assert not any(c[0][0] in ('bash', 'sh') for c in calls)
