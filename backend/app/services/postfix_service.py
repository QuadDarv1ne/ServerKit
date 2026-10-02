"""Postfix SMTP server management service."""
import os
import re
import subprocess
from typing import Dict

from app.utils.system import (PackageManager, ServiceControl, run_checked,
                             run_privileged,
                             write_privileged_file)
from app import paths


class PostfixService:
    """Service for managing Postfix (SMTP server)."""

    POSTFIX_MAIN_CF = '/etc/postfix/main.cf'
    POSTFIX_MASTER_CF = '/etc/postfix/master.cf'
    VIRTUAL_DOMAINS_FILE = '/etc/postfix/virtual_domains'
    VIRTUAL_MAILBOXES_FILE = '/etc/postfix/virtual_mailboxes'
    VIRTUAL_ALIASES_FILE = '/etc/postfix/virtual_aliases'

    MAIN_CF_ADDITIONS = """
# ServerKit mail configuration
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# TLS parameters
smtpd_tls_cert_file = {tls_cert}
smtpd_tls_key_file = {tls_key}
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_security_level = may

# Virtual mailbox configuration
virtual_mailbox_domains = hash:/etc/postfix/virtual_domains
virtual_mailbox_maps = hash:/etc/postfix/virtual_mailboxes
virtual_alias_maps = hash:/etc/postfix/virtual_aliases
virtual_mailbox_base = {vmail_dir}
virtual_minimum_uid = {vmail_uid}
virtual_uid_maps = static:{vmail_uid}
virtual_gid_maps = static:{vmail_gid}
virtual_transport = lmtp:unix:private/dovecot-lmtp

# SASL authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
broken_sasl_auth_clients = yes

# Restrictions
smtpd_recipient_restrictions =
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org

# DKIM milter
smtpd_milters = inet:localhost:8891
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
milter_protocol = 6

# SpamAssassin milter
smtpd_milters = inet:localhost:8891, inet:localhost:8893

# Message size limit (25MB)
message_size_limit = 26214400
mailbox_size_limit = 0
"""

    SUBMISSION_CONF = """submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
"""

    @classmethod
    def get_status(cls) -> Dict:
        """Get Postfix installation and running status."""
        installed = False
        running = False
        enabled = False
        version = None
        hostname = None

        try:
            result = run_checked(['which', 'postfix'], timeout=None)
            installed = result['success']
            if not installed:
                installed = PackageManager.is_installed('postfix')

            if installed:
                running = ServiceControl.is_active('postfix')
                enabled = ServiceControl.is_enabled('postfix')

                result = run_checked(['postconf', 'mail_version'], timeout=None)
                match = re.search(r'mail_version\s*=\s*(\S+)', result['output'])
                if match:
                    version = match.group(1)

                result = run_checked(['postconf', 'myhostname'], timeout=None)
                match = re.search(r'myhostname\s*=\s*(\S+)', result['output'])
                if match:
                    hostname = match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return {
            'installed': installed,
            'running': running,
            'enabled': enabled,
            'version': version,
            'hostname': hostname,
        }

    @classmethod
    def install(cls, hostname: str = None) -> Dict:
        """Install Postfix."""
        try:
            if hostname and not re.fullmatch(r'[a-zA-Z0-9.-]+', hostname):
                return {'success': False, 'error': 'Invalid hostname format'}

            # Pre-seed debconf to avoid interactive prompts. The values are
            # piped via stdin so no user input is ever interpolated into a
            # shell command string (GHSA-mc93-rc3x-fpgq).
            if PackageManager.detect() == 'apt':
                debconf_lines = (
                    f'postfix postfix/mailname string {hostname or "localhost"}\n'
                    'postfix postfix/main_mailer_type select Internet Site\n'
                )
                run_privileged(['debconf-set-selections'], input=debconf_lines)

            result = PackageManager.install(['postfix'], timeout=300)
            if result.returncode != 0:
                return {'success': False, 'error': result.stderr or 'Failed to install Postfix'}

            # Create virtual map files
            for path in [cls.VIRTUAL_DOMAINS_FILE, cls.VIRTUAL_MAILBOXES_FILE, cls.VIRTUAL_ALIASES_FILE]:
                run_privileged(['touch', path])
                run_privileged(['postmap', path])

            # Create vmail user/group
            run_privileged(['groupadd', '-g', str(paths.VMAIL_GID), 'vmail'], check=False)
            run_privileged(['useradd', '-u', str(paths.VMAIL_UID), '-g', 'vmail',
                          '-d', paths.VMAIL_DIR, '-s', '/usr/sbin/nologin', 'vmail'], check=False)
            run_privileged(['mkdir', '-p', paths.VMAIL_DIR])
            run_privileged(['chown', '-R', f'{paths.VMAIL_UID}:{paths.VMAIL_GID}', paths.VMAIL_DIR])

            ServiceControl.enable('postfix')
            ServiceControl.start('postfix', timeout=30)

            return {'success': True, 'message': 'Postfix installed successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def configure(cls, hostname: str = None, tls_cert: str = None, tls_key: str = None) -> Dict:
        """Configure Postfix for virtual mailbox hosting."""
        try:
            cert = tls_cert or '/etc/ssl/certs/ssl-cert-snakeoil.pem'
            key = tls_key or '/etc/ssl/private/ssl-cert-snakeoil.key'

            if hostname:
                run_privileged(['postconf', '-e', f'myhostname={hostname}'])

            additions = cls.MAIN_CF_ADDITIONS.format(
                tls_cert=cert,
                tls_key=key,
                vmail_dir=paths.VMAIL_DIR,
                vmail_uid=paths.VMAIL_UID,
                vmail_gid=paths.VMAIL_GID,
            )

            # Append to main.cf
            write_privileged_file(cls.POSTFIX_MAIN_CF, additions, append=True)

            # Enable submission port in master.cf
            result = run_privileged(['cat', cls.POSTFIX_MASTER_CF])
            if 'submission' not in (result.stdout or ''):
                write_privileged_file(cls.POSTFIX_MASTER_CF, cls.SUBMISSION_CONF, append=True)

            # Restart
            ServiceControl.restart('postfix', timeout=30)

            return {'success': True, 'message': 'Postfix configured successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _mentions_domain(line: str, domain: str) -> bool:
        """True when any address token on the map line is at exactly *domain*.

        Token-suffix match, not substring: removing example.com must not
        also delete lines for example.com.br, and sub.example.com entries
        must survive removing example.com."""
        suffix = '@' + domain.lower()
        return any(token.endswith(suffix)
                   for token in re.split(r'[\s,]+', line.lower()))

    @classmethod
    def _append_map_entry(cls, path: str, entry: str) -> None:
        """Append one map entry, guarding against a file whose last line is
        missing its newline — tee -a would glue the entry onto that line,
        corrupting both and making them unmatchable on removal."""
        result = run_privileged(['cat', path])
        content = result.stdout or ''
        if content and not content.endswith('\n'):
            entry = '\n' + entry
        write_privileged_file(path, entry, append=True)

    @classmethod
    def add_domain(cls, domain: str) -> Dict:
        """Add a domain to the virtual domains map."""
        try:
            result = run_privileged(['cat', cls.VIRTUAL_DOMAINS_FILE])
            content = result.stdout or ''
            # Dedupe on the line's domain field, not a raw substring — with
            # sub.example.com already mapped, adding example.com used to
            # no-op while still reporting success.
            existing = {line.split()[0].lower()
                        for line in content.splitlines() if line.split()}
            if domain.lower() not in existing:
                entry = f'{domain} OK\n'
                if content and not content.endswith('\n'):
                    entry = '\n' + entry
                write_privileged_file(cls.VIRTUAL_DOMAINS_FILE, entry, append=True)
                run_privileged(['postmap', cls.VIRTUAL_DOMAINS_FILE])
                run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def remove_domain(cls, domain: str) -> Dict:
        """Remove a domain from the virtual domains map."""
        try:
            result = run_privileged(['cat', cls.VIRTUAL_DOMAINS_FILE])
            lines = [l for l in (result.stdout or '').splitlines() if not l.startswith(f'{domain} ')]
            write_privileged_file(cls.VIRTUAL_DOMAINS_FILE, '\n'.join(lines) + '\n')
            run_privileged(['postmap', cls.VIRTUAL_DOMAINS_FILE])

            # Also remove mailboxes for this domain (address-token match, so
            # user@example.com.br mailboxes survive removing example.com)
            result = run_privileged(['cat', cls.VIRTUAL_MAILBOXES_FILE])
            lines = [l for l in (result.stdout or '').splitlines()
                     if not cls._mentions_domain(l, domain)]
            write_privileged_file(cls.VIRTUAL_MAILBOXES_FILE, '\n'.join(lines) + '\n')
            run_privileged(['postmap', cls.VIRTUAL_MAILBOXES_FILE])

            # Remove aliases for this domain
            result = run_privileged(['cat', cls.VIRTUAL_ALIASES_FILE])
            lines = [l for l in (result.stdout or '').splitlines()
                     if not cls._mentions_domain(l, domain)]
            write_privileged_file(cls.VIRTUAL_ALIASES_FILE, '\n'.join(lines) + '\n')
            run_privileged(['postmap', cls.VIRTUAL_ALIASES_FILE])

            run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def add_mailbox(cls, email: str, domain: str, username: str) -> Dict:
        """Add a mailbox to the virtual mailbox map."""
        try:
            mailbox_path = f'{domain}/{username}/Maildir/'
            cls._append_map_entry(cls.VIRTUAL_MAILBOXES_FILE, f'{email} {mailbox_path}\n')
            run_privileged(['postmap', cls.VIRTUAL_MAILBOXES_FILE])
            run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def remove_mailbox(cls, email: str) -> Dict:
        """Remove a mailbox from the virtual mailbox map."""
        try:
            result = run_privileged(['cat', cls.VIRTUAL_MAILBOXES_FILE])
            lines = [l for l in (result.stdout or '').splitlines() if not l.startswith(f'{email} ')]
            write_privileged_file(cls.VIRTUAL_MAILBOXES_FILE, '\n'.join(lines) + '\n')
            run_privileged(['postmap', cls.VIRTUAL_MAILBOXES_FILE])
            run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def add_alias(cls, source: str, destination: str) -> Dict:
        """Add a virtual alias."""
        try:
            cls._append_map_entry(cls.VIRTUAL_ALIASES_FILE, f'{source} {destination}\n')
            run_privileged(['postmap', cls.VIRTUAL_ALIASES_FILE])
            run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def remove_alias(cls, source: str) -> Dict:
        """Remove a virtual alias."""
        try:
            result = run_privileged(['cat', cls.VIRTUAL_ALIASES_FILE])
            lines = [l for l in (result.stdout or '').splitlines() if not l.startswith(f'{source} ')]
            write_privileged_file(cls.VIRTUAL_ALIASES_FILE, '\n'.join(lines) + '\n')
            run_privileged(['postmap', cls.VIRTUAL_ALIASES_FILE])
            run_privileged(['postfix', 'reload'])
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def get_queue(cls) -> Dict:
        """Get the Postfix mail queue."""
        try:
            result = run_checked(['mailq'], timeout=None)
            output = result['output']

            if 'Mail queue is empty' in output:
                return {'success': True, 'queue': [], 'total': 0}

            queue = []
            current = None

            for line in output.splitlines():
                # Queue ID line: starts with hex ID
                id_match = re.match(r'^([A-F0-9]+)\s+(\d+)\s+(\S+\s+\S+\s+\S+)\s+(.+)', line)
                if id_match:
                    if current:
                        queue.append(current)
                    current = {
                        'queue_id': id_match.group(1),
                        'size': int(id_match.group(2)),
                        'arrival_time': id_match.group(3),
                        'sender': id_match.group(4),
                        'recipients': [],
                        'error': None,
                    }
                elif current and line.strip().startswith('('):
                    # Error message
                    current['error'] = line.strip().strip('()')
                elif current and line.strip() and not line.startswith('-'):
                    # Recipient line
                    current['recipients'].append(line.strip())

            if current:
                queue.append(current)

            return {'success': True, 'queue': queue, 'total': len(queue)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def flush_queue(cls) -> Dict:
        """Flush the Postfix mail queue."""
        try:
            result = run_privileged(['postfix', 'flush'])
            if result.returncode == 0:
                return {'success': True, 'message': 'Mail queue flushed'}
            return {'success': False, 'error': result.stderr or 'Flush failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def delete_from_queue(cls, queue_id: str) -> Dict:
        """Delete a message from the mail queue."""
        try:
            result = run_privileged(['postsuper', '-d', queue_id])
            if result.returncode == 0:
                return {'success': True, 'message': f'Message {queue_id} deleted from queue'}
            return {'success': False, 'error': result.stderr or 'Delete failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def get_logs(cls, lines: int = 100) -> Dict:
        """Get recent mail log entries."""
        try:
            log_files = ['/var/log/mail.log', '/var/log/maillog']
            log_file = None
            for f in log_files:
                if os.path.exists(f):
                    log_file = f
                    break

            if not log_file:
                return {'success': True, 'logs': [], 'message': 'No mail log file found'}

            result = run_privileged(['tail', '-n', str(lines), log_file])
            log_lines = (result.stdout or '').splitlines()

            return {'success': True, 'logs': log_lines, 'total': len(log_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def reload(cls) -> Dict:
        """Reload Postfix configuration."""
        try:
            result = run_privileged(['postfix', 'reload'])
            if result.returncode == 0:
                return {'success': True, 'message': 'Postfix reloaded'}
            return {'success': False, 'error': result.stderr or 'Reload failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def restart(cls) -> Dict:
        """Restart Postfix."""
        try:
            result = ServiceControl.restart('postfix', timeout=30)
            return ServiceControl.result_dict(result, 'Postfix restarted',
                                              fallback='Restart failed')
        except Exception as e:
            return {'success': False, 'error': str(e)}

    POSTFIX_SASL_PASSWD = '/etc/postfix/sasl_passwd'

    @classmethod
    def configure_relay(cls, host: str, port: int = 587, username: str = None,
                        password: str = None, use_tls: bool = True) -> Dict:
        """Route outbound mail through an external SMTP smarthost (relayhost).

        Sets relayhost + SASL auth in main.cf and writes the credential map. Linux
        / Postfix only — the caller persists the config regardless of platform.
        """
        try:
            relay = f'[{host}]:{port}'
            run_privileged(['postconf', '-e', f'relayhost={relay}'])
            if username:
                run_privileged(['postconf', '-e', 'smtp_sasl_auth_enable=yes'])
                run_privileged(['postconf', '-e', f'smtp_sasl_password_maps=hash:{cls.POSTFIX_SASL_PASSWD}'])
                run_privileged(['postconf', '-e', 'smtp_sasl_security_options=noanonymous'])
                write_privileged_file(cls.POSTFIX_SASL_PASSWD,
                                      f'{relay} {username}:{password or ""}\n', mode='600')
                run_privileged(['postmap', cls.POSTFIX_SASL_PASSWD])
            run_privileged(['postconf', '-e', f'smtp_tls_security_level={"encrypt" if use_tls else "may"}'])
            run_privileged(['postfix', 'reload'])
            return {'success': True, 'message': f'Relaying outbound mail through {relay}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @classmethod
    def disable_relay(cls) -> Dict:
        """Stop relaying through a smarthost (revert to direct delivery)."""
        try:
            run_privileged(['postconf', '-e', 'relayhost='])
            run_privileged(['postconf', '-e', 'smtp_sasl_auth_enable=no'])
            run_privileged(['postconf', '-e', 'smtp_sasl_password_maps='])
            run_privileged(['rm', '-f', cls.POSTFIX_SASL_PASSWD, cls.POSTFIX_SASL_PASSWD + '.db'], check=False)
            run_privileged(['postfix', 'reload'])
            return {'success': True, 'message': 'Outbound relay disabled'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
