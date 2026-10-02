// Right-side drawer for the backup "Protection" panel: shows one backup run's
// details (status, timing, size, cost, storage, verification) plus the run-level
// actions (restore, verify remote, download, delete). Always renders the Drawer
// so its open/close slide animation plays even when there's no run selected.
import { Drawer, Pill } from '@/components/ds';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import { Archive, RotateCcw, ShieldCheck, Download, Trash2, ExternalLink } from 'lucide-react';
import { humanSize, formatMoney, formatDateTime, statusKind, storageLabel } from './format';
import { useTranslation } from 'react-i18next';

export default function BackupDetailDrawer({ run, open, onClose, onRestore, onVerify, onDelete, onDownload }) {
    const { t } = useTranslation();
    // No run selected: render an empty Drawer so the close animation still plays.
    if (!run) {
        return (
            <Drawer open={open} onOpenChange={(v) => !v && onClose()} title={t('app.backupDetailDrawer.backup', 'Backup')} width={520}>
                <div />
            </Drawer>
        );
    }

    const title = run.metadata?.backup_name || `Backup #${run.id}`;
    const verification = run.remote_key
        ? (run.verified ? 'Verified' : 'Unverified')
        : 'Local only';

    return (
        <Drawer
            open={open}
            onOpenChange={(v) => !v && onClose()}
            title={title}
            subtitle={run.kind}
            icon={<Archive size={18} />}
            width={520}
        >
            <div className="backup-detail-drawer">
                <div className="backup-detail-drawer__head">
                    <Pill kind={statusKind(run.status)}>{run.status}</Pill>
                    {run.verified && <Pill kind="green" dot={false}>{t('app.backupDetailDrawer.verified', 'Verified')}</Pill>}
                </div>

                {run.status === 'failed' && run.error_message && (
                    <p className="backup-detail-drawer__error">{run.error_message}</p>
                )}

                <div className="backup-detail-drawer__meta">
                    <div className="backup-detail-drawer__row"><span>{t('common.labels.created', 'Created')}</span><span>{formatDateTime(run.started_at)}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('app.backupDetailDrawer.finished', 'Finished')}</span><span>{formatDateTime(run.finished_at)}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('common.labels.duration', 'Duration')}</span><span>{run.duration_seconds != null ? `${run.duration_seconds}s` : '—'}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('common.labels.type', 'Type')}</span><span>{run.kind}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('app.backupDetailDrawer.compression', 'Compression')}</span><span>{run.compression || '—'}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('common.labels.storage', 'Storage')}</span><span>{storageLabel(run)}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('app.backupDetailDrawer.sizeLocal', 'Size (local)')}</span><span>{humanSize(run.size_local)}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('app.backupDetailDrawer.sizeRemote', 'Size (remote)')}</span><span>{run.size_remote ? humanSize(run.size_remote) : '—'}</span></div>
                    <div className="backup-detail-drawer__row"><span>{t('app.backupDetailDrawer.verification', 'Verification')}</span><span>{verification}</span></div>
                </div>

                <div className="backup-detail-drawer__cost">
                    {t('app.backupDetailDrawer.estimatedCost', 'Estimated cost:')} {formatMoney(run.cost_local)} {t('app.backupDetailDrawer.local', '(local) +')} {formatMoney(run.cost_remote)} {t('app.backupDetailDrawer.remote', '(remote) =')} {formatMoney(run.cost_total)} total
                </div>

                <div className="backup-detail-drawer__actions">
                    <Button variant="primary" size="sm" disabled={run.status !== 'success'} onClick={() => onRestore(run)}>
                        <RotateCcw size={14} /> {t('common.actions.restore', 'Restore')}
                    </Button>
                    {run.remote_key && (
                        <Button variant="outline" size="sm" onClick={() => onVerify(run)}>
                            <ShieldCheck size={14} /> {t('app.backupDetailDrawer.verifyRemote', 'Verify remote')}
                        </Button>
                    )}
                    {onDownload && run.storage_path && (
                        <Button variant="outline" size="sm" onClick={() => onDownload(run)}>
                            <Download size={14} /> {t('common.actions.download', 'Download')}
                        </Button>
                    )}
                    <Button variant="destructive" size="sm" onClick={() => onDelete(run)}>
                        <Trash2 size={14} /> {t('common.actions.delete', 'Delete')}
                    </Button>
                </div>

                {run.job_id && (
                    <Link className="backup-detail-drawer__joblink" to="/monitoring/jobs">
                        <ExternalLink size={13} /> {t('app.backupDetailDrawer.viewJob', 'View job')}
                    </Link>
                )}
            </div>
        </Drawer>
    );
}
