import { io } from 'socket.io-client';
import { SOCKET_EVENTS } from '../constants/events';
import { TUNNEL_BASE, storageKey } from './tunnelBase.js';

const getSocketUrl = () => {
    if (import.meta.env.DEV) return window.location.origin;
    return import.meta.env.VITE_API_URL?.replace(/\/api\/v1\/?$/, '') || window.location.origin;
};

const SOCKET_URL = getSocketUrl();

class SocketService {
    constructor() {
        this.socket = null;
        this.listeners = new Map();
    }

    connect() {
        const token = localStorage.getItem(storageKey('access_token'));
        if (!token) {
            console.warn('No token available for WebSocket connection');
            return;
        }

        if (this.socket?.connected) {
            return;
        }

        this.socket = io(SOCKET_URL, {
            auth: { token },
            // Through ServerKit Cloud's relay the panel lives under a prefix,
            // and so does its Socket.IO endpoint.
            ...(TUNNEL_BASE ? { path: `${TUNNEL_BASE}/socket.io` } : {}),
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000
        });

        this.socket.on('connect', () => {
            console.log('WebSocket connected');
            this.emit('connected');
        });

        this.socket.on('disconnect', (reason) => {
            console.log('WebSocket disconnected:', reason);
            this.emit('disconnected', reason);
        });

        this.socket.on('error', (error) => {
            console.error('WebSocket error:', error);
            this.emit('error', error);
        });

        this.socket.on('metrics', (data) => {
            this.emit('metrics', data);
        });

        this.socket.on('log_line', (data) => {
            this.emit('log_line', data);
        });

        this.socket.on('log_error', (data) => {
            this.emit('log_error', data);
        });

        // New in-app notification pushed to this user's room by the bus.
        this.socket.on('notification', (data) => {
            this.emit('notification', data);
        });

        // Deploy Console live push (plan 51): batched log lines + status
        // summaries for a deployment job. Accelerator over after_id polling.
        this.socket.on('deploy_log', (data) => {
            this.emit('deploy_log', data);
        });

        this.socket.on('deploy_status', (data) => {
            this.emit('deploy_status', data);
        });

        this.socket.on(SOCKET_EVENTS.RUN_LOG, (data) => {
            this.emit(SOCKET_EVENTS.RUN_LOG, data);
        });

        this.socket.on(SOCKET_EVENTS.RUN_STATUS, (data) => {
            this.emit(SOCKET_EVENTS.RUN_STATUS, data);
        });

        this.socket.on(SOCKET_EVENTS.CONTAINER_LOG, (data) => {
            this.emit(SOCKET_EVENTS.CONTAINER_LOG, data);
        });

        this.socket.on(SOCKET_EVENTS.CONTAINER_LOG_ERROR, (data) => {
            this.emit(SOCKET_EVENTS.CONTAINER_LOG_ERROR, data);
        });

        this.socket.on(SOCKET_EVENTS.CONTAINER_LOG_ENDED, (data) => {
            this.emit(SOCKET_EVENTS.CONTAINER_LOG_ENDED, data);
        });
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }

    subscribeMetrics() {
        if (this.socket?.connected) {
            this.socket.emit('subscribe_metrics');
        }
    }

    unsubscribeMetrics() {
        if (this.socket?.connected) {
            this.socket.emit('unsubscribe_metrics');
        }
    }

    subscribeLogs(filepath) {
        if (this.socket?.connected) {
            this.socket.emit('subscribe_logs', { path: filepath });
        }
    }

    unsubscribeLogs() {
        if (this.socket?.connected) {
            this.socket.emit('unsubscribe_logs');
        }
    }

    subscribeDeploy(jobId) {
        if (this.socket?.connected) {
            this.socket.emit('subscribe_deploy', { job_id: jobId });
        }
    }

    unsubscribeDeploy(jobId) {
        if (this.socket?.connected) {
            this.socket.emit('unsubscribe_deploy', { job_id: jobId });
        }
    }

    subscribeRun(runKind, runId) {
        if (this.socket?.connected && runKind && runId != null) {
            this.socket.emit('subscribe_run', { run_kind: runKind, run_id: runId });
        }
    }

    unsubscribeRun(runKind, runId) {
        if (this.socket?.connected && runKind && runId != null) {
            this.socket.emit('unsubscribe_run', { run_kind: runKind, run_id: runId });
        }
    }

    subscribeContainerLogs(appId, options = {}) {
        if (this.socket?.connected && appId != null) {
            this.socket.emit('subscribe_container_logs', {
                app_id: appId,
                tail: options.tail || 200,
                ...(options.service ? { service: options.service } : {}),
            });
        }
    }

    unsubscribeContainerLogs() {
        if (this.socket?.connected) this.socket.emit('unsubscribe_container_logs');
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);

        return () => {
            this.listeners.get(event)?.delete(callback);
        };
    }

    off(event, callback) {
        this.listeners.get(event)?.delete(callback);
    }

    emit(event, data) {
        this.listeners.get(event)?.forEach(callback => {
            try {
                callback(data);
            } catch (e) {
                console.error('Socket listener error:', e);
            }
        });
    }
}

export const socketService = new SocketService();
export default socketService;
