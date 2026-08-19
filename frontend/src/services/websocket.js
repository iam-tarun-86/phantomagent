import { authFetch, getToken } from './auth';

/**
 * Resolve the WebSocket URL from the page origin so the Vite proxy handles it in dev and
 * the app still works when served from any other host. Override with VITE_WS_URL.
 */
function resolveWsUrl() {
    if (import.meta.env.VITE_WS_URL) return import.meta.env.VITE_WS_URL;
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    return `${scheme}://${window.location.host}/ws`;
}

class WebSocketService {
    constructor() {
        this.ws = null;
        this.listeners = new Map();
        this.connected = false;
        this.reconnectTimer = null;
        this.intentionallyClosed = false;
    }

    connect() {
        // Don't connect if already connecting or open
        if (this.ws?.readyState === WebSocket.OPEN || this.ws?.readyState === WebSocket.CONNECTING) {
            return;
        }

        // The socket is authenticated; without a token the server would just close it.
        const token = getToken();
        if (!token) {
            console.warn('[WS] No auth token — not connecting');
            return;
        }

        // Clear any existing reconnect timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        this.intentionallyClosed = false;
        this.ws = new WebSocket(`${resolveWsUrl()}?token=${encodeURIComponent(token)}`);

        this.ws.onopen = () => {
            console.log('[WS] Connected');
            this.connected = true;
            this.emit('connection', { status: 'connected' });
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                console.log('[WS] Received:', msg.type);
                this.emit(msg.type, msg.data);
            } catch (err) {
                console.error('[WS] Parse error:', err);
            }
        };

        this.ws.onclose = (event) => {
            console.log('[WS] Disconnected');
            this.connected = false;
            this.emit('connection', { status: 'disconnected' });
            this.ws = null;

            // 1008 = policy violation, i.e. the server rejected our token. Reconnecting
            // with the same credentials would just loop.
            if (event.code === 1008) {
                console.error('[WS] Authentication rejected — not retrying');
                this.emit('auth_error', { reason: event.reason || 'Invalid token' });
                return;
            }

            if (!this.intentionallyClosed) {
                this.reconnectTimer = setTimeout(() => this.connect(), 3000);
            }
        };

        this.ws.onerror = (err) => {
            console.error('[WS] Error:', err);
        };
    }

    disconnect() {
        this.intentionallyClosed = true;

        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        if (this.ws) {
            if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
                this.ws.close();
            }
            this.ws = null;
        }
    }

    async approveThreat(threatId) {
        try {
            const response = await authFetch(`/threats/${threatId}/approve`, { method: 'POST' });
            const data = await response.json();
            console.log('[HTTP] Approve response:', data);
            return data;
        } catch (err) {
            console.error('[HTTP] Approve error:', err);
            throw err;
        }
    }

    async dismissThreat(threatId) {
        try {
            const response = await authFetch(`/threats/${threatId}/dismiss`, { method: 'POST' });
            const data = await response.json();
            console.log('[HTTP] Dismiss response:', data);
            return data;
        } catch (err) {
            console.error('[HTTP] Dismiss error:', err);
            throw err;
        }
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);
        return () => this.listeners.get(event).delete(callback);
    }

    emit(event, data) {
        this.listeners.get(event)?.forEach(cb => cb(data));
    }
}

const wsService = new WebSocketService();
export default wsService;
