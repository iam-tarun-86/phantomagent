const WS_URL = 'ws://localhost:8000/ws';
const API_URL = 'http://localhost:8000/api';

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

        // Clear any existing reconnect timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        this.intentionallyClosed = false;
        this.ws = new WebSocket(WS_URL);

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

        this.ws.onclose = () => {
            console.log('[WS] Disconnected');
            this.connected = false;
            this.emit('connection', { status: 'disconnected' });
            this.ws = null;

            // Only auto-reconnect if we didn't intentionally close
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
            const response = await fetch(`${API_URL}/threats/${threatId}/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
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
            const response = await fetch(`${API_URL}/threats/${threatId}/dismiss`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
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