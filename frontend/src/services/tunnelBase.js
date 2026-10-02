// Where this panel is mounted.
//
// Normally at the root of its own host. When ServerKit Cloud opens it
// through the relay, it lives under a path instead —
// https://relay.serverkit.ai/t/dev_ABC123/ — and every absolute URL the SPA
// builds (router, API, Socket.IO) has to carry that prefix, or it lands on
// the relay's root where no server answers.
//
// The panel's own server says which prefix it was reached through by
// setting `window.__SERVERKIT_BASE__` in the page it serves; the path itself
// is the fallback.
const PREFIX = /^\/t\/dev_[A-Za-z0-9_-]+/;

function detect() {
    if (typeof window === 'undefined') return '';
    const injected = window.__SERVERKIT_BASE__;
    if (typeof injected === 'string' && PREFIX.test(injected)) return injected.replace(/\/+$/, '');
    const match = window.location.pathname.match(PREFIX);
    return match ? match[0] : '';
}

export const TUNNEL_BASE = detect();

export const inTunnel = TUNNEL_BASE !== '';

// Every server opened through the relay shares the relay's origin, and with
// it localStorage. Keys are namespaced by prefix so two panels open in one
// browser do not overwrite each other's sign-in.
export const storageKey = (name) => (TUNNEL_BASE ? `${name}@${TUNNEL_BASE}` : name);
