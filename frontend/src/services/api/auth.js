// Authentication, 2FA, SSO, user management, permissions, invitations

// Auth endpoints
export async function getSetupStatus() {
    return this.request('/auth/setup-status');
}

export async function login(email, password) {
    const data = await this.request('/auth/login', {
        method: 'POST',
        body: { email, password },
    });
    if (data.access_token) {
        this.setTokens(data.access_token, data.refresh_token);
    }
    return data;
}

export async function register(email, username, password, inviteToken, setupCode) {
    const body = { email, username, password };
    if (inviteToken) body.invite_token = inviteToken;
    if (setupCode) body.setup_code = setupCode;
    const data = await this.request('/auth/register', {
        method: 'POST',
        body,
    });
    this.setTokens(data.access_token, data.refresh_token);
    return data;
}

export async function completeOnboarding(useCases, installedExtensions = [], securityPosture = 'minimal') {
    return this.request('/auth/complete-onboarding', {
        method: 'POST',
        body: {
            use_cases: useCases,
            installed_extensions: installedExtensions,
            security_posture: securityPosture,
        },
    });
}

export async function logout() {
    try {
        await this.request('/auth/logout', { method: 'POST' });
    } finally {
        this.clearTokens();
    }
}

export async function getCurrentUser() {
    return this.request('/auth/me');
}

export async function updateCurrentUser(data) {
    const response = await this.request('/auth/me', {
        method: 'PUT',
        body: data
    });
    if (response.access_token) {
        this.setTokens(response.access_token, response.refresh_token);
    }
    return response;
}

// One-time login links
export async function mintLoginLink(data = {}) {
    return this.request('/auth/login-links', {
        method: 'POST',
        body: data,
    });
}

export async function getLoginLinks() {
    return this.request('/auth/login-links');
}

export async function revokeLoginLink(id) {
    return this.request(`/auth/login-links/${id}`, { method: 'DELETE' });
}

export async function redeemLoginLink(token) {
    const data = await this.request('/auth/login-links/redeem', {
        method: 'POST',
        body: { token },
    });
    if (data.access_token) {
        this.setTokens(data.access_token, data.refresh_token);
    }
    return data;
}

// Opened from ServerKit Cloud through its relay: the relay hands the panel
// Cloud's signed grant, and the panel signs in the user with that email.
export async function connectSession() {
    const data = await this.request('/auth/connect-session', { method: 'POST' });
    if (data.access_token) {
        this.setTokens(data.access_token, data.refresh_token);
    }
    return data;
}

// Demo mode
export async function getDemoInfo() {
    return this.request('/auth/demo-info');
}

// Admin - User Management endpoints
export async function getUsers() {
    return this.request('/admin/users');
}

export async function getUser(userId) {
    return this.request(`/admin/users/${userId}`);
}

export async function createUser(userData) {
    return this.request('/admin/users', {
        method: 'POST',
        body: userData
    });
}

export async function updateUser(userId, userData) {
    return this.request(`/admin/users/${userId}`, {
        method: 'PUT',
        body: userData
    });
}

export async function deleteUser(userId) {
    return this.request(`/admin/users/${userId}`, {
        method: 'DELETE'
    });
}

// Admin - Audit Log endpoints
export async function getAuditLogs(params = {}) {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.append('page', params.page);
    if (params.per_page) searchParams.append('per_page', params.per_page);
    if (params.action) searchParams.append('action', params.action);
    if (params.user_id) searchParams.append('user_id', params.user_id);
    if (params.target_type) searchParams.append('target_type', params.target_type);
    const query = searchParams.toString();
    return this.request(`/admin/audit-logs${query ? '?' + query : ''}`);
}

export async function getAuditLogActions() {
    return this.request('/admin/audit-logs/actions');
}

// Admin - Permissions endpoints
export async function getUserPermissions(userId) {
    return this.request(`/admin/users/${userId}/permissions`);
}

export async function updateUserPermissions(userId, permissions) {
    return this.request(`/admin/users/${userId}/permissions`, {
        method: 'PUT',
        body: { permissions }
    });
}

export async function resetUserPermissions(userId) {
    return this.request(`/admin/users/${userId}/permissions/reset`, {
        method: 'POST'
    });
}

export async function getPermissionTemplates() {
    return this.request('/admin/permissions/templates');
}

// Admin - Invitations endpoints
export async function getInvitations(status) {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    return this.request(`/admin/invitations/${query}`);
}

export async function createInvitation(data) {
    return this.request('/admin/invitations/', {
        method: 'POST',
        body: data
    });
}

export async function revokeInvitation(id) {
    return this.request(`/admin/invitations/${id}`, {
        method: 'DELETE'
    });
}

export async function resendInvitation(id) {
    return this.request(`/admin/invitations/resend/${id}`, {
        method: 'POST'
    });
}

export async function validateInvitation(token) {
    return this.request(`/admin/invitations/validate/${token}`);
}

// Admin - Activity endpoints
export async function getActivitySummary() {
    return this.request('/admin/activity/summary');
}

export async function getActivityFeed(params = {}) {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.append('page', params.page);
    if (params.per_page) searchParams.append('per_page', params.per_page);
    if (params.user_id) searchParams.append('user_id', params.user_id);
    if (params.action) searchParams.append('action', params.action);
    if (params.target_type) searchParams.append('target_type', params.target_type);
    if (params.target_id) searchParams.append('target_id', params.target_id);
    if (params.start_date) searchParams.append('start_date', params.start_date);
    if (params.end_date) searchParams.append('end_date', params.end_date);
    const query = searchParams.toString();
    return this.request(`/admin/activity/feed${query ? '?' + query : ''}`);
}

// Two-Factor Authentication endpoints
export async function get2FAStatus() {
    return this.request('/auth/2fa/status');
}

export async function initiate2FASetup() {
    return this.request('/auth/2fa/setup', { method: 'POST' });
}

export async function confirm2FASetup(code) {
    return this.request('/auth/2fa/setup/confirm', {
        method: 'POST',
        body: { code }
    });
}

export async function disable2FA(code) {
    return this.request('/auth/2fa/disable', {
        method: 'POST',
        body: { code }
    });
}

export async function regenerateBackupCodes(code) {
    return this.request('/auth/2fa/backup-codes/regenerate', {
        method: 'POST',
        body: { code }
    });
}

export async function verify2FA(tempToken, code) {
    return this.request('/auth/2fa/verify', {
        method: 'POST',
        body: { temp_token: tempToken, code }
    });
}

// SSO / OAuth
export async function getSSOProviders() {
    return this.request('/sso/providers');
}

export async function startSSOAuth(provider, redirectUri) {
    return this.request(`/sso/authorize/${provider}?redirect_uri=${encodeURIComponent(redirectUri)}`);
}

export async function completeSSOAuth(provider, code, state, redirectUri) {
    const data = await this.request(`/sso/callback/${provider}`, {
        method: 'POST',
        body: { code, state, redirect_uri: redirectUri },
    });
    if (data.access_token) {
        this.setTokens(data.access_token, data.refresh_token);
    }
    return data;
}

export async function getSSOIdentities() {
    return this.request('/sso/identities');
}

export async function linkSSOProvider(provider, code, state, redirectUri) {
    return this.request(`/sso/link/${provider}`, {
        method: 'POST',
        body: { code, state, redirect_uri: redirectUri },
    });
}

export async function unlinkSSOProvider(provider) {
    return this.request(`/sso/link/${provider}`, { method: 'DELETE' });
}

// SSO Admin
export async function getSSOConfig() {
    return this.request('/sso/admin/config');
}

export async function updateSSOProviderConfig(provider, config) {
    return this.request(`/sso/admin/config/${provider}`, {
        method: 'PUT',
        body: config,
    });
}

export async function testSSOProvider(provider) {
    return this.request(`/sso/admin/test/${provider}`, { method: 'POST' });
}

export async function updateSSOGeneralSettings(settings) {
    return this.request('/sso/admin/general', {
        method: 'PUT',
        body: settings,
    });
}

// API Keys
export async function getApiKeys() {
    return this.request('/api-keys/');
}

export async function getApiKeyScopes() {
    return this.request('/api-keys/scopes');
}

export async function createApiKey(data) {
    return this.request('/api-keys/', { method: 'POST', body: data });
}

export async function getApiKey(id) {
    return this.request(`/api-keys/${id}`);
}

export async function updateApiKey(id, data) {
    return this.request(`/api-keys/${id}`, { method: 'PUT', body: data });
}

export async function revokeApiKey(id) {
    return this.request(`/api-keys/${id}`, { method: 'DELETE' });
}

export async function rotateApiKey(id) {
    return this.request(`/api-keys/${id}/rotate`, { method: 'POST' });
}

// Event Subscriptions (Webhooks)
export async function getEventSubscriptions() {
    return this.request('/event-subscriptions/');
}

export async function createEventSubscription(data) {
    return this.request('/event-subscriptions/', { method: 'POST', body: data });
}

export async function getAvailableEvents() {
    return this.request('/event-subscriptions/events');
}

export async function getEventSubscription(id) {
    return this.request(`/event-subscriptions/${id}`);
}

export async function updateEventSubscription(id, data) {
    return this.request(`/event-subscriptions/${id}`, { method: 'PUT', body: data });
}

export async function deleteEventSubscription(id) {
    return this.request(`/event-subscriptions/${id}`, { method: 'DELETE' });
}

export async function testEventSubscription(id) {
    return this.request(`/event-subscriptions/${id}/test`, { method: 'POST' });
}

export async function getEventDeliveries(id, page = 1) {
    return this.request(`/event-subscriptions/${id}/deliveries?page=${encodeURIComponent(page)}`);
}

export async function retryEventDelivery(subId, deliveryId) {
    return this.request(`/event-subscriptions/${subId}/deliveries/${deliveryId}/retry`, { method: 'POST' });
}

// API Analytics
export async function getApiAnalyticsOverview(period = '24h') {
    return this.request(`/api-analytics/overview?period=${encodeURIComponent(period)}`);
}

export async function getApiAnalyticsEndpoints(period = '24h', limit = 20) {
    return this.request(`/api-analytics/endpoints?period=${encodeURIComponent(period)}&limit=${encodeURIComponent(limit)}`);
}

export async function getApiAnalyticsErrors(period = '24h') {
    return this.request(`/api-analytics/errors?period=${encodeURIComponent(period)}`);
}

export async function getApiAnalyticsTimeseries(period = '24h', interval = 'hour') {
    return this.request(`/api-analytics/timeseries?period=${encodeURIComponent(period)}&interval=${encodeURIComponent(interval)}`);
}

export async function getApiKeyUsage(keyId, period = '24h') {
    return this.request(`/api-analytics/keys/${keyId}/usage?period=${encodeURIComponent(period)}`);
}
