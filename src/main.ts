// Synapse Dashboard — Entry point
import './otel';
import './dashboard.css';
import './eink';
import './api';
import { toast, setLoading } from './toast';
import { connectSSE, setRefreshAll } from './sse';
import { loadStatus, refreshAll } from './stats';
import { loadDockerServices, loadKumaMonitors, loadNPMProxies, loadHistory, loadEvents, runReconcile } from './tabs';
import { loadSettings, saveSettings, testConnection, loadKumaInstances, showKumaInstanceForm, hideKumaInstanceForm, saveKumaInstance, loadNPMInstances, showNPMInstanceForm, hideNPMInstanceForm, saveNPMInstance, loadAutheliaInstances, showAutheliaInstanceForm, hideAutheliaInstanceForm, saveAutheliaInstance } from './settings';
import { loadAutheliaInstanceSelector, loadAutheliaDashboard, loadAutheliaStatus, loadAutheliaAlerts, loadAutheliaTempAccess, resolveAlert, revokeTempAccess, runAutheliaSync } from './authelia';
import { loadAlertRules, loadIncidents, saveAlertRule, resetAlertRuleForm } from './alerts';
import { setupLogFilters, loadLogs, connectLogSSE, toggleLogMeta, isLogsLoaded } from './logs';
import { getVisibleTabButtons } from './tabVisibility';
import './tabVisibility';

// Wire SSE refreshAll reference
setRefreshAll(refreshAll);

// ─── Confirmation Modal ───────────────────────────────────────
function showConfirmModal(message: string, okText?: string): Promise<boolean> {
    return new Promise(function(resolve) {
        var modalEl = document.getElementById('confirm-modal') as HTMLElement;
        var bodyEl = document.getElementById('confirm-modal-body')!;
        var okBtn = document.getElementById('confirm-modal-ok')!;
        var cancelBtn = document.getElementById('confirm-modal-cancel')!;

        bodyEl.textContent = message;
        if (okText) okBtn.textContent = okText;
        else okBtn.textContent = 'Confirm';

        var modal = new bootstrap.Modal(modalEl);
        modal.show();

        function cleanup() {
            modal.hide();
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            modalEl.removeEventListener('hidden.bs.modal', onHide);
        }
        function onOk() { cleanup(); resolve(true); }
        function onCancel() { cleanup(); resolve(false); }
        function onHide() { cleanup(); resolve(false); }

        okBtn.addEventListener('click', onOk);
        cancelBtn.addEventListener('click', onCancel);
        modalEl.addEventListener('hidden.bs.modal', onHide);
    });
}

// Event listeners
document.getElementById('btn-docker')!.addEventListener('click', function() {
    showConfirmModal('Start Docker Compose sync?', 'Start Sync').then(function(ok) {
        if (ok) startSync('docker');
    });
});
document.getElementById('btn-npm')!.addEventListener('click', function() {
    showConfirmModal('Start NPM Proxy Hosts sync?', 'Start Sync').then(function(ok) {
        if (ok) startSync('npm');
    });
});
document.getElementById('btn-auth-dryrun')!.addEventListener('click', function() { runAutheliaSync(true); });
document.getElementById('btn-auth-sync')!.addEventListener('click', function() {
    showConfirmModal('Auto-add missing CNAMEs to Authelia config? This modifies the Authelia configuration file.', 'Sync').then(function(ok) {
        if (ok) runAutheliaSync(false);
    });
});
document.getElementById('btn-ta-submit')!.addEventListener('click', function() {
    var ip = (document.getElementById('ta-ip') as HTMLInputElement).value.trim();
    var reason = (document.getElementById('ta-reason') as HTMLInputElement).value.trim();
    var duration = (document.getElementById('ta-duration') as HTMLInputElement).value.trim();
    if (!ip) { toast('IP address is required', 'error'); return; }
    if (!duration) { toast('Duration is required', 'error'); return; }

    apiFetch('/api/authelia/temp-access', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: ip, reason: reason, duration: duration }) })
        .then(function(r){return r.json();})
        .then(function(d: any) { if (d.error) { toast(d.error, 'error'); return; } toast('Temp access rule added', 'success'); (document.getElementById('ta-ip') as HTMLInputElement).value = ''; (document.getElementById('ta-reason') as HTMLInputElement).value = ''; (document.getElementById('ta-duration') as HTMLInputElement).value = ''; loadAutheliaTempAccess(); })
        .catch(function(err: Error) { if (err.message === 'not authenticated') return; toast('Failed to add rule', 'error'); });
});

document.getElementById('btn-logout')!.addEventListener('click', logout);
document.getElementById('settings-form')!.addEventListener('submit', saveSettings);

// Kuma instance management
document.getElementById('btn-kuma-add')!.addEventListener('click', function() { showKumaInstanceForm(null); });
document.getElementById('btn-kuma-save')!.addEventListener('click', saveKumaInstance);
document.getElementById('btn-kuma-cancel')!.addEventListener('click', hideKumaInstanceForm);

// NPM instance management
document.getElementById('btn-npm-add')!.addEventListener('click', function() { showNPMInstanceForm(null); });
document.getElementById('btn-npm-save')!.addEventListener('click', saveNPMInstance);
document.getElementById('btn-npm-cancel')!.addEventListener('click', hideNPMInstanceForm);

// Authelia instance management
document.getElementById('btn-authelia-add')!.addEventListener('click', function() { showAutheliaInstanceForm(null); });
document.getElementById('btn-authelia-save')!.addEventListener('click', saveAutheliaInstance);
document.getElementById('btn-authelia-cancel')!.addEventListener('click', hideAutheliaInstanceForm);

// Alerts rule editor
document.getElementById('btn-alert-rule-save')!.addEventListener('click', saveAlertRule);
document.getElementById('btn-alert-rule-cancel')!.addEventListener('click', function() {
    resetAlertRuleForm();
    var collapse = bootstrap.Collapse.getInstance(document.getElementById('alert-rule-form')!);
    if (collapse) collapse.hide();
});
document.getElementById('incident-filter-status')!.addEventListener('change', loadIncidents);

// Authelia instance selector
document.getElementById('auth-instance-selector')!.addEventListener('change', onInstanceSelectorChange);

// Monitor detail panel close
document.getElementById('monitor-detail-close')!.addEventListener('click', function() {
    document.getElementById('monitor-detail-panel')!.classList.add('d-none');
});

// Clickable Docker stat card → switch to Docker tab (respects hidden tabs)
function activateDockerTab(): void {
    var tabBtn = document.getElementById('tab-btn-docker') as HTMLElement | null;
    if (!tabBtn) return;
    var li = tabBtn.closest('li') as HTMLElement | null;
    if (li && li.classList.contains('d-none')) {
        var visible = getVisibleTabButtons();
        if (!visible.length) return;
        tabBtn = visible[0];
    }
    var tab = bootstrap.Tab.getInstance(tabBtn) || new bootstrap.Tab(tabBtn);
    tab.show();
}
document.getElementById('stat-docker-card')!.addEventListener('click', activateDockerTab);
document.getElementById('stat-docker-card')!.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateDockerTab(); }
});

// Clickable Alerts stat card → switch to Alerts tab
function activateAlertsTab(): void {
    var tabBtn = document.getElementById('tab-btn-alerts') as HTMLElement | null;
    if (!tabBtn) return;
    var li = tabBtn.closest('li') as HTMLElement | null;
    if (li && li.classList.contains('d-none')) {
        var visible = getVisibleTabButtons();
        if (!visible.length) return;
        tabBtn = visible[0];
    }
    var tab = bootstrap.Tab.getInstance(tabBtn) || new bootstrap.Tab(tabBtn);
    tab.show();
}
document.getElementById('stat-alerts-card')!.addEventListener('click', activateAlertsTab);
document.getElementById('stat-alerts-card')!.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateAlertsTab(); }
});

// Tab switching with focus management
function setupTabPanel(target: string): void {
    var pane = document.querySelector(target) as HTMLElement;
    if (pane) {
        pane.setAttribute('tabindex', '-1');
        var isActive = pane.classList.contains('show');
        if (isActive) pane.focus({ preventScroll: true });
    }
}
document.querySelectorAll('[data-bs-toggle="tab"]').forEach(function(tab) {
    tab.addEventListener('shown.bs.tab', function(e: Event) {
        var target = (e.target as HTMLElement).getAttribute('data-bs-target')!;
        setupTabPanel(target);
        if (target === '#tab-docker') loadDockerServices();
        else if (target === '#tab-npm') loadNPMProxies();
        else if (target === '#tab-kuma') loadKumaMonitors();
        else if (target === '#tab-history') loadHistory();
        else if (target === '#tab-events') loadEvents();
        else if (target === '#tab-settings') { loadSettings(); loadKumaInstances(); loadNPMInstances(); loadAutheliaInstances(); }
        else if (target === '#tab-authelia') loadAutheliaInstanceSelector();
        else if (target === '#tab-alerts') { loadAlertRules(); loadIncidents(); }
        else if (target === '#tab-logs') {
            setupLogFilters();
            if (!isLogsLoaded()) { loadLogs(false); connectLogSSE(); }
        }
    });
});

// WAI-ARIA keyboard navigation for tabs (skips hidden tabs)
document.querySelector('.nav-tabs')!.addEventListener('keydown', function(e) {
    var tabs = getVisibleTabButtons();
    var currentIdx = tabs.indexOf(document.activeElement as HTMLElement);
    if (currentIdx === -1) return;
    var ke = e as KeyboardEvent;
    var newIdx = currentIdx;
    switch (ke.key) {
        case 'ArrowRight':
            newIdx = (currentIdx + 1) % tabs.length;
            e.preventDefault();
            break;
        case 'ArrowLeft':
            newIdx = (currentIdx - 1 + tabs.length) % tabs.length;
            e.preventDefault();
            break;
        case 'Home':
            newIdx = 0;
            e.preventDefault();
            break;
        case 'End':
            newIdx = tabs.length - 1;
            e.preventDefault();
            break;
        default:
            return;
    }

    tabs[newIdx].focus();
    if (tabs[newIdx] !== document.activeElement) tabs[newIdx].click();
});

// Initial load — refreshAll() calls loadStatus() (which fetches /api/status
// and /api/authelia/status) once, avoiding a duplicate status round trip.
refreshAll();

// Start SSE
connectSSE();

// Helper: startSync (used by button handlers)
function startSync(source: string): void {
    (document.getElementById('btn-docker') as HTMLButtonElement).disabled = true;
    (document.getElementById('btn-npm') as HTMLButtonElement).disabled = true;
    document.getElementById('stat-status')!.innerHTML = '<span class="badge bg-primary">Running...</span>';
    toast('Sync started: ' + source, 'info');
    apiFetch('/api/sync/' + source, { method: 'POST' }).then(r => r.json()).then(function(d) {
        console.log(source + ' sync started', d);
    }).catch(function(err: Error) {
        if (err.message === 'not authenticated') return;
        (document.getElementById('btn-docker') as HTMLButtonElement).disabled = false;
        (document.getElementById('btn-npm') as HTMLButtonElement).disabled = false;
        document.getElementById('stat-status')!.innerHTML = '<span class="badge bg-secondary">Idle</span>';
        toast('Sync failed to start', 'error');
    });
}
window.startSync = startSync;

// Reconcile button on the Docker tab
document.getElementById('btn-reconcile')!.addEventListener('click', runReconcile);
