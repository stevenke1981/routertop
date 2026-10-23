'use strict';

(() => {
  const API = '/cgi-bin/routertop.cgi';
  const $ = (id) => document.getElementById(id);
  const state = { csrf: null, config: null, revision: null, authenticated: false, dirty: false, busy: false };
  const panelNames = { overview: '系統總覽', network: '網路設定', security: '帳號安全' };

  function text(id, value) { $(id).textContent = String(value); }
  function message(id, value) { text(id, value || ''); $(id).hidden = !value; }
  function clearMessages() { ['auth-error', 'auth-message', 'global-error', 'global-message'].forEach((id) => message(id, '')); }
  function errorText(error) { return error instanceof Error ? error.message : '發生未預期的錯誤，請稍後重試。'; }
  function clearPasswords() {
    document.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ''; });
    $('setup-token').value = '';
  }
  function showAuth(setupRequired, note = '') {
    state.authenticated = false;
    state.csrf = null;
    state.config = null;
    state.revision = null;
    state.dirty = false;
    $('network-form').reset();
    $('network-fields').disabled = true;
    $('save-config').disabled = true;
    $('pending-banner').hidden = true;
    clearPasswords();
    clearMessages();
    $('app-screen').hidden = true;
    $('auth-screen').hidden = false;
    $('loading-panel').hidden = true;
    $('setup-panel').hidden = !setupRequired;
    $('login-panel').hidden = setupRequired;
    $('retry-connection').hidden = true;
    document.querySelector('.skip-link').href = '#auth-main';
    message('auth-message', note);
  }

  async function request(path, options = {}) {
    const headers = { Accept: 'application/json' };
    const init = { method: options.method || 'GET', credentials: 'same-origin', cache: 'no-store', headers };
    if (init.method === 'POST') {
      headers['Content-Type'] = 'application/json';
      if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
      init.body = JSON.stringify(options.body || {});
    }
    const controller = new AbortController();
    init.signal = controller.signal;
    const timeout = window.setTimeout(() => controller.abort(), 20000);
    let response;
    let body;
    try {
      response = await fetch(API + path, init);
      body = await response.json();
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('路由器回應逾時。請確認網路連線後再試一次。');
      if (response) throw new Error('管理服務回傳的資料格式不正確。請重新連線。');
      throw new Error('無法連接路由器。請檢查連線與管理頁面位址。');
    } finally { window.clearTimeout(timeout); }
    if (!response.ok) {
      if (response.status === 401 && state.authenticated) {
        showAuth(false, '登入已逾時或失效，請重新登入。');
      }
      const fallback = response.status === 409
        ? '設定已由另一個工作階段更新。請重新讀取最新設定後再修改。'
        : response.status === 429 ? '嘗試次數過多，請稍後再試。' : '操作未完成，請稍後再試。';
      const error = new Error(body && typeof body.error === 'string' ? body.error : fallback);
      error.status = response.status;
      throw error;
    }
    return body;
  }

  function formBusy(form, busy) {
    form.setAttribute('aria-busy', String(busy));
    form.querySelectorAll('button[type="submit"]').forEach((button) => {
      if (busy) { button.dataset.idleLabel = button.textContent; button.textContent = '處理中…'; }
      else if (button.dataset.idleLabel) { button.textContent = button.dataset.idleLabel; delete button.dataset.idleLabel; }
      button.disabled = busy;
    });
  }
  function validatePassword(password, confirmation) {
    const bytes = new TextEncoder().encode(password).length;
    if (password.length < 12 || bytes < 12 || bytes > 128) throw new Error('密碼至少需要 12 個字元，且不得超過 128 位元組。');
    if (password !== confirmation) throw new Error('兩次輸入的密碼不一致，請重新確認。');
  }
  function showPanel(name, focus = false) {
    if (!Object.hasOwn(panelNames, name)) return;
    Object.keys(panelNames).forEach((key) => { $('panel-' + key).hidden = key !== name; });
    document.querySelectorAll('.nav-item').forEach((button) => {
      const active = button.dataset.panel === name;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    text('breadcrumb', panelNames[name]);
    if (focus) $(name + '-title').focus();
  }
  function setPending(pending) {
    $('pending-banner').hidden = !pending;
    text('apply-value', pending ? '已儲存，待重新啟動' : '已套用');
    text('active-badge', pending ? '待重新啟動' : '運行中');
    $('active-badge').classList.toggle('pending', pending);
  }
  function setRevision(revision) {
    state.revision = revision;
    text('revision-value', '#' + revision);
    text('config-revision', '已儲存版本 #' + revision);
  }
  function uptime(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return '無法取得';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return days ? `${days} 天 ${hours} 小時` : hours ? `${hours} 小時 ${minutes} 分` : `${minutes} 分鐘`;
  }
  async function loadStatus() {
    const data = await request('/status');
    if (!state.authenticated) return;
    text('active-hostname', data.hostname || '—');
    text('sidebar-hostname', data.hostname || '路由器');
    text('version-value', data.version || '—');
    text('sidebar-version', data.version || '');
    text('uptime-value', uptime(data.uptime_seconds));
    const total = data.memory_total_kib;
    const available = data.memory_available_kib;
    if (Number.isFinite(total) && Number.isFinite(available) && total > 0) {
      const used = Math.max(0, Math.min(total, total - available));
      const percent = Math.round((used / total) * 100);
      text('memory-value', percent + '%');
      text('memory-detail', `${(used / 1024).toFixed(0)} / ${(total / 1024).toFixed(0)} MiB`);
      $('memory-fill').style.width = percent + '%';
      $('memory-meter').setAttribute('aria-valuenow', String(percent));
    } else {
      text('memory-value', '無法取得'); text('memory-detail', '未提供有效的記憶體資料');
      $('memory-fill').style.width = '0%'; $('memory-meter').removeAttribute('aria-valuenow');
    }
    text('persistence-value', data.persistent ? '持久儲存' : '尚未就緒');
    text('persistence-detail', data.persistent ? '已連接設定儲存空間' : '無法確認設定儲存空間');
    setPending(Boolean(data.pending_reboot));
    text('status-updated', '最近更新：' + new Date().toLocaleTimeString('zh-TW', { hour12: false }));
  }
  function populateConfig(data) {
    const config = data.config;
    if (!config || !config.wan || !config.lan || !config.dhcp || !config.dns || !Array.isArray(config.dns.upstream) || !Number.isSafeInteger(data.revision)) {
      throw new Error('設定資料不完整，無法安全編輯。請重新讀取。');
    }
    state.config = structuredClone(config);
    setRevision(data.revision);
    $('hostname').value = config.hostname;
    $('wan-interface').value = config.wan.interface;
    $('lan-interface').value = config.lan.interface;
    $('lan-address').value = config.lan.address;
    $('dhcp-start').value = config.dhcp.start;
    $('dhcp-end').value = config.dhcp.end;
    $('lease-hours').value = config.dhcp.lease_hours;
    $('dns-upstream').value = config.dns.upstream.join('\n');
    state.dirty = false;
    text('dirty-state', '尚未修改設定');
    $('network-fields').disabled = false;
    $('save-config').disabled = false;
    setPending(Boolean(data.pending_reboot));
  }
  async function loadConfig() {
    const data = await request('/config');
    if (state.authenticated) populateConfig(data);
  }
  async function enterApp(data) {
    if (!data || typeof data.csrf_token !== 'string' || !data.csrf_token) throw new Error('登入回應缺少安全權杖，請重新連線。');
    state.csrf = data.csrf_token;
    state.authenticated = true;
    clearPasswords(); clearMessages();
    $('auth-screen').hidden = true;
    $('app-screen').hidden = false;
    document.querySelector('.skip-link').href = '#main';
    showPanel('overview');
    const results = await Promise.allSettled([loadStatus(), loadConfig()]);
    if (!state.authenticated) return;
    const failed = results.find((result) => result.status === 'rejected');
    if (failed) message('global-error', errorText(failed.reason));
    $('overview-title').focus();
  }
  async function bootstrap() {
    clearMessages();
    $('retry-connection').hidden = true;
    $('loading-panel').hidden = false;
    $('setup-panel').hidden = true;
    $('login-panel').hidden = true;
    try {
      const data = await request('/session');
      if (data.authenticated) await enterApp(data); else showAuth(Boolean(data.setup_required));
    } catch (error) {
      $('loading-panel').hidden = true;
      message('auth-error', errorText(error));
      $('retry-connection').hidden = false;
    }
  }

  $('setup-form').addEventListener('submit', async (event) => {
    event.preventDefault(); clearMessages();
    const form = event.currentTarget;
    try {
      validatePassword($('setup-password').value, $('setup-confirm').value);
      formBusy(form, true);
      const data = await request('/setup', { method: 'POST', body: { token: $('setup-token').value.trim(), password: $('setup-password').value } });
      await enterApp(data);
    } catch (error) { message('auth-error', errorText(error)); }
    finally { formBusy(form, false); }
  });
  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault(); clearMessages();
    const form = event.currentTarget;
    formBusy(form, true);
    try { await enterApp(await request('/login', { method: 'POST', body: { username: 'admin', password: $('login-password').value } })); }
    catch (error) { message('auth-error', errorText(error)); $('login-password').value = ''; }
    finally { formBusy(form, false); }
  });
  document.querySelectorAll('[data-panel]').forEach((button) => button.addEventListener('click', () => showPanel(button.dataset.panel, true)));
  $('retry-connection').addEventListener('click', bootstrap);
  $('logout-button').addEventListener('click', async () => {
    if (state.dirty && !window.confirm('還有尚未儲存的變更，確定要登出嗎？')) return;
    const button = $('logout-button'); button.disabled = true; clearMessages();
    try { await request('/logout', { method: 'POST' }); showAuth(false, '已安全登出。'); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { button.disabled = false; }
  });
  $('refresh-button').addEventListener('click', async () => {
    const button = $('refresh-button'); button.disabled = true; clearMessages();
    try { await loadStatus(); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { button.disabled = false; }
  });
  $('network-form').addEventListener('input', () => { state.dirty = true; text('dirty-state', '有尚未儲存的變更'); });
  $('reload-config').addEventListener('click', async () => {
    if (state.dirty && !window.confirm('重新讀取會捨棄尚未儲存的修改，確定繼續嗎？')) return;
    const button = $('reload-config'); button.disabled = true; clearMessages();
    try { await loadConfig(); if (state.authenticated) message('global-message', '已讀取最新的已儲存設定。'); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { button.disabled = false; }
  });
  $('network-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!state.config || state.busy) return;
    clearMessages();
    const config = structuredClone(state.config);
    config.hostname = $('hostname').value.trim();
    config.wan.interface = $('wan-interface').value.trim();
    config.lan.interface = $('lan-interface').value.trim();
    config.lan.address = $('lan-address').value.trim();
    config.dhcp.start = $('dhcp-start').value.trim();
    config.dhcp.end = $('dhcp-end').value.trim();
    config.dhcp.lease_hours = Number($('lease-hours').value);
    config.dns.upstream = $('dns-upstream').value.split(/[\s,]+/).filter(Boolean);
    if (!Number.isSafeInteger(config.dhcp.lease_hours) || config.dhcp.lease_hours < 1) { message('global-error', '租約時間必須是大於零的整數。'); return; }
    state.busy = true; $('network-fields').disabled = true; $('save-config').disabled = true; $('reload-config').disabled = true;
    $('network-form').setAttribute('aria-busy', 'true'); text('save-config', '儲存中…');
    try {
      const result = await request('/config', { method: 'POST', body: { config, revision: state.revision } });
      if (!state.authenticated) return;
      state.config = config; state.dirty = false; setRevision(result.revision); setPending(Boolean(result.pending_reboot));
      text('dirty-state', '變更已儲存到裝置');
      message('global-message', '設定已儲存。重新啟動後生效；目前的連線設定尚未變更。');
    } catch (error) {
      const detail = error.status === 409 ? errorText(error) + ' 請按「重新讀取」，確認最新設定後再編輯。' : errorText(error);
      message(state.authenticated ? 'global-error' : 'auth-error', detail);
    } finally {
      state.busy = false; $('network-fields').disabled = !state.authenticated; $('save-config').disabled = !state.authenticated;
      $('reload-config').disabled = false; $('network-form').setAttribute('aria-busy', 'false'); text('save-config', '儲存設定');
    }
  });
  $('password-form').addEventListener('submit', async (event) => {
    event.preventDefault(); clearMessages();
    const form = event.currentTarget;
    try {
      validatePassword($('new-password').value, $('confirm-password').value);
      formBusy(form, true);
      await request('/password', { method: 'POST', body: { current_password: $('current-password').value, new_password: $('new-password').value } });
      showAuth(false, '密碼已更新，所有工作階段已登出。請使用新密碼登入。');
    } catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { formBusy(form, false); }
  });
  document.querySelectorAll('.reboot-button').forEach((button) => button.addEventListener('click', async () => {
    if (state.dirty) { message('global-error', '還有尚未儲存的修改。請先儲存，或重新讀取以捨棄變更，再重新啟動。'); return; }
    if (!window.confirm('確定重新啟動 RouterTop？網路連線會暫時中斷，已儲存的設定將在開機後生效。如果變更了 LAN 位址，請改用新位址連線。')) return;
    clearMessages(); document.querySelectorAll('.reboot-button').forEach((item) => { item.disabled = true; });
    try {
      await request('/reboot', { method: 'POST' });
      showAuth(false, '已送出重新啟動要求。請稍候再重新連線；若 LAN 位址有變更，請開啟新位址。');
      $('login-panel').hidden = true; $('retry-connection').hidden = false;
    } catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { document.querySelectorAll('.reboot-button').forEach((item) => { item.disabled = false; }); }
  }));
  window.addEventListener('beforeunload', (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
  bootstrap();
})();
