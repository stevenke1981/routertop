'use strict';

(() => {
  const API = '/cgi-bin/routertop.cgi';
  const $ = (id) => document.getElementById(id);
  const state = { csrf: null, config: null, revision: null, authenticated: false, dirty: false, busy: false, publicKeys: {}, ipv6Vlans: [], pdVlans: [], wanPasswordSet: false, wanBackupPasswordSet: false };
  const panelNames = { overview: '系統總覽', network: '網路設定', ipv6: 'IPv6', vlans: 'VLAN 網路', wireguard: 'WireGuard VPN', firewall: '防火牆規則', security: '帳號安全' };

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
    state.publicKeys = {};
    state.ipv6Vlans = [];
    state.pdVlans = [];
    state.wanPasswordSet = false;
    state.wanBackupPasswordSet = false;
    text('wan-runtime-active', '尚未取得');
    $('wan-runtime-links').hidden = true;
    ['mode', 'state', 'ipv4', 'ipv6'].forEach((name) => text('wan-runtime-' + name, '尚未取得'));
    $('editor-dialog').close();
    ['vlans-list', 'wireguard-list', 'firewall-list', 'ipv6-vlans-list', 'editor-fields'].forEach((id) => $(id).replaceChildren());
    $('network-form').reset();
    $('ipv6-form').reset();
    $('ipv6-fields').disabled = true;
    $('ipv6-enabled').disabled = true;
    ['mode', 'wan', 'prefix', 'lan', 'dns'].forEach((name) => text('ipv6-runtime-' + name, '尚未取得'));
    message('ipv6-runtime-error', '');
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
    if (password.length < 12 || bytes < 12 || bytes > 128 || /[\x00-\x1f\x7f]/.test(password)) throw new Error('密碼至少需要 12 個字元，不得超過 128 位元組，且不可包含控制字元。');
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
    document.title = `${panelNames[name]} · RouterTop 設定`;
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
    text('console-auth-status', data.console_auth_required === true ? '已啟用（必要）' : '無法確認驗證狀態');
    text('console-password-status', data.console_password_shared === true ? '與 Web admin 密碼相同' : '無法確認共用密碼狀態');
    const wanStatus = data.wan;
    const wan = wanStatus?.dual_wan && ['primary', 'backup'].includes(wanStatus.active) ? {...wanStatus, ...wanStatus[wanStatus.active]} : wanStatus;
    const wanStates = { unavailable: '無法連線', probing: '正在檢查連線', dialing: '正在撥號', connected: '已連線', reconnecting: '連線中斷，正在重撥', disabled: '由 DHCP 取得位址' };
    const modeLabel = (mode) => ({pppoe: 'PPPoE 撥號', dhcp: '自動取得（DHCP）', static: '固定 IP'})[mode] || '尚未取得';
    text('wan-runtime-mode', modeLabel(wan?.mode));
    text('wan-runtime-active', wan?.active === 'backup' ? '備援 WAN' : wan?.active === 'none' ? '尚無可用 WAN' : '主要 WAN');
    $('wan-runtime-links').hidden = wan?.dual_wan !== true;
    ['primary', 'backup'].forEach((slot) => { const link = wan?.[slot]; text('wan-runtime-' + slot, link ? `${modeLabel(link.mode)} · ${link.logical_interface || link.interface || '—'} · ${link.healthy === true ? '健康' : wanStates[link.state] || '檢查中'}${link.ipv4_address ? ' · ' + link.ipv4_address : ''}` : '尚未取得'); });
    text('wan-runtime-state', wanStates[wan?.state] || '無法確認連線狀態');
    text('wan-runtime-ipv4', typeof wan?.ipv4_address === 'string' && wan.ipv4_address ? wan.ipv4_address : '尚未取得');
    text('wan-runtime-ipv6', wan?.ipv6_ready === true ? '已就緒' : wan?.mode === 'pppoe' ? '尚未就緒' : '請查看 IPv6 頁面');
    const dynamic = data.ipv6_dynamic;
    const leases = Array.isArray(dynamic?.delegated) ? dynamic.delegated : [];
    const labels = { waiting: '等待上游提供 IPv6', bound: '已取得動態 IPv6', degraded: '連線資訊不完整' };
    text('ipv6-runtime-mode', dynamic ? (labels[dynamic.state] || '無法確認連線狀態') : '目前未使用動態 WAN');
    text('ipv6-runtime-wan', dynamic?.wan_addresses?.join('\n') || '—');
    text('ipv6-runtime-prefix', [...new Set(leases.map((lease) => lease.prefix))].join('\n') || '尚未取得');
    text('ipv6-runtime-lan', leases.map((lease) => `${lease.interface} · ${lease.address}`).join('\n') || '—');
    text('ipv6-runtime-dns', dynamic?.dns_servers?.join('\n') || '—');
    message('ipv6-runtime-error', typeof dynamic?.error === 'string' ? dynamic.error : '');
    setPending(Boolean(data.pending_reboot));
    text('status-updated', '最近更新：' + new Date().toLocaleTimeString('zh-TW', { hour12: false }));
  }
  function populateConfig(data) {
    const config = data.config;
    if (!config || !config.wan || !config.lan || !config.dhcp || !config.dns || !Array.isArray(config.dns.upstream) || !Number.isSafeInteger(data.revision)) {
      throw new Error('設定資料不完整，無法安全編輯。請重新讀取。');
    }
    state.config = structuredClone(config);
    if (state.config.wan.pppoe) state.config.wan.pppoe.password = '';
    if (state.config.wan_backup?.pppoe) state.config.wan_backup.pppoe.password = '';
    state.wanPasswordSet = data.wan_password_set === true;
    state.wanBackupPasswordSet = data.wan_backup_password_set === true;
    $('wan-mode').value = config.wan.mode || 'dhcp';
    $('pppoe-username').value = config.wan.pppoe?.username || '';
    $('pppoe-password').value = '';
    $('pppoe-mtu').value = config.wan.pppoe?.mtu ?? 1492;
    $('wan-static-address').value = config.wan.static_ipv4?.address || '';
    $('wan-static-gateway').value = config.wan.static_ipv4?.gateway || '';
    $('wan-backup-enabled').checked = Boolean(config.wan_backup);
    $('wan-backup-mode').value = config.wan_backup?.mode || 'dhcp';
    $('wan-backup-interface').value = config.wan_backup?.interface || 'eth2';
    $('wan-backup-static-address').value = config.wan_backup?.static_ipv4?.address || '';
    $('wan-backup-static-gateway').value = config.wan_backup?.static_ipv4?.gateway || '';
    $('wan-backup-pppoe-username').value = config.wan_backup?.pppoe?.username || '';
    $('wan-backup-pppoe-password').value = '';
    $('wan-backup-pppoe-mtu').value = config.wan_backup?.pppoe?.mtu ?? 1492;
    $('failover-primary-target').value = config.failover?.primary_target || '1.1.1.1';
    $('failover-backup-target').value = config.failover?.backup_target || '8.8.8.8';
    $('failover-interval').value = config.failover?.interval_seconds ?? 5;
    $('failover-failure').value = config.failover?.failure_threshold ?? 3;
    $('failover-recovery').value = config.failover?.recovery_threshold ?? 3;
    state.config.vlans ??= [];
    state.config.wireguard ??= [];
    state.config.firewall.rules ??= [];
    state.config.ipv6 ??= null;
    state.ipv6Vlans = structuredClone(config.ipv6?.vlans || []);
    state.pdVlans = structuredClone(config.ipv6?.pd?.vlans || []);
    $('ipv6-enabled').checked = Boolean(config.ipv6);
    $('ipv6-wan-mode').value = config.ipv6?.wan_mode || 'static';
    $('ipv6-dns-auto').checked = config.ipv6?.dns_auto ?? true;
    $('ipv6-pd-enabled').checked = Boolean(config.ipv6?.pd);
    $('ipv6-pd-prefix-length').value = config.ipv6?.pd?.prefix_length ?? 56;
    $('ipv6-pd-lan-subnet').value = config.ipv6?.pd?.lan_subnet_id ?? 0;
    $('ipv6-wan-address').value = config.ipv6?.wan_address || '';
    $('ipv6-wan-gateway').value = config.ipv6?.wan_gateway || '';
    $('ipv6-lan-address').value = config.ipv6?.lan_address || '';
    $('ipv6-dns').value = (config.ipv6?.dns_upstream || []).join('\n');
    setRevision(data.revision);
    $('hostname').value = config.hostname;
    $('wan-interface').value = config.wan.interface;
    $('lan-interface').value = config.lan.interface;
    syncWanFields();
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
    renderAdvanced();
  }
  function syncWanFields() {
    const backup = $('wan-backup-enabled').checked;
    $('wan-backup-fields').hidden = !backup;
    $('wan-backup-fields').disabled = !backup;
    [['wan', 'pppoe', state.config?.wan, state.wanPasswordSet], ['wan-backup', 'wan-backup-pppoe', state.config?.wan_backup, state.wanBackupPasswordSet]].forEach(([slot, prefix, saved, passwordSet]) => {
      const mode = $(slot + '-mode').value;
      const enabled = slot === 'wan' || backup;
      const fields = $(prefix + '-fields');
      fields.hidden = mode !== 'pppoe' || !enabled;
      fields.disabled = mode !== 'pppoe' || !enabled;
      $(slot + '-static-fields').hidden = mode !== 'static' || !enabled;
      $(slot + '-static-fields').disabled = mode !== 'static' || !enabled;
      const preserved = passwordSet && $(prefix + '-username').value === saved?.pppoe?.username && $(slot + '-interface').value.trim() === saved?.interface;
      $(prefix + '-password').required = enabled && mode === 'pppoe' && !preserved;
      text(prefix + '-password-help', preserved ? '已儲存撥號密碼。留空保留原密碼；輸入新密碼即可更新。' : '請輸入網路業者提供的撥號密碼；變更帳號或介面時需要重新輸入。');
      if (mode !== 'pppoe' || !enabled) $(prefix + '-password').value = '';
    });
  }
  async function loadConfig() {
    const data = await request('/config');
    if (state.authenticated) { populateConfig(data); await loadPublicKeys(); }
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

  function draftMessage(value) {
    text('dirty-state', value);
    document.querySelectorAll('.advanced-dirty').forEach((item) => { item.textContent = value; });
  }
  function markDirty() { state.dirty = true; draftMessage('有尚未儲存的變更（包含其他設定分頁）'); }
  function pdEnabled() { return $('ipv6-wan-mode').value === 'auto' && $('ipv6-pd-enabled').checked; }
  function pdSubnetMax() {
    const length = Number($('ipv6-pd-prefix-length').value);
    return Number.isInteger(length) && length >= 48 && length <= 64 ? 2 ** (64 - length) - 1 : 0;
  }
  function syncIpv6Mode() {
    const auto = $('ipv6-wan-mode').value === 'auto';
    const pd = pdEnabled();
    [['ipv6-static-wan', auto], ['ipv6-auto-wan', !auto], ['ipv6-pd-fields', !pd], ['ipv6-static-lan', pd]].forEach(([id, inactive]) => {
      $(id).hidden = inactive; $(id).disabled = inactive;
    });
    $('ipv6-pd-lan-subnet').max = String(pdSubnetMax());
    text('ipv6-mode-badge', !$('ipv6-enabled').checked ? '設定：未啟用' : auto ? (pd ? '設定：自動 · 前綴委派' : '設定：自動 WAN') : '設定：固定 IPv6');
    text('ipv6-pd-help', `要求 /${$('ipv6-pd-prefix-length').value || '—'} 時，子網 ID 範圍為 0–${pdSubnetMax()}，LAN 與 VLAN 不可重複。上游實際委派的前綴也需要足夠容納所有子網路。`);
    text('ipv6-lan-help', pd ? 'LAN 位址由上游委派前綴與 LAN 子網 ID 組成，取得後才會廣播。' : 'LAN 使用 /64 網段，裝置可透過 SLAAC 自行取得位址。');
    text('ipv6-vlans-title', pd ? 'VLAN 子網分配' : 'VLAN IPv6 位址');
    text('ipv6-vlans-help', pd ? '以固定子網 ID，從委派前綴分配各 VLAN 的 /64。' : '為既有 VLAN 指定獨立的 /64 網段。');
  }
  function advancedBusy() {
    syncIpv6Mode();
    document.querySelectorAll('.advanced-control').forEach((item) => {
      item.disabled = state.busy || !state.config || !state.authenticated || item.dataset.locked === 'true';
    });
    $('ipv6-fields').disabled = state.busy || !state.config || !state.authenticated || !$('ipv6-enabled').checked;
  }
  function element(tag, content, className = '') {
    const item = document.createElement(tag);
    if (content !== undefined) item.textContent = String(content);
    if (className) item.className = className;
    return item;
  }
  function actionButton(label, action, accessibleLabel = label, locked = false) {
    const button = element('button', label, 'button secondary compact-button advanced-control');
    button.type = 'button'; button.setAttribute('aria-label', accessibleLabel);
    button.dataset.locked = String(locked);
    button.addEventListener('click', () => { if (!state.busy) action(); });
    return button;
  }
  function emptyList(list, messageText) { list.append(element('p', messageText, 'empty-state')); }
  function removeItem(items, index, label) {
    if (!window.confirm(`刪除 ${label}？需儲存全部變更並重新啟動後才會生效。`)) return;
    items.splice(index, 1); markDirty(); renderAdvanced();
  }
  function itemCard(kind, title, summary) {
    const card = element('article', undefined, 'card advanced-item'); card.dataset.kind = kind;
    const header = element('div', undefined, 'advanced-item-header');
    const heading = element('div'); heading.append(element('h2', title), element('p', summary, 'muted'));
    const controls = element('div', undefined, 'item-actions');
    header.append(heading, controls); card.append(header);
    return { card, controls };
  }
  async function loadPublicKeys() {
    state.publicKeys = {};
    if (!state.config?.wireguard?.length) return;
    try {
      const response = await request('/wireguard/keys');
      if (!state.authenticated) return;
      state.publicKeys = response.public_keys || {};
      renderAdvanced();
    } catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', '公鑰尚未讀取成功。' + errorText(error)); }
  }
  function renderAdvanced() {
    if (!state.config) return;
    const config = state.config;
    ['vlans-list', 'wireguard-list', 'firewall-list', 'ipv6-vlans-list'].forEach((id) => $(id).replaceChildren());
    const ipv6Vlans = pdEnabled() ? state.pdVlans : state.ipv6Vlans;
    if (!ipv6Vlans.length) emptyList($('ipv6-vlans-list'), pdEnabled() ? '尚未分配 VLAN 子網 ID。請先建立 VLAN，再新增分配。' : '尚未設定 VLAN IPv6 位址。請先建立 VLAN，再指定 /64 網段。');
    ipv6Vlans.forEach((vlan, index) => {
      const { card, controls } = itemCard('ipv6-vlan', vlan.interface, pdEnabled() ? `委派子網 ID：${vlan.subnet_id} · /64` : vlan.address);
      card.dataset.interface = vlan.interface;
      controls.append(actionButton('編輯', () => openEditor('ipv6-vlan', index), `編輯 IPv6 VLAN ${vlan.interface}`), actionButton('刪除', () => removeItem(ipv6Vlans, index, `${vlan.interface} IPv6 分配`), `刪除 IPv6 VLAN ${vlan.interface}`));
      $('ipv6-vlans-list').append(card);
    });
    if (!config.vlans.length) emptyList($('vlans-list'), '尚未建立 VLAN。新增網路後，可設定標籤、位址與獨立 DHCP 範圍。');
    config.vlans.forEach((vlan, index) => {
      const { card, controls } = itemCard('vlan', vlan.interface, `VLAN ${vlan.id} · ${vlan.parent} · ${vlan.address}`);
      card.dataset.interface = vlan.interface;
      controls.append(actionButton('編輯', () => openEditor('vlan', index), `編輯 VLAN ${vlan.interface}`), actionButton('刪除', () => removeItem(config.vlans, index, vlan.interface), `刪除 VLAN ${vlan.interface}`));
      card.append(element('p', vlan.dhcp ? `DHCP ${vlan.dhcp.start} — ${vlan.dhcp.end} · ${vlan.dhcp.lease_hours} 小時` : 'DHCP 未啟用', 'item-detail'));
      card.append(element('span', vlan.internet ? '允許連往 WAN' : '隔離子網路', 'badge'));
      $('vlans-list').append(card);
    });
    if (!config.wireguard.length) emptyList($('wireguard-list'), '尚未建立 VPN。新增介面並儲存後，路由器會自動產生專屬金鑰。');
    config.wireguard.forEach((wg, index) => {
      const { card, controls } = itemCard('wireguard', wg.interface, `${wg.address} · UDP ${wg.listen_port} · MTU ${wg.mtu}`);
      card.dataset.interface = wg.interface;
      controls.append(actionButton('編輯', () => openEditor('wireguard', index), `編輯 VPN ${wg.interface}`), actionButton('刪除', () => removeItem(config.wireguard, index, wg.interface), `刪除 VPN ${wg.interface}`));
      card.append(element('span', wg.full_tunnel ? '全通道 VPN' : wg.internet ? '分流 · 允許連往 WAN' : '分流 · 不開放 WAN 轉送', 'badge'));
      if (wg.address_v6) card.append(element('p', `IPv6 ${wg.address_v6}${wg.nat66 ? ' · NAT66 已啟用' : ' · 未啟用 NAT66'}`, 'item-detail'));
      if (wg.full_tunnel) card.append(element('p', '預設流量經由此 VPN，斷線時由核心的保護規則阻止流量改走 WAN。', 'field-help'));
      const key = Object.hasOwn(state.publicKeys, wg.interface) ? state.publicKeys[wg.interface] : null;
      const keyRow = element('div', undefined, 'public-key-row');
      keyRow.append(element('span', '本機公鑰', 'field-help'));
      if (typeof key === 'string' && key) {
        const value = element('input', undefined, 'public-key'); value.type = 'text'; value.readOnly = true; value.value = key;
        value.setAttribute('aria-label', `${wg.interface} 本機公鑰`);
        keyRow.append(value, actionButton('複製公鑰', async () => {
          try { await navigator.clipboard.writeText(key); message('global-message', '已複製公鑰，可提供給對等端。'); }
          catch { value.focus(); value.select(); message('global-message', '請手動複製已選取的公鑰。'); }
        }, `複製 ${wg.interface} 公鑰`));
      } else keyRow.append(element('p', '儲存此介面後即可取得公鑰。', 'muted'));
      card.append(keyRow);
      const peerHeading = element('div', undefined, 'peer-heading');
      peerHeading.append(element('h3', `對等端 · ${wg.peers.length}`), actionButton('新增對等端', () => openEditor('peer', index), `新增 ${wg.interface} 對等端`));
      card.append(peerHeading);
      if (!wg.peers.length) card.append(element('p', '尚未加入對等端。只會接納已設定公鑰的對等端。', 'field-help'));
      wg.peers.forEach((peer, peerIndex) => {
        const row = element('div', undefined, 'peer-row'); row.dataset.peerIndex = String(peerIndex);
        const description = element('div'); description.append(element('code', peer.public_key, 'peer-key'), element('p', peer.allowed_ips.join(', ') + (peer.endpoint ? ` · ${peer.endpoint}` : ' · 等待對等端連入'), 'field-help'));
        const actions = element('div', undefined, 'item-actions');
        actions.append(actionButton('編輯', () => openEditor('peer', index, peerIndex), `編輯 ${wg.interface} 對等端 ${peerIndex + 1}`), actionButton('刪除', () => removeItem(wg.peers, peerIndex, `${wg.interface} 對等端 ${peerIndex + 1}`), `刪除 ${wg.interface} 對等端 ${peerIndex + 1}`));
        row.append(description, actions); card.append(row);
      });
      $('wireguard-list').append(card);
    });
    const rules = config.firewall.rules;
    if (!rules.length) emptyList($('firewall-list'), '尚無自訂規則。系統的預設安全規則仍會生效。');
    const actions = { accept: '允許', drop: '丟棄', reject: '拒絕' };
    rules.forEach((rule, index) => {
      const { card, controls } = itemCard('rule', `${index + 1}. ${rule.id}`, `${rule.family === 'ipv6' ? 'IPv6' : 'IPv4'} · ${rule.chain} · ${actions[rule.action]} · ${rule.protocol}${rule.destination_port ? ` : ${rule.destination_port}` : ''}`);
      card.dataset.ruleId = rule.id; card.classList.toggle('rule-disabled', !rule.enabled);
      controls.append(
        actionButton('上移', () => { [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]]; markDirty(); renderAdvanced(); }, `上移規則 ${rule.id}`, index === 0),
        actionButton('下移', () => { [rules[index], rules[index + 1]] = [rules[index + 1], rules[index]]; markDirty(); renderAdvanced(); }, `下移規則 ${rule.id}`, index === rules.length - 1),
        actionButton(rule.enabled ? '停用' : '啟用', () => { rule.enabled = !rule.enabled; markDirty(); renderAdvanced(); }, `${rule.enabled ? '停用' : '啟用'}規則 ${rule.id}`),
        actionButton('編輯', () => openEditor('rule', index), `編輯規則 ${rule.id}`),
        actionButton('刪除', () => removeItem(rules, index, rule.id), `刪除規則 ${rule.id}`));
      card.append(element('p', `${rule.in_interface || '任何來源介面'} → ${rule.out_interface || '任何目的介面'} · ${rule.source || '任何來源位址'} → ${rule.destination || '任何目的位址'}`, 'item-detail'));
      if (rule.comment) card.append(element('p', rule.comment, 'field-help'));
      card.append(element('span', rule.enabled ? '已啟用' : '已停用', 'badge'));
      $('firewall-list').append(card);
    });
    draftMessage(state.dirty ? '有尚未儲存的變更（包含其他設定分頁）' : `已讀取設定版本 #${state.revision}`);
    advancedBusy();
  }

  let editor = null;
  function addField(name, labelText, value, options = {}) {
    const wrapper = element('div', undefined, 'field' + (options.wide ? ' span-two' : ''));
    const label = element('label', labelText); label.htmlFor = 'edit-' + name;
    const input = element(options.choices ? 'select' : options.multiline ? 'textarea' : 'input');
    input.id = 'edit-' + name; input.name = name;
    if (options.choices) options.choices.forEach(([key, label]) => { const option = element('option', label); option.value = key; input.append(option); });
    else if (!options.multiline) input.type = options.type || 'text';
    if (options.type === 'checkbox') { input.checked = Boolean(value); wrapper.classList.add('check-field'); }
    else input.value = value ?? '';
    if (options.min !== undefined) input.min = String(options.min);
    if (options.max !== undefined) input.max = String(options.max);
    if (options.placeholder) input.placeholder = options.placeholder;
    input.required = Boolean(options.required);
    input.autocomplete = 'off'; input.spellcheck = false;
    wrapper.append(label, input);
    if (options.help) wrapper.append(element('p', options.help, 'field-help'));
    $('editor-fields').append(wrapper);
    return input;
  }
  const interfaceChoices = () => [...new Set(['', ...($('wan-mode').value === 'pppoe' ? ['ppp0'] : []), ...($('wan-backup-enabled').checked ? [$('wan-backup-interface').value.trim(), ...($('wan-backup-mode').value === 'pppoe' ? ['ppp1'] : [])] : []), $('wan-interface').value.trim(), $('lan-interface').value.trim(), ...state.config.vlans.map((v) => v.interface), ...state.config.wireguard.map((w) => w.interface)])].map((name) => [name, name || '任何介面']);
  function optionalField(name) { return $('edit-' + name).value.trim() || null; }
  function numberField(name) { const value = Number($('edit-' + name).value); if (!Number.isSafeInteger(value)) throw new Error('數值欄位必須填入整數。'); return value; }
  function openEditor(kind, index = -1, peerIndex = -1) {
    if (!state.config || state.busy) return;
    editor = { kind, index, peerIndex }; $('editor-fields').replaceChildren(); message('editor-error', '');
    const names = { vlan: 'VLAN', 'ipv6-vlan': 'VLAN IPv6 位址', wireguard: 'WireGuard 介面', peer: '對等端', rule: '防火牆規則' };
    const isNew = kind === 'peer' ? peerIndex < 0 : index < 0;
    text('editor-title', `${isNew ? '新增' : '編輯'}${names[kind]}`);
    text('editor-help', '加入變更只會更新草稿。請在分頁按「儲存全部變更」，重新啟動後生效。');
    if (kind === 'ipv6-vlan') {
      if (!state.config.vlans.length) { message('global-error', '請先在 VLAN 網路分頁新增 VLAN，再設定其 IPv6 位址。'); return; }
      const value = (pdEnabled() ? state.pdVlans : state.ipv6Vlans)[index] || { interface: state.config.vlans[0].interface, address: '', subnet_id: '' };
      addField('interface', 'VLAN 介面', value.interface, { required: true, choices: state.config.vlans.map((vlan) => [vlan.interface, vlan.interface]) });
      if (pdEnabled()) addField('subnet-id', '子網 ID', value.subnet_id, { required: true, type: 'number', min: 0, max: pdSubnetMax(), help: '使用十進位整數；不可與 LAN 或其他 VLAN 重複。' });
      else addField('address', 'IPv6 位址 /64', value.address, { required: true, placeholder: '例如 fd20:20::1/64' });
    } else if (kind === 'vlan') {
      const value = state.config.vlans[index] || { interface: '', parent: $('lan-interface').value, id: '', address: '', dhcp: null, internet: false };
      addField('interface', 'VLAN 介面名稱', value.interface, { required: true, placeholder: '例如 vlan20' });
      addField('parent', '上層實體介面', value.parent, { required: true, choices: [$('wan-interface').value.trim(), $('lan-interface').value.trim()].map((name) => [name, name]) });
      addField('id', 'VLAN 標籤（1–4094）', value.id, { type: 'number', min: 1, max: 4094, required: true });
      addField('address', 'IPv4 位址 / 前綴', value.address, { required: true, placeholder: '例如 192.168.20.1/24' });
      const enabled = addField('dhcp-enabled', '啟用 DHCP', Boolean(value.dhcp), { type: 'checkbox' });
      addField('internet', '允許此子網路連往 WAN', value.internet, { type: 'checkbox' });
      const start = addField('dhcp-start', 'DHCP 起始位址', value.dhcp?.start || '', { placeholder: '例如 192.168.20.100' });
      const end = addField('dhcp-end', 'DHCP 結束位址', value.dhcp?.end || '', { placeholder: '例如 192.168.20.150' });
      const lease = addField('lease-hours', '租約時間（小時）', value.dhcp?.lease_hours ?? 12, { type: 'number', min: 1 });
      const sync = () => [start, end, lease].forEach((input) => { input.disabled = !enabled.checked; input.required = enabled.checked; });
      enabled.addEventListener('change', sync); sync();
    } else if (kind === 'wireguard') {
      const value = state.config.wireguard[index] || { interface: '', address: '', address_v6: null, listen_port: 51820, mtu: 1420, internet: false, full_tunnel: false, nat66: false };
      addField('interface', 'VPN 介面名稱', value.interface, { required: true, placeholder: '例如 wg0' });
      addField('address', 'IPv4 位址 / 前綴', value.address, { required: true, placeholder: '例如 10.44.0.1/24' });
      addField('address-v6', 'IPv6 位址 / 前綴（選填）', value.address_v6, { wide: true, placeholder: '例如 fd44::1/64', help: '允許 /64 至 /128；啟用 IPv6 時 MTU 至少為 1280。' });
      addField('listen-port', 'UDP 接聽埠', value.listen_port, { type: 'number', min: 1, max: 65535, required: true });
      addField('mtu', 'MTU', value.mtu, { type: 'number', min: 576, max: 9000, required: true });
      const full = addField('full-tunnel', '將預設流量送入全通道 VPN', value.full_tunnel, { type: 'checkbox', wide: true, help: '全系統限一個全通道介面，且只能有一個對等端。允許網段須為 0.0.0.0/0，可再加 ::/0；遠端端點必填。' });
      const internet = addField('internet', '允許分流對等端連往 WAN', value.internet, { type: 'checkbox', wide: true });
      const nat66 = addField('nat66', '啟用 NAT66', value.nat66, { type: 'checkbox', wide: true, help: '僅適用含 ::/0 的全通道 VPN。未啟用時，遠端必須具備回到本機 IPv6 網段的路由。' });
      const sync = () => { internet.disabled = full.checked; if (full.checked) internet.checked = false; nat66.disabled = !full.checked; if (!full.checked) nat66.checked = false; };
      full.addEventListener('change', sync); sync();
    } else if (kind === 'peer') {
      const value = state.config.wireguard[index].peers[peerIndex] || { public_key: '', allowed_ips: [], endpoint: null, persistent_keepalive: 0 };
      addField('public-key', '對等端公鑰', value.public_key, { required: true, wide: true, help: '填入對方的 WireGuard 公鑰，不要提供私鑰。' });
      const full = state.config.wireguard[index].full_tunnel;
      addField('allowed-ips', '對等端允許的 IPv4／IPv6 網段', value.allowed_ips.join('\n'), { required: true, wide: true, multiline: true, placeholder: full ? '0.0.0.0/0\n::/0' : '例如 10.44.0.2/32、fd44::2/128', help: full ? '全通道必須包含 0.0.0.0/0，可再加入 ::/0；不可混入其他網段。' : '每行一個網段。分流模式不可使用預設路由，也不可與本機 LAN/VLAN 或其他對等端路由重疊。' });
      addField('endpoint', full ? '遠端端點' : '遠端端點（選填）', value.endpoint, { required: Boolean(full), placeholder: '例如 198.51.100.10:51820', help: full ? '全通道必填 IPv4:埠；遠端必須具備轉送能力。' : '僅接受 IPv4:埠；留空表示等待對方連入。' });
      addField('keepalive', 'Keepalive 秒數', value.persistent_keepalive, { type: 'number', min: 0, max: 65535, required: true, help: '0 表示停用。' });
    } else {
      const value = state.config.firewall.rules[index] || { id: '', enabled: true, family: 'ipv4', chain: 'forward', action: 'drop', protocol: 'any', in_interface: null, out_interface: null, source: null, destination: null, destination_port: null, comment: '' };
      addField('id', '規則 ID', value.id, { required: true, placeholder: '例如 allow-vlan-dns' });
      addField('enabled', '啟用規則', value.enabled, { type: 'checkbox' });
      const family = addField('family', '位址協定', value.family || 'ipv4', { choices: [['ipv4', 'IPv4'], ['ipv6', 'IPv6']] });
      const chain = addField('chain', '規則鏈', value.chain, { choices: [['forward', 'forward · 穿越路由器'], ['input', 'input · 送至路由器']] });
      addField('action', '處理方式', value.action, { choices: [['accept', 'accept · 允許'], ['drop', 'drop · 丟棄'], ['reject', 'reject · 拒絕']] });
      const protocols = (version) => [['any', 'any · 任意'], ['tcp', 'TCP'], ['udp', 'UDP'], version === 'ipv6' ? ['icmpv6', 'ICMPv6'] : ['icmp', 'ICMP']];
      const protocol = addField('protocol', '協定', value.protocol, { choices: protocols(family.value) });
      const port = addField('destination-port', '目的埠（選填）', value.destination_port, { type: 'number', min: 1, max: 65535 });
      addField('in-interface', '來源介面', value.in_interface, { choices: interfaceChoices() });
      const out = addField('out-interface', '目的介面', value.out_interface, { choices: interfaceChoices() });
      addField('source', '來源網段（選填）', value.source, { help: '須與選取的 IPv4／IPv6 協定一致。' });
      addField('destination', '目的網段（選填）', value.destination, { help: '須與選取的 IPv4／IPv6 協定一致。' });
      addField('comment', '備註（選填）', value.comment, { wide: true, help: '最多 80 個 ASCII 可列印字元。' });
      const sync = () => { out.disabled = chain.value === 'input'; port.disabled = !['tcp', 'udp'].includes(protocol.value); };
      chain.addEventListener('change', sync); protocol.addEventListener('change', sync); sync();
      family.addEventListener('change', () => { const previous = protocol.value; protocol.replaceChildren(); protocols(family.value).forEach(([key, label]) => { const option = element('option', label); option.value = key; protocol.append(option); }); protocol.value = previous === 'icmp' || previous === 'icmpv6' ? (family.value === 'ipv6' ? 'icmpv6' : 'icmp') : previous; sync(); });
    }
    $('editor-dialog').showModal();
  }
  $('editor-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!editor || state.busy || !state.config) return;
    const { kind, index, peerIndex } = editor;
    try {
      for (const input of $('editor-fields').querySelectorAll('[required]:not(:disabled)')) {
        if (!input.value.trim()) throw new Error('必填欄位不可只填入空白。');
      }
      let value, items, target = index;
      if (kind === 'ipv6-vlan') {
        items = pdEnabled() ? state.pdVlans : state.ipv6Vlans;
        value = pdEnabled() ? { interface: optionalField('interface'), subnet_id: numberField('subnet-id') } : { interface: optionalField('interface'), address: optionalField('address') };
        if (items.some((vlan, row) => row !== index && vlan.interface === value.interface)) throw new Error('每個 VLAN 只能指定一個 IPv6 網段。');
        if (pdEnabled() && (value.subnet_id === Number($('ipv6-pd-lan-subnet').value) || items.some((vlan, row) => row !== index && vlan.subnet_id === value.subnet_id))) throw new Error('LAN 與 VLAN 的子網 ID 不可重複。');
      } else if (kind === 'vlan') {
        items = state.config.vlans;
        value = { interface: optionalField('interface'), parent: optionalField('parent'), id: numberField('id'), address: optionalField('address'), dhcp: $('edit-dhcp-enabled').checked ? { start: optionalField('dhcp-start'), end: optionalField('dhcp-end'), lease_hours: numberField('lease-hours') } : null, internet: $('edit-internet').checked };
        if (index < 0 && items.length >= 16) throw new Error('最多可建立 16 個 VLAN。');
      } else if (kind === 'wireguard') {
        items = state.config.wireguard;
        value = { interface: optionalField('interface'), address: optionalField('address'), address_v6: optionalField('address-v6'), listen_port: numberField('listen-port'), mtu: numberField('mtu'), internet: $('edit-internet').checked, full_tunnel: $('edit-full-tunnel').checked, nat66: $('edit-nat66').checked, peers: index >= 0 ? structuredClone(items[index].peers) : [] };
        if (index < 0 && items.length >= 4) throw new Error('最多可建立 4 個 WireGuard 介面。');
      } else if (kind === 'peer') {
        items = state.config.wireguard[index].peers; target = peerIndex;
        if (target < 0 && state.config.wireguard[index].full_tunnel && items.length >= 1) throw new Error('全通道介面只能設定一個對等端。請編輯既有對等端，或先刪除再新增。');
        const publicKey = optionalField('public-key');
        let decoded;
        try { decoded = atob(publicKey); } catch { throw new Error('對等端公鑰必須是有效的 Base64。'); }
        if (decoded.length !== 32 || btoa(decoded) !== publicKey || ![...decoded].some((byte) => byte.charCodeAt(0))) throw new Error('公鑰須為標準 Base64 編碼的 32 位元組非零值。');
        value = { public_key: publicKey, allowed_ips: $('edit-allowed-ips').value.trim().split(/[\s,]+/).filter(Boolean), endpoint: optionalField('endpoint'), persistent_keepalive: numberField('keepalive') };
        if (target < 0 && items.length >= 32) throw new Error('每個介面最多可建立 32 個對等端。');
      } else {
        items = state.config.firewall.rules;
        const comment = $('edit-comment').value;
        if (!/^[\x20-\x7e]{0,80}$/.test(comment)) throw new Error('備註只能使用最多 80 個 ASCII 可列印字元。');
        value = { id: optionalField('id'), enabled: $('edit-enabled').checked, family: $('edit-family').value, chain: $('edit-chain').value, action: $('edit-action').value, protocol: $('edit-protocol').value, in_interface: optionalField('in-interface'), out_interface: $('edit-out-interface').disabled ? null : optionalField('out-interface'), source: optionalField('source'), destination: optionalField('destination'), destination_port: $('edit-destination-port').disabled || !$('edit-destination-port').value ? null : numberField('destination-port'), comment };
        if (index < 0 && items.length >= 64) throw new Error('最多可建立 64 條自訂規則。');
        if (items.some((rule, row) => row !== index && rule.id === value.id)) throw new Error('規則 ID 不可重複。');
      }
      if (target >= 0) items[target] = value; else items.push(value);
      $('editor-dialog').close(); editor = null; markDirty(); renderAdvanced();
    } catch (error) { message('editor-error', errorText(error)); }
  });
  ['editor-close', 'editor-cancel'].forEach((id) => $(id).addEventListener('click', () => $('editor-dialog').close()));
  $('editor-dialog').addEventListener('keydown', (event) => {
    if (event.key !== 'Tab' || event.altKey || event.ctrlKey || event.metaKey) return;
    const dialog = event.currentTarget;
    // Native modal dialogs can tab into browser chrome; keep this editor's cycle local.
    // Recompute after every keypress because DHCP and VPN options enable fields dynamically.
    const controls = [...dialog.querySelectorAll('button, input, select, textarea, a[href], [tabindex]')]
      .filter((control) => control.tabIndex >= 0 && !control.matches(':disabled') && control.checkVisibility());
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (!first) { event.preventDefault(); dialog.focus(); return; }
    if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog)) {
      event.preventDefault(); first.focus();
    }
  });
  $('add-vlans').addEventListener('click', () => openEditor('vlan'));
  $('add-ipv6-vlan').addEventListener('click', () => openEditor('ipv6-vlan'));
  $('ipv6-form').addEventListener('input', () => { markDirty(); advancedBusy(); });
  ['ipv6-wan-mode', 'ipv6-pd-enabled'].forEach((id) => $(id).addEventListener('change', renderAdvanced));
  $('ipv6-form').addEventListener('submit', (event) => { event.preventDefault(); saveAll(); });
  $('add-wireguard').addEventListener('click', () => openEditor('wireguard'));
  $('add-firewall').addEventListener('click', () => openEditor('rule'));
  document.querySelectorAll('.advanced-save').forEach((button) => button.addEventListener('click', () => saveAll()));
  document.querySelectorAll('.advanced-reload').forEach((button) => button.addEventListener('click', () => $('reload-config').click()));

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
  ['refresh-button', 'ipv6-refresh', 'wan-refresh'].forEach((id) => $(id).addEventListener('click', async () => {
    const button = $(id); button.disabled = true; clearMessages();
    try { await loadStatus(); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { button.disabled = false; }
  }));
  $('network-form').addEventListener('input', markDirty);
  ['wan-mode', 'wan-backup-mode', 'wan-backup-enabled'].forEach((id) => $(id).addEventListener('change', () => { syncWanFields(); markDirty(); }));
  ['pppoe-username', 'wan-interface', 'wan-backup-pppoe-username', 'wan-backup-interface'].forEach((id) => $(id).addEventListener('input', syncWanFields));
  $('reload-config').addEventListener('click', async () => {
    if (state.busy) return;
    if (state.dirty && !window.confirm('重新讀取會捨棄尚未儲存的修改，確定繼續嗎？')) return;
    const button = $('reload-config'); button.disabled = true; clearMessages();
    state.busy = true; $('network-fields').disabled = true; $('save-config').disabled = true; advancedBusy();
    try { await loadConfig(); if (state.authenticated) message('global-message', '已讀取最新的已儲存設定。'); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { state.busy = false; button.disabled = false; $('network-fields').disabled = !state.authenticated || !state.config; $('save-config').disabled = !state.authenticated || !state.config; advancedBusy(); }
  });
  async function saveAll() {
    if (!state.config || state.busy) return;
    if (!$('network-form').checkValidity()) { showPanel('network'); $('network-form').reportValidity(); return; }
    if (!$('ipv6-form').checkValidity()) { showPanel('ipv6'); $('ipv6-form').reportValidity(); return; }
    clearMessages();
    const config = structuredClone(state.config);
    config.hostname = $('hostname').value.trim();
    config.wan.interface = $('wan-interface').value.trim();
    config.wan.mode = $('wan-mode').value;
    config.wan.pppoe = config.wan.mode === 'pppoe' ? { username: $('pppoe-username').value, password: $('pppoe-password').value, mtu: Number($('pppoe-mtu').value) } : null;
    config.wan.static_ipv4 = config.wan.mode === 'static' ? {address: $('wan-static-address').value.trim(), gateway: $('wan-static-gateway').value.trim()} : null;
    const backupMode = $('wan-backup-mode').value;
    config.wan_backup = $('wan-backup-enabled').checked ? {interface: $('wan-backup-interface').value.trim(), mode: backupMode, pppoe: backupMode === 'pppoe' ? {username: $('wan-backup-pppoe-username').value, password: $('wan-backup-pppoe-password').value, mtu: Number($('wan-backup-pppoe-mtu').value)} : null, static_ipv4: backupMode === 'static' ? {address: $('wan-backup-static-address').value.trim(), gateway: $('wan-backup-static-gateway').value.trim()} : null} : null;
    config.failover = config.wan_backup ? {primary_target: $('failover-primary-target').value.trim(), backup_target: $('failover-backup-target').value.trim(), interval_seconds: Number($('failover-interval').value), failure_threshold: Number($('failover-failure').value), recovery_threshold: Number($('failover-recovery').value)} : null;
    config.lan.interface = $('lan-interface').value.trim();
    config.lan.address = $('lan-address').value.trim();
    config.dhcp.start = $('dhcp-start').value.trim();
    config.dhcp.end = $('dhcp-end').value.trim();
    config.dhcp.lease_hours = Number($('lease-hours').value);
    config.dns.upstream = $('dns-upstream').value.split(/[\s,]+/).filter(Boolean);
    const autoIpv6 = $('ipv6-wan-mode').value === 'auto';
    if (config.wan_backup && $('ipv6-enabled').checked && !autoIpv6) { message('global-error', '雙 WAN 的 IPv6 請選擇「自動取得」。固定 IPv6 目前適用於單一 WAN。'); showPanel('ipv6'); return; }
    const pd = pdEnabled() ? { prefix_length: Number($('ipv6-pd-prefix-length').value), lan_subnet_id: Number($('ipv6-pd-lan-subnet').value), vlans: structuredClone(state.pdVlans) } : null;
    if ($('ipv6-enabled').checked && pd) {
      const ids = [pd.lan_subnet_id, ...pd.vlans.map((vlan) => vlan.subnet_id)];
      if (ids.some((id) => !Number.isInteger(id) || id < 0 || id > pdSubnetMax()) || new Set(ids).size !== ids.length) { message('global-error', 'LAN 與 VLAN 的子網 ID 必須各自不同，且符合要求的前綴長度。'); return; }
    }
    config.ipv6 = $('ipv6-enabled').checked ? { ...state.config.ipv6, wan_mode: autoIpv6 ? 'auto' : 'static', dns_auto: autoIpv6 && $('ipv6-dns-auto').checked, wan_address: autoIpv6 ? null : $('ipv6-wan-address').value.trim() || null, wan_gateway: autoIpv6 ? null : $('ipv6-wan-gateway').value.trim() || null, lan_address: pd ? '' : $('ipv6-lan-address').value.trim(), vlans: pd ? [] : structuredClone(state.ipv6Vlans), dns_upstream: $('ipv6-dns').value.split(/[\s,]+/).filter(Boolean), pd } : null;
    if (!Number.isSafeInteger(config.dhcp.lease_hours) || config.dhcp.lease_hours < 1) { message('global-error', '租約時間必須是大於零的整數。'); return; }
    state.busy = true; $('network-fields').disabled = true; $('save-config').disabled = true; $('reload-config').disabled = true;
    advancedBusy();
    $('network-form').setAttribute('aria-busy', 'true'); text('save-config', '儲存中…');
    try {
      const result = await request('/config', { method: 'POST', body: { config, revision: state.revision } });
      if (!state.authenticated) return;
      state.wanPasswordSet = config.wan.mode === 'pppoe';
      state.wanBackupPasswordSet = config.wan_backup?.mode === 'pppoe';
      if (config.wan.pppoe) config.wan.pppoe.password = '';
      $('pppoe-password').value = '';
      $('wan-backup-pppoe-password').value = '';
      if (config.wan_backup?.pppoe) config.wan_backup.pppoe.password = '';
      state.config = config; syncWanFields(); state.dirty = false; setRevision(result.revision); setPending(Boolean(result.pending_reboot));
      renderAdvanced(); draftMessage('全部變更已儲存到裝置');
      message('global-message', '設定已儲存。重新啟動後生效；目前的連線設定尚未變更。');
      await loadPublicKeys();
    } catch (error) {
      const detail = error.status === 409 ? errorText(error) + ' 請按「重新讀取」，確認最新設定後再編輯。' : errorText(error);
      message(state.authenticated ? 'global-error' : 'auth-error', detail);
    } finally {
      $('pppoe-password').value = '';
      if (config.wan.pppoe) config.wan.pppoe.password = '';
      $('wan-backup-pppoe-password').value = '';
      if (config.wan_backup?.pppoe) config.wan_backup.pppoe.password = '';
      syncWanFields();
      state.busy = false; $('network-fields').disabled = !state.authenticated; $('save-config').disabled = !state.authenticated;
      $('reload-config').disabled = false; $('network-form').setAttribute('aria-busy', 'false'); text('save-config', '儲存設定');
      advancedBusy();
    }
  }
  $('network-form').addEventListener('submit', (event) => { event.preventDefault(); saveAll(); });
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
