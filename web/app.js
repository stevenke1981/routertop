'use strict';

(() => {
  const API = '/cgi-bin/routertop.cgi';
  const $ = (id) => document.getElementById(id);
  const state = { csrf: null, config: null, revision: null, authenticated: false, dirty: false, busy: false, publicKeys: {} };
  const panelNames = { overview: '系統總覽', network: '網路設定', vlans: 'VLAN 網路', wireguard: 'WireGuard VPN', firewall: '防火牆規則', security: '帳號安全' };

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
    $('editor-dialog').close();
    ['vlans-list', 'wireguard-list', 'firewall-list', 'editor-fields'].forEach((id) => $(id).replaceChildren());
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
    state.config.vlans ??= [];
    state.config.wireguard ??= [];
    state.config.firewall.rules ??= [];
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
    renderAdvanced();
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
  function advancedBusy() {
    document.querySelectorAll('.advanced-control').forEach((item) => {
      item.disabled = state.busy || !state.config || !state.authenticated || item.dataset.locked === 'true';
    });
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
    ['vlans-list', 'wireguard-list', 'firewall-list'].forEach((id) => $(id).replaceChildren());
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
      card.append(element('span', wg.internet ? '允許連往 WAN' : '不開放 WAN 轉送', 'badge'));
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
      const { card, controls } = itemCard('rule', `${index + 1}. ${rule.id}`, `${rule.chain} · ${actions[rule.action]} · ${rule.protocol}${rule.destination_port ? ` : ${rule.destination_port}` : ''}`);
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
  const interfaceChoices = () => ['', $('wan-interface').value.trim(), $('lan-interface').value.trim(), ...state.config.vlans.map((v) => v.interface), ...state.config.wireguard.map((w) => w.interface)].map((name) => [name, name || '任何介面']);
  function optionalField(name) { return $('edit-' + name).value.trim() || null; }
  function numberField(name) { const value = Number($('edit-' + name).value); if (!Number.isSafeInteger(value)) throw new Error('數值欄位必須填入整數。'); return value; }
  function openEditor(kind, index = -1, peerIndex = -1) {
    if (!state.config || state.busy) return;
    editor = { kind, index, peerIndex }; $('editor-fields').replaceChildren(); message('editor-error', '');
    const names = { vlan: 'VLAN', wireguard: 'WireGuard 介面', peer: '對等端', rule: '防火牆規則' };
    const isNew = kind === 'peer' ? peerIndex < 0 : index < 0;
    text('editor-title', `${isNew ? '新增' : '編輯'}${names[kind]}`);
    text('editor-help', '加入變更只會更新草稿。請在分頁按「儲存全部變更」，重新啟動後生效。');
    if (kind === 'vlan') {
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
      const value = state.config.wireguard[index] || { interface: '', address: '', listen_port: 51820, mtu: 1420, internet: false };
      addField('interface', 'VPN 介面名稱', value.interface, { required: true, placeholder: '例如 wg0' });
      addField('address', 'IPv4 位址 / 前綴', value.address, { required: true, placeholder: '例如 10.44.0.1/24' });
      addField('listen-port', 'UDP 接聽埠', value.listen_port, { type: 'number', min: 1, max: 65535, required: true });
      addField('mtu', 'MTU', value.mtu, { type: 'number', min: 576, max: 9000, required: true });
      addField('internet', '允許對等端連往 WAN', value.internet, { type: 'checkbox', wide: true });
    } else if (kind === 'peer') {
      const value = state.config.wireguard[index].peers[peerIndex] || { public_key: '', allowed_ips: [], endpoint: null, persistent_keepalive: 0 };
      addField('public-key', '對等端公鑰', value.public_key, { required: true, wide: true, help: '填入對方的 WireGuard 公鑰，不要提供私鑰。' });
      addField('allowed-ips', '對等端允許的 IPv4 網段', value.allowed_ips.join('\n'), { required: true, wide: true, multiline: true, placeholder: '例如 10.44.0.2/32', help: '每行一個網段；不允許 0.0.0.0/0，且不可與本機 LAN/VLAN 或其他對等端路由重疊。' });
      addField('endpoint', '遠端端點（選填）', value.endpoint, { placeholder: '例如 198.51.100.10:51820', help: '僅接受 IPv4:埠；留空表示等待對方連入。' });
      addField('keepalive', 'Keepalive 秒數', value.persistent_keepalive, { type: 'number', min: 0, max: 65535, required: true, help: '0 表示停用。' });
    } else {
      const value = state.config.firewall.rules[index] || { id: '', enabled: true, chain: 'forward', action: 'drop', protocol: 'any', in_interface: null, out_interface: null, source: null, destination: null, destination_port: null, comment: '' };
      addField('id', '規則 ID', value.id, { required: true, placeholder: '例如 allow-vlan-dns' });
      addField('enabled', '啟用規則', value.enabled, { type: 'checkbox' });
      const chain = addField('chain', '規則鏈', value.chain, { choices: [['forward', 'forward · 穿越路由器'], ['input', 'input · 送至路由器']] });
      addField('action', '處理方式', value.action, { choices: [['accept', 'accept · 允許'], ['drop', 'drop · 丟棄'], ['reject', 'reject · 拒絕']] });
      const protocol = addField('protocol', '協定', value.protocol, { choices: [['any', 'any · 任意'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP']] });
      const port = addField('destination-port', '目的埠（選填）', value.destination_port, { type: 'number', min: 1, max: 65535 });
      addField('in-interface', '來源介面', value.in_interface, { choices: interfaceChoices() });
      const out = addField('out-interface', '目的介面', value.out_interface, { choices: interfaceChoices() });
      addField('source', '來源 IPv4 網段（選填）', value.source, { placeholder: '例如 192.168.20.0/24' });
      addField('destination', '目的 IPv4 網段（選填）', value.destination, { placeholder: '例如 10.44.0.2/32' });
      addField('comment', '備註（選填）', value.comment, { wide: true, help: '最多 80 個 ASCII 可列印字元。' });
      const sync = () => { out.disabled = chain.value === 'input'; port.disabled = !['tcp', 'udp'].includes(protocol.value); };
      chain.addEventListener('change', sync); protocol.addEventListener('change', sync); sync();
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
      if (kind === 'vlan') {
        items = state.config.vlans;
        value = { interface: optionalField('interface'), parent: optionalField('parent'), id: numberField('id'), address: optionalField('address'), dhcp: $('edit-dhcp-enabled').checked ? { start: optionalField('dhcp-start'), end: optionalField('dhcp-end'), lease_hours: numberField('lease-hours') } : null, internet: $('edit-internet').checked };
        if (index < 0 && items.length >= 16) throw new Error('最多可建立 16 個 VLAN。');
      } else if (kind === 'wireguard') {
        items = state.config.wireguard;
        value = { interface: optionalField('interface'), address: optionalField('address'), listen_port: numberField('listen-port'), mtu: numberField('mtu'), internet: $('edit-internet').checked, peers: index >= 0 ? structuredClone(items[index].peers) : [] };
        if (index < 0 && items.length >= 4) throw new Error('最多可建立 4 個 WireGuard 介面。');
      } else if (kind === 'peer') {
        items = state.config.wireguard[index].peers; target = peerIndex;
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
        value = { id: optionalField('id'), enabled: $('edit-enabled').checked, chain: $('edit-chain').value, action: $('edit-action').value, protocol: $('edit-protocol').value, in_interface: optionalField('in-interface'), out_interface: $('edit-out-interface').disabled ? null : optionalField('out-interface'), source: optionalField('source'), destination: optionalField('destination'), destination_port: $('edit-destination-port').disabled || !$('edit-destination-port').value ? null : numberField('destination-port'), comment };
        if (index < 0 && items.length >= 64) throw new Error('最多可建立 64 條自訂規則。');
        if (items.some((rule, row) => row !== index && rule.id === value.id)) throw new Error('規則 ID 不可重複。');
      }
      if (target >= 0) items[target] = value; else items.push(value);
      $('editor-dialog').close(); editor = null; markDirty(); renderAdvanced();
    } catch (error) { message('editor-error', errorText(error)); }
  });
  ['editor-close', 'editor-cancel'].forEach((id) => $(id).addEventListener('click', () => $('editor-dialog').close()));
  $('add-vlans').addEventListener('click', () => openEditor('vlan'));
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
  $('refresh-button').addEventListener('click', async () => {
    const button = $('refresh-button'); button.disabled = true; clearMessages();
    try { await loadStatus(); }
    catch (error) { message(state.authenticated ? 'global-error' : 'auth-error', errorText(error)); }
    finally { button.disabled = false; }
  });
  $('network-form').addEventListener('input', markDirty);
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
    advancedBusy();
    $('network-form').setAttribute('aria-busy', 'true'); text('save-config', '儲存中…');
    try {
      const result = await request('/config', { method: 'POST', body: { config, revision: state.revision } });
      if (!state.authenticated) return;
      state.config = config; state.dirty = false; setRevision(result.revision); setPending(Boolean(result.pending_reboot));
      renderAdvanced(); draftMessage('全部變更已儲存到裝置');
      message('global-message', '設定已儲存。重新啟動後生效；目前的連線設定尚未變更。');
      await loadPublicKeys();
    } catch (error) {
      const detail = error.status === 409 ? errorText(error) + ' 請按「重新讀取」，確認最新設定後再編輯。' : errorText(error);
      message(state.authenticated ? 'global-error' : 'auth-error', detail);
    } finally {
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
