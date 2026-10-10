/* ==========================================================================
   天翼校园客户端 — 网页界面逻辑
   纯原生 JS，无框架、无外部依赖。

   对接的后端接口（全部来自 WebApiGet.c / WebApiPost.c）:
     GET  /api/status/auth    -> {status:bool, reachable:bool, offline:bool}
     GET  /api/status/online  -> 204 已在线 / 302 需认证 / 503 离线（无 body）
     GET  /api/status/sys     -> {version,uptime_ms,log_level,log_dir,
                                  config_file,program_enabled,restart_pending,
                                  account_count,thread_count,configured,
                                  config_corrupt,portal_live,portal_live_port,
                                  portal_source}
     GET  /api/getConfigs     -> {enabled,web_external_acc,log_lv,log_dir,
                                  conn_timeout,op_timeout,web_port,accounts:[...]}
     GET  /api/logs           -> {dir, files:[{name,size,mtime,current}]}
     GET  /api/logs?file=X    -> 纯文本
     POST /api/saveConfigs    -> 204（body 为**完整**配置 JSON）
     POST /api/applyConfigs   -> 204（body {"apply":true}）
     POST /api/restartAuth    -> 204
     POST /api/disconnect     -> 204（登出并停止自动重连；幂等）
     POST /api/connect        -> 204（解除断开状态；幂等）
   ========================================================================== */
'use strict';

const $ = (sel) => document.querySelector(sel);

const LOG_LEVEL_NAMES = ['NONE', 'FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'VERBOSE'];
const ONLINE = { OK: 'ok', NEED_AUTH: 'need_auth', OFFLINE: 'offline', UNKNOWN: 'unknown' };

const state = {
  page: 'dashboard',
  online: ONLINE.UNKNOWN,
  auth: { status: false, reachable: false, offline: false },
  sys: null,
  cfg: null,          // 最近一次从后端读到的配置
  provinceFromApi: null, // null = 后端不返回该字段（旧版本）
  logFile: null,
  logTimer: null,
  pollTimer: null,
  dirty: false,
};

/* ------------------------------ 小工具 ---------------------------------- */

function toast(msg, kind = 'ok', ms = 3200) {
  const el = document.createElement('div');
  el.className = 'toast toast--' + kind;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .2s ease';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 220);
  }, ms);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  return res;
}

async function getJSON(path) {
  const res = await api(path);
  if (!res.ok) throw new Error(path + ' → HTTP ' + res.status);
  return res.json();
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  if (d > 0) return `${d} 天 ${h} 时`;
  if (h > 0) return `${h} 时 ${m} 分`;
  if (m > 0) return `${m} 分 ${ss} 秒`;
  return `${ss} 秒`;
}

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

function fmtTime(sec) {
  const d = new Date(sec * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
         `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ------------------------------- 主题 ----------------------------------- */

const THEMES = ['auto', 'light', 'dark'];
const THEME_LABEL = { auto: '跟随系统', light: '浅色', dark: '深色' };

function applyTheme(name) {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const real = name === 'auto' ? (prefersDark ? 'dark' : 'light') : name;
  document.documentElement.dataset.theme = real;
  try { localStorage.setItem('esurfing-theme', name); } catch (_) { /* 隐私模式 */ }
  $('#btnTheme').title = '主题：' + THEME_LABEL[name] + '（点击切换）';
}

function initTheme() {
  let saved = 'auto';
  try { saved = localStorage.getItem('esurfing-theme') || 'auto'; } catch (_) { /* ignore */ }
  if (!THEMES.includes(saved)) saved = 'auto';
  applyTheme(saved);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    let cur = 'auto';
    try { cur = localStorage.getItem('esurfing-theme') || 'auto'; } catch (_) { /* ignore */ }
    if (cur === 'auto') applyTheme('auto');
  });
  $('#btnTheme').addEventListener('click', () => {
    let cur = 'auto';
    try { cur = localStorage.getItem('esurfing-theme') || 'auto'; } catch (_) { /* ignore */ }
    applyTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
  });
}

/* ------------------------------- 导航 ----------------------------------- */

function showPage(name) {
  state.page = name;
  document.querySelectorAll('.nav__item').forEach((b) =>
    b.classList.toggle('is-active', b.dataset.page === name));
  document.querySelectorAll('.page').forEach((p) =>
    p.classList.toggle('is-active', p.dataset.page === name));
  if (name === 'logs') { loadLogFiles(); }
}

/* ---------------------------- 状态轮询 ---------------------------------- */

function setStatusPill(kind, text) {
  const el = $('#tbStatus');
  el.className = 'status-pill ' + (kind ? 'is-' + kind : '');
  el.querySelector('.status-pill__text').textContent = text;
}

async function pollStatus() {
  // /api/status/online 用状态码表达，没有 body
  let online = ONLINE.UNKNOWN;
  try {
    const res = await api('/api/status/online');
    if (res.status === 204) online = ONLINE.OK;
    else if (res.status === 302) online = ONLINE.NEED_AUTH;
    else if (res.status === 503) online = ONLINE.OFFLINE;
  } catch (_) { online = ONLINE.UNKNOWN; }
  state.online = online;

  try { state.auth = await getJSON('/api/status/auth'); } catch (_) { /* 保持旧值 */ }
  try { state.sys = await getJSON('/api/status/sys'); } catch (_) { /* 保持旧值 */ }

  renderStatus();
}

/* ------------------------- 「实际使用的门户」 ---------------------------- */

/**
 * 把「程序到底在连哪个门户」画出来。
 *
 * 设置页那两栏填的是**回退值**（设备没下发时用的兜底），而用户看到「门户地址
 * 175.12.104.1」自然会以为那就是程序在连的地址 —— 这两个值可以不一样。
 * 后端把上一次认证真正采用的值放在 /api/status/sys 里，这里如实并排显示。
 *
 * 三种情形分开说，不含糊：
 *   dhcp   接入设备下发的（正常情况）
 *   config 设备没下发，退回了配置值
 *   空     还没判定过：程序刚起来，或者本来就已认证（那时没有 302 可看）
 *
 * 已认证时这个值是**上一次**的结果，必须写清楚，不能假装它是当前的 ——
 * 认证成功后探测返回 204，门户地址这个量在现场根本不存在。
 */
function renderLivePortal() {
  const s = state.sys;

  const text = {
    dhcp: ['接入设备下发', 'ok'],
    config: ['设备未下发，回退到配置', 'warn'],
  };

  let addr = '未知';
  let note = '尚未认证，接入设备还没告知';
  let kind = 'unknown';

  if (s && s.portal_live) {
    addr = s.portal_live + (s.portal_live_port ? ':' + s.portal_live_port : '');
    const t = text[s.portal_source];
    note = t ? t[0] : '';
    kind = t ? t[1] : 'unknown';

    /* 已认证 = 没有 302，这个值是上一次认证时记下的 */
    if (state.auth && state.auth.status) {
      note = (note ? note + '，' : '') + '上次认证时采用';
    }
  }

  const live = $('#portalLive');
  if (live) {
    live.dataset.kind = kind;
    $('#portalLiveAddr').textContent = addr;
    $('#portalLiveNote').textContent = note;
  }

  const abEl = $('#abPortal');
  if (abEl) {
    abEl.textContent = addr;
    $('#abPortalSrc').textContent =
      s && s.portal_live
        ? (kind === 'ok' ? '接入设备下发' : kind === 'warn' ? '配置回退' : '—')
        : '尚未判定';
  }
}

function renderStatus() {
  const a = state.auth || {};
  const s = state.sys;

  /* 用户主动断开时, 网络探测必然显示"需要认证"/"已断线" —— 那是**预期结果**,
     不是故障, 所以断开的判断要排在网络状态之前, 否则界面会把用户自己刚做的
     操作报成异常。 */
  const offline = a.offline === true;

  /* 还没配置好（账号为空 / 被停用）。这时网络探测必然显示"需要认证"，
     但那是**还没开始认证**，不是故障 —— 所以这个判断要排在网络状态之前，
     否则第一次打开页面的人只会看到"需要认证"，不知道该怎么办。 */
  const notConfigured = !!(s && s.configured === false);

  // 顶部胶囊
  if (notConfigured) {
    setStatusPill('busy', '待配置');
  } else if (offline) {
    setStatusPill('err', '已断开');
  } else if (state.online === ONLINE.OK) {
    setStatusPill('ok', a.status ? '已认证' : '已在线');
  } else if (state.online === ONLINE.NEED_AUTH) {
    setStatusPill('warn', '需要认证');
  } else if (state.online === ONLINE.OFFLINE) {
    setStatusPill('err', '已断线');
  } else {
    setStatusPill('busy', '状态未知');
  }

  // 主卡
  const hero = $('#heroCard');
  const bar = $('#heroBar');
  const C = 2 * Math.PI * 18;
  bar.setAttribute('stroke-dasharray', C.toFixed(1));

  let heroClass = '', stateText = '', hint = '', dash = 0;
  if (notConfigured) {
    heroClass = 'is-warn'; stateText = '等待配置'; dash = C * .12;
    hint = '在「设置」里填手机号、密码并选择省份，然后点「保存并应用」';
  } else if (offline) {
    heroClass = 'is-err'; stateText = '已断开连接'; dash = 0;
    hint = '会话已登出，程序不会再自动重连';
  } else if (state.online === ONLINE.OK && a.status) {
    heroClass = 'is-ok'; stateText = '已连接并认证'; dash = C;
    hint = '会话有效，心跳正常';
  } else if (state.online === ONLINE.OK) {
    heroClass = 'is-ok'; stateText = '出网正常'; dash = C * .66;
    hint = a.reachable === false ? '但认证进程不可达' : '尚未建立本程序的会话';
  } else if (state.online === ONLINE.NEED_AUTH) {
    heroClass = 'is-warn'; stateText = '需要认证'; dash = C * .33;
    hint = '门户已拦截，等待程序发起认证';
  } else if (state.online === ONLINE.OFFLINE) {
    heroClass = 'is-err'; stateText = '已断线'; dash = C * .08;
    hint = '探测不到公网出口';
  } else {
    heroClass = 'is-warn'; stateText = '状态未知'; dash = C * .15;
    hint = '无法从后端读取状态';
  }
  hero.className = 'hero ' + heroClass;
  bar.setAttribute('stroke-dashoffset', (C - dash).toFixed(1));
  $('#heroState').textContent = stateText;
  $('#heroHint').textContent = hint;

  // 统计卡
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('#stAuth', notConfigured ? '待配置' : (offline ? '已断开' : (a.status ? '已认证' : '未认证')));
  set('#stAuthSub', notConfigured ? '还没有账号，见「设置」'
                                 : (offline ? '手动断开，等待「连接」'
                                            : (a.reachable === false ? '认证进程不可达' : '认证进程可达')));
  set('#stOnline', state.online === ONLINE.OK ? '通' :
                   state.online === ONLINE.NEED_AUTH ? '待认证' :
                   state.online === ONLINE.OFFLINE ? '断' : '未知');
  set('#stOnlineSub', '基于门户探测');
  set('#stUptime', s ? fmtDuration(s.uptime_ms) : '—');
  set('#stUptimeSub', s ? '自本次启动' : '—');
  set('#stAccounts', s ? String(s.account_count) : '—');
  set('#stAccountsSub', s ? `${s.thread_count} 个认证线程` : '—');
  $('#navUptime').textContent = s ? '运行 ' + fmtDuration(s.uptime_ms) : '运行 —';

  if (s) {
    set('#tbVersion', s.version || '—');
    set('#abVersion', s.version || '—');
    set('#siVersion', s.version || '—');
    set('#siLogLv', `${s.log_level} ${LOG_LEVEL_NAMES[s.log_level] || ''}`);
    set('#siLogDir', s.log_dir || '—');
    set('#siCfg', s.config_file || '—');
    set('#siRestart', s.restart_pending ? '有（点「保存并应用」生效）' : '无');
  }

  renderLivePortal();

  /* 「断开连接 / 连接」按钮: 断开中它变成主按钮, 同时禁用「重新认证」
     （那个接口要求当前已认证, 断开状态下必然 403, 不如直接禁用） */
  const btnConn = $('#btnDisconnect');
  if (btnConn) {
    btnConn.textContent = offline ? '连接' : '断开连接';
    btnConn.classList.toggle('btn--accent', offline);
    btnConn.classList.toggle('btn--danger', !offline);
    btnConn.disabled = a.reachable === false;
  }
  const btnReauth = $('#btnReauth');
  if (btnReauth) btnReauth.disabled = offline || notConfigured;

  /* 设置页的引导条也跟着状态走（配置刚被应用时它要自己消失） */
  renderSettingsBanner();
}

/* ------------------------------ 配置读写 -------------------------------- */

/**
 * 后端是否返回了省份字段。
 *
 * 这件事必须检查：/api/saveConfigs 是**原样写盘**的（Config.c 的 write_cfg_json），
 * 页面读不到什么、保存时就会写丢什么。旧版后端不返回 province/portal/mscgip，
 * 在这种后端上点一次保存就会把湖南配置抹成广东 —— 所以这里直接禁用保存按钮，
 * 而不是让用户"小心一点"。
 */
function checkConfigRoundTrip(cfg) {
  const acct = cfg && cfg.accounts && cfg.accounts[0];
  state.provinceFromApi = acct && Object.prototype.hasOwnProperty.call(acct, 'province')
    ? acct.province : null;

  const banner = $('#settingsBanner');
  const btnSave = $('#btnSave');
  const btnApply = $('#btnApply');

  if (state.provinceFromApi === null) {
    btnSave.disabled = true;
    btnApply.disabled = true;
    renderSettingsBanner();
    return;
  }

  btnSave.disabled = false;
  btnApply.disabled = false;
  renderSettingsBanner();
}

/**
 * 设置页顶部的提示条。按优先级只显示一条：
 *
 *  1. 后端太旧（不返回 province）—— 保存会把省份抹掉，直接禁用保存
 *  2. 配置文件无法解析 —— 保存会覆盖它，必须先告诉用户
 *  3. 还没配置好 —— 首次运行的引导
 *
 * 第 1 条由 checkConfigRoundTrip 关掉按钮，这里只负责画出来。
 */
function renderSettingsBanner() {
  const banner = $('#settingsBanner');
  if (!banner) return;

  if (state.provinceFromApi === null) {
    banner.innerHTML =
      '<div class="banner banner--err">' +
      '<div class="banner__icon">⚠️</div><div>' +
      '<div class="banner__title">已禁用保存：后端版本过旧</div>' +
      '<div class="banner__desc">当前运行的程序不返回 province / portal / mscgip，' +
      '而保存是把页面内容原样写盘 —— 在这里保存会把省份配置抹掉，' +
      '重启后静默退回广东模式。请先更新到带省份字段的版本。</div>' +
      '</div></div>';
    return;
  }

  const sys = state.sys;

  if (sys && sys.config_corrupt) {
    banner.innerHTML =
      '<div class="banner banner--err">' +
      '<div class="banner__icon">⚠️</div><div>' +
      '<div class="banner__title">原来的配置文件无法解析</div>' +
      '<div class="banner__desc">程序已经改用默认值在跑。你在这里点「保存」，' +
      '会用页面上的内容**覆盖**那个文件 —— 如果原文件里有想保留的东西，' +
      '先备份再保存。</div>' +
      '</div></div>';
    return;
  }

  if (sys && sys.configured === false) {
    banner.innerHTML =
      '<div class="banner banner--accent">' +
      '<div class="banner__icon">①</div><div>' +
      '<div class="banner__title">还差一步就能上网</div>' +
      '<div class="banner__desc">' +
      '<b>1.</b> 填手机号与密码；<b>2.</b> 选对省份（湖南 / 广东）；' +
      '<b>3.</b> 点下面的「保存并应用」。<br>' +
      '不需要手工编辑任何配置文件 —— 填完这一页就行了。' +
      (sys.program_enabled === false ? '<br>⚠️ 当前是「已停用」状态，请把上面的开关打开。' : '') +
      '</div></div></div>';
    return;
  }

  banner.innerHTML = '';
}

function fillForm(cfg) {
  const a = cfg.accounts && cfg.accounts[0] ? cfg.accounts[0] : {};

  $('#fUser').value = a.username || '';
  $('#fPass').value = a.password || '';
  $('#fChannel').value = a.channel || 'android';

  if (state.provinceFromApi !== null) {
    $('#fProvince').value = a.province || 'guangdong';
    $('#fPortal').value = a.portal || '';
    $('#fPortalPort').value = a.portal_port || '';
    $('#fMscgip').value = a.mscgip || '';
  }
  syncProvinceEnabled();

  setSwitch('#fEnabled', !!cfg.enabled);
  setSwitch('#fWebExternal', !!cfg.web_external_acc);
  $('#fLogLv').value = cfg.log_lv;
  updateLogLvName();
  $('#fConnTimeout').value = cfg.conn_timeout;
  $('#fOpTimeout').value = cfg.op_timeout;
  $('#fWebPort').value = cfg.web_port;
  $('#fLogDir').value = cfg.log_dir || './';

  state.dirty = false;
}

/** 广东模式下门户/mscgip 用不到，灰掉以免误导 */
function syncProvinceEnabled() {
  const isHunan = $('#fProvince').value === 'hunan';
  ['#fPortal', '#fPortalPort', '#fMscgip'].forEach((id) => {
    const el = $(id);
    el.disabled = !isHunan;
    el.style.opacity = isHunan ? '' : '.5';
  });
}

function setSwitch(sel, on) {
  const el = $(sel);
  el.setAttribute('aria-checked', on ? 'true' : 'false');
}
function getSwitch(sel) {
  return $(sel).getAttribute('aria-checked') === 'true';
}

function updateLogLvName() {
  const v = Number($('#fLogLv').value);
  $('#logLvName').textContent = `(${v} ${LOG_LEVEL_NAMES[v] || ''})`;
}

function collectForm() {
  const cfg = JSON.parse(JSON.stringify(state.cfg || {}));
  const acct = (cfg.accounts && cfg.accounts[0]) || {};

  acct.username = $('#fUser').value.trim();
  acct.password = $('#fPass').value;
  acct.channel = $('#fChannel').value;
  if (state.provinceFromApi !== null) {
    acct.province = $('#fProvince').value;
    acct.portal = $('#fPortal').value.trim();
    const port = parseInt($('#fPortalPort').value, 10);
    acct.portal_port = Number.isFinite(port) ? port : 10001;
    acct.mscgip = $('#fMscgip').value.trim();
  }
  // time_windows 本页不编辑，但必须原样带回去（否则同样会被写丢）
  if (!Array.isArray(acct.time_windows)) acct.time_windows = [];

  cfg.accounts = [acct];
  cfg.enabled = getSwitch('#fEnabled');
  cfg.web_external_acc = getSwitch('#fWebExternal');
  cfg.log_lv = Number($('#fLogLv').value);
  cfg.conn_timeout = Number($('#fConnTimeout').value) || 7;
  cfg.op_timeout = Number($('#fOpTimeout').value) || 10;
  cfg.web_port = Number($('#fWebPort').value) || 8888;
  cfg.log_dir = $('#fLogDir').value.trim() || './';

  return cfg;
}

async function loadConfig() {
  try {
    const cfg = await getJSON('/api/getConfigs');
    state.cfg = cfg;
    checkConfigRoundTrip(cfg);
    fillForm(cfg);
  } catch (e) {
    toast('读取配置失败：' + e.message, 'err');
  }
}

async function saveConfig() {
  const msg = $('#saveMsg');
  try {
    const cfg = collectForm();
    if (!cfg.accounts[0].username) { toast('手机号不能为空', 'err'); return false; }
    const res = await api('/api/saveConfigs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    if (res.status === 204) {
      state.cfg = cfg;
      state.dirty = false;
      msg.textContent = '已保存';
      msg.className = 'actions__msg is-ok';
      toast('配置已保存', 'ok');
      return true;
    }
    msg.textContent = '保存失败（HTTP ' + res.status + '）';
    msg.className = 'actions__msg is-err';
    toast('保存失败：HTTP ' + res.status, 'err');
    return false;
  } catch (e) {
    msg.textContent = '保存失败：' + e.message;
    msg.className = 'actions__msg is-err';
    toast('保存失败：' + e.message, 'err');
    return false;
  }
}

async function applyConfig() {
  const ok = await saveConfig();
  if (!ok) return;
  try {
    const res = await api('/api/applyConfigs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apply: true }),
    });
    if (res.status === 204) {
      toast('已提交，程序即将重启以应用配置', 'ok', 5000);
      $('#saveMsg').textContent = '已提交，程序重启中…';
    } else {
      toast('应用失败：HTTP ' + res.status, 'err');
      $('#saveMsg').textContent = '应用失败（HTTP ' + res.status + '）';
      $('#saveMsg').className = 'actions__msg is-err';
    }
  } catch (e) {
    toast('应用失败：' + e.message, 'err');
  }
}

/* -------------------------------- 日志 ---------------------------------- */

async function loadLogFiles() {
  try {
    const data = await getJSON('/api/logs');
    $('#logsDir').textContent = data.dir || '—';
    const box = $('#logFiles');
    box.innerHTML = '';
    if (!data.files || !data.files.length) {
      box.innerHTML = '<div style="padding:10px;color:var(--text-3);font-size:12.5px">还没有日志文件</div>';
      return;
    }
    data.files.forEach((f) => {
      const b = document.createElement('button');
      b.className = 'log-file' + (state.logFile === f.name ? ' is-active' : '');
      b.innerHTML =
        '<span class="log-file__name">' + escapeHtml(f.name) +
        (f.current ? ' <span style="color:var(--accent)">·当前</span>' : '') + '</span>' +
        '<span class="log-file__meta">' + fmtBytes(f.size) + '</span>';
      b.title = fmtTime(f.mtime);
      b.addEventListener('click', () => { state.logFile = f.name; loadLogFile(); loadLogFiles(); });
      box.appendChild(b);
    });
  } catch (e) {
    toast('读取日志列表失败：' + e.message, 'err');
  }
}

async function loadLogFile() {
  if (!state.logFile) return;
  $('#logName').textContent = state.logFile;
  try {
    const res = await api('/api/logs?file=' + encodeURIComponent(state.logFile));
    const text = await res.text();
    const body = $('#logBody');
    const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
    body.textContent = res.ok ? text : '读取失败：' + text;
    if (atBottom) body.scrollTop = body.scrollHeight;
  } catch (e) {
    $('#logBody').textContent = '读取失败：' + e.message;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ------------------------------ 连接开关 --------------------------------- */

/**
 * 断开 / 连接。
 *
 * 「断开」= 登出（服务端会话真的被释放，不是本地假断开），之后程序不再自动
 * 重连，直到点「连接」。后端是幂等的，重复点不会出错。
 *
 * 状态不会在 204 之后立刻翻转：断开要等认证线程退出、在 clean() 里跑完 term()，
 * 所以这里补两次延迟刷新，让界面跟得上（正常情况下 3 秒的轮询也会纠正它）。
 */
async function toggleConnection() {
  const offline = state.auth && state.auth.offline === true;

  if (!offline && !confirm('断开连接？\n会先登出当前会话（服务端下线），' +
                           '之后程序不再自动重连，直到你点「连接」。')) {
    return;
  }

  try {
    const res = await api('/api/' + (offline ? 'connect' : 'disconnect'), { method: 'POST' });
    if (res.status === 204) {
      toast(offline ? '已请求连接，正在重新认证' : '已请求断开连接，正在登出', 'ok');
      setTimeout(pollStatus, 800);
      setTimeout(pollStatus, 2600);
    } else if (res.status === 503) {
      toast('认证进程不可达，请检查程序是否在运行', 'err');
    } else {
      toast('请求失败：HTTP ' + res.status, 'err');
    }
  } catch (e) {
    toast('请求失败：' + e.message, 'err');
  }
}

/* ------------------------------- 事件绑定 -------------------------------- */

function bind() {
  document.querySelectorAll('.nav__item').forEach((b) =>
    b.addEventListener('click', () => showPage(b.dataset.page)));

  $('#btnRefresh').addEventListener('click', async () => {
    await pollStatus();
    await loadConfig();
    if (state.page === 'logs') loadLogFiles();
    toast('已刷新', 'ok', 1600);
  });

  $('#btnReauth').addEventListener('click', async () => {
    if (!confirm('让认证进程重新认证一次？\n这会先登出当前会话，然后重新登录（其间会短暂断网）。')) return;
    try {
      const res = await api('/api/restartAuth', { method: 'POST' });
      if (res.status === 204) toast('已请求重新认证', 'ok');
      else toast('请求失败：HTTP ' + res.status, 'err');
    } catch (e) { toast('请求失败：' + e.message, 'err'); }
  });

  $('#btnDisconnect').addEventListener('click', toggleConnection);

  $('#btnPeek').addEventListener('click', () => {
    const p = $('#fPass');
    const show = p.type === 'password';
    p.type = show ? 'text' : 'password';
    $('#btnPeek').textContent = show ? '隐藏' : '显示';
  });

  $('#fLogLv').addEventListener('input', updateLogLvName);
  $('#fProvince').addEventListener('change', syncProvinceEnabled);

  ['#fEnabled', '#fWebExternal'].forEach((sel) =>
    $(sel).addEventListener('click', () => setSwitch(sel, !getSwitch(sel))));

  ['input', 'change'].forEach((ev) => {
    document.querySelectorAll('.page[data-page="settings"] .input').forEach((el) =>
      el.addEventListener(ev, () => { state.dirty = true; }));
  });

  $('#btnSave').addEventListener('click', saveConfig);
  $('#btnApply').addEventListener('click', applyConfig);
  $('#btnReload').addEventListener('click', loadConfig);

  $('#btnLogRefresh').addEventListener('click', () => { loadLogFiles(); loadLogFile(); });
  $('#logFollow').addEventListener('change', (e) => {
    if (state.logTimer) { clearInterval(state.logTimer); state.logTimer = null; }
    if (e.target.checked) state.logTimer = setInterval(loadLogFile, 2000);
  });

  window.addEventListener('beforeunload', (e) => {
    if (state.dirty) { e.preventDefault(); e.returnValue = ''; }
  });

  $('#abUrl').textContent = location.origin;
}

/* -------------------------------- 启动 ---------------------------------- */

async function boot() {
  initTheme();
  bind();
  await pollStatus();
  await loadConfig();

  /**
   * 还没配置好 —— 首次运行就是这个状态。
   *
   * 直接把用户送到「设置」页：这是唯一需要他动手的地方，让他在仪表盘上
   * 看着一个"需要认证"的红灯猜要干什么，是最没必要的折磨。
   */
  if (state.sys && state.sys.configured === false) {
    showPage('settings');
    toast('欢迎使用：请填写手机号与密码，选择省份，然后点「保存并应用」', 'ok', 8000);
  }

  state.pollTimer = setInterval(pollStatus, 3000);
}

document.addEventListener('DOMContentLoaded', boot);
