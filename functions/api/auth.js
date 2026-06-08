/**
 * 认证 API（安全加固版 — HttpOnly Cookie + CSRF）
 * POST /api/auth/login       - 手机号+密码登录
 * POST /api/auth/register    - 注册
 * GET  /api/auth/verify      - 验证 token
 * GET  /api/auth/me          - 获取当前用户（读取 Cookie JWT）
 * POST /api/auth/logout      - 退出登录（清除 Cookie）
 */

let CURRENT_ORIGIN = 'https://skgl.pages.dev';
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': CURRENT_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true',
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

function error(msg, status = 400) {
  return json({ success: false, error: msg }, status);
}

// ========== Cookie 工具 ==========
function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function setCookieHeaders(jwt, csrf) {
  const headers = {};
  if (jwt) {
    headers['Set-Cookie'] = `skgl_token=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`;
  }
  if (csrf) {
    const csrfCookie = `skgl_csrf=${csrf}; Secure; SameSite=Strict; Path=/; Max-Age=604800`;
    if (headers['Set-Cookie']) {
      headers['Set-Cookie'] = [headers['Set-Cookie'], csrfCookie];
    } else {
      headers['Set-Cookie'] = csrfCookie;
    }
  }
  return headers;
}

function clearCookieHeaders() {
  return {
    'Set-Cookie': [
      'skgl_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
      'skgl_csrf=; Secure; SameSite=Strict; Path=/; Max-Age=0',
    ],
  };
}

function generateCSRF() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ========== JWT 工具（仅使用 crypto.subtle，无外部依赖） ==========
function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function signJWT(payload, secret) {
  const enc = new TextEncoder();
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const data = enc.encode(`${headerB64}.${payloadB64}`);
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return `${headerB64}.${payloadB64}.${bufferToBase64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const enc = new TextEncoder();
  const data = enc.encode(`${parts[0]}.${parts[1]}`);
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  let sigBytes;
  try {
    sigBytes = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  } catch { return null; }
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
  if (!valid) return null;
  try {
    const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(payloadJson);
    if (Date.now() > payload.exp * 1000) return null;
    return payload;
  } catch { return null; }
}

// ========== PBKDF2 密码哈希 ==========
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function hashPasswordPBKDF2(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return `${bytesToHex(salt)}:${bytesToHex(new Uint8Array(hash))}`;
}

async function verifyPasswordPBKDF2(password, stored) {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const salt = hexToBytes(parts[0]);
  const storedHash = parts[1];
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return bytesToHex(new Uint8Array(hash)) === storedHash;
}

async function sha256(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

function idCardHashSecret(env) {
  return env?.DATA_ENCRYPTION_KEY || env?.SKGL_DATA_KEY || env?.JWT_SECRET || 'skgl-id-card-dev-secret';
}

async function hashIdCardValue(env, phone, idCard) {
  return sha256(`${idCardHashSecret(env)}:id-card:${normalizePhone(phone)}:${normalizeIdCard(idCard)}`);
}

function getJWTSecret(env) {
  const secret = env && env.JWT_SECRET;
  if (!secret || secret === 'dev-secret-change-in-production' || secret.length < 32) return null;
  return secret;
}

function isDisabledValue(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'disabled' || v === '停用' || v === '禁用' || v === '离职';
}

async function ensureAuthUsersSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    phone TEXT,
    tenant_id TEXT,
    password_hash TEXT,
    salt TEXT,
    role TEXT,
    wx_openid TEXT,
    wx_unionid TEXT,
    created_at TEXT
  )`).run().catch(() => {});
  const cols = ['phone TEXT','username TEXT','tenant_id TEXT','id_card TEXT','id_card_hash TEXT','password_hash TEXT','salt TEXT','role TEXT','wx_openid TEXT','wx_unionid TEXT','created_at TEXT','name TEXT','disabled TEXT','must_change_password TEXT'];
  for (const col of cols) {
    try { await DB.prepare(`ALTER TABLE users ADD COLUMN ${col}`).run(); } catch (_) {}
  }
  await ensureTenantMembershipSchema(DB);
}

async function ensureTenantMembershipSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT,
    owner_user_id TEXT,
    status TEXT,
    created_at TEXT,
    updated_at TEXT
  )`).run().catch(() => {});
  await DB.prepare(`CREATE TABLE IF NOT EXISTS tenant_members (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT,
    user_id INTEGER,
    phone TEXT,
    name TEXT,
    role TEXT,
    disabled TEXT,
    notes TEXT,
    created_at TEXT,
    updated_at TEXT
  )`).run().catch(() => {});
  const tenantCols = ['name TEXT','owner_user_id TEXT','status TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of tenantCols) {
    try { await DB.prepare(`ALTER TABLE tenants ADD COLUMN ${col}`).run(); } catch (_) {}
  }
  const memberCols = ['tenant_id TEXT','user_id INTEGER','phone TEXT','name TEXT','role TEXT','disabled TEXT','notes TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of memberCols) {
    try { await DB.prepare(`ALTER TABLE tenant_members ADD COLUMN ${col}`).run(); } catch (_) {}
  }
  const rows = await DB.prepare("SELECT id, phone, tenant_id, role, name, disabled, created_at FROM users WHERE COALESCE(phone,'') <> '' AND COALESCE(tenant_id,'') <> '' AND LOWER(COALESCE(role,'')) IN ('admin','管理员','1') LIMIT 1000")
    .all().catch(() => ({ results: [] }));
  for (const u of rows.results || []) {
    const tenantId = String(u.tenant_id || '').trim();
    if (!tenantId) continue;
    const n = u.created_at || new Date().toISOString();
    await DB.prepare('INSERT OR IGNORE INTO tenants (id, name, owner_user_id, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(tenantId, `账套${tenantId}`, String(u.id), 'active', n, n).run().catch(() => {});
    await DB.prepare('UPDATE tenants SET owner_user_id = COALESCE(NULLIF(owner_user_id, ""), ?2), status = COALESCE(NULLIF(status, ""), "active") WHERE id = ?1')
      .bind(tenantId, String(u.id)).run().catch(() => {});
    const exists = await DB.prepare('SELECT id FROM tenant_members WHERE tenant_id = ?1 AND user_id = ?2')
      .bind(tenantId, u.id).first().catch(() => null);
    if (!exists) {
      await DB.prepare('INSERT INTO tenant_members (tenant_id, user_id, phone, name, role, disabled, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
        .bind(tenantId, u.id, u.phone || '', u.name || '', effectiveUserRole(u) || 'admin', u.disabled || 'false', '', n, n).run().catch(() => {});
    }
  }
}

// ========== 暴力破解防护 ==========
const SUPER_ADMIN_PHONE = '13399330020';
const loginFailMap = new Map();
function effectiveUserRole(user) {
  return String(user?.phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (user?.role || '');
}

function memberRole(user, member) {
  return String(user?.phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (member?.role || user?.role || 'user');
}

async function activeTenantMemberships(DB, user) {
  await ensureTenantMembershipSchema(DB);
  const rows = await DB.prepare(`SELECT m.tenant_id, m.role, m.disabled, m.name, t.name AS tenant_name, t.status
    FROM tenant_members m
    LEFT JOIN tenants t ON t.id = m.tenant_id
    WHERE m.user_id = ?1
    ORDER BY m.id ASC`)
    .bind(user.id).all().catch(() => ({ results: [] }));
  return (rows.results || [])
    .filter(r => !isDisabledValue(r.disabled) && !isDisabledValue(r.status) && String(r.status || 'active') !== 'deleted')
    .map(r => ({
      tenantId: String(r.tenant_id || ''),
      name: r.tenant_name || `账套${r.tenant_id || ''}`,
      role: memberRole(user, r),
    }))
    .filter(r => r.tenantId);
}

async function signLoginSession(env, user, tenant) {
  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return null;
  const now = Math.floor(Date.now() / 1000);
  return signJWT({
    uid: user.id,
    tid: tenant?.tenantId || '',
    role: tenant?.role || effectiveUserRole(user) || 'user',
    iat: now,
    exp: now + 7 * 24 * 60 * 60,
  }, JWT_SECRET);
}

async function signPendingSession(env, user, reason) {
  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return null;
  const now = Math.floor(Date.now() / 1000);
  return signJWT({
    uid: user.id,
    pending: reason || 'tenant',
    iat: now,
    exp: now + 60 * 60,
  }, JWT_SECRET);
}

function checkBruteForce(ip) {
  const entry = loginFailMap.get(ip);
  if (!entry) return true;
  if (entry.lockUntil && Date.now() < entry.lockUntil) return false;
  if (entry.lockUntil && Date.now() >= entry.lockUntil) {
    loginFailMap.delete(ip);
  }
  return true;
}

function recordLoginFailure(ip) {
  const entry = loginFailMap.get(ip) || { count: 0, lockUntil: 0 };
  entry.count++;
  if (entry.count >= 5) {
    entry.lockUntil = Date.now() + 15 * 60 * 1000;
  }
  loginFailMap.set(ip, entry);
}

function resetLoginFailures(ip) {
  loginFailMap.delete(ip);
}

// ========== 审计日志记录（通过 context 回调注入） ==========
async function tryAudit(context, DB, userId, action, target, detail, ip, tenantId = '') {
  if (context._auditLog) {
    try { await context._auditLog(DB, userId, action, target, detail, ip, tenantId); } catch (_) {}
  }
}

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function validPhone(phone) {
  return /^1\d{10}$/.test(phone);
}

function normalizeIdCard(idCard) {
  return String(idCard || '').trim().toUpperCase().replace(/\s+/g, '');
}

function validIdCard(idCard) {
  return /^(\d{15}|\d{17}[\dX])$/.test(idCard);
}

function isPublicRegisterEnabled(env) {
  if (env.DISABLE_PUBLIC_REGISTER === '1' || env.DISABLE_PUBLIC_REGISTER === 'true') return false;
  if (env.ALLOW_PUBLIC_REGISTER === '0' || env.ALLOW_PUBLIC_REGISTER === 'false') return false;
  return true;
}

// ========== 主路由 ==========
export default async function auth(context) {
  const { request, env, body } = context;
  CURRENT_ORIGIN = request.headers.get('Origin') || new URL(request.url).origin || CURRENT_ORIGIN;
  const DB = env.DB;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/auth\/?/, '');

  switch (`${request.method} ${path}`) {
    case 'POST login':
      return await login(DB, body, request, env, context);
    case 'POST select-tenant':
      return await selectTenant(context);
    case 'POST change-initial-password':
      return await changeInitialPassword(context);
    case 'POST register':
      return await register(DB, body, env, context);
    case 'GET verify':
      return await verifyToken(context);
    case 'GET me':
      return await getCurrentUser(context);
    case 'POST logout':
      return await logout(context);
    default:
      return error('未知的认证操作', 404);
  }
}

// 手机号+密码登录
async function login(DB, body, request, env, context) {
  await ensureAuthUsersSchema(DB);
  const phone = normalizePhone(body?.phone);
  const password = body?.password || '';
  if (!phone || !password) return error('手机号或密码错误');

  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '0.0.0.0';

  if (!checkBruteForce(ip)) {
    await tryAudit(context, DB, null, 'login_fail', 'auth', 'IP locked', ip);
    return error('登录失败次数过多，请15分钟后再试', 429);
  }

  const user = await DB.prepare(
    'SELECT id, phone, password_hash, role, disabled, must_change_password, created_at FROM users WHERE phone = ?1'
  ).bind(phone).first();

  if (!user) {
    recordLoginFailure(ip);
    await tryAudit(context, DB, null, 'login_fail', 'auth', 'phone_not_found', ip);
    return error('手机号或密码错误');
  }

  if (isDisabledValue(user.disabled)) {
    recordLoginFailure(ip);
    await tryAudit(context, DB, user.id, 'login_fail', 'auth', 'disabled_user', ip);
    return error('账号已被禁用，请联系管理员', 403);
  }

  let passwordValid = false;
  let needsUpgrade = false;

  if (user.password_hash && user.password_hash.includes(':')) {
    passwordValid = await verifyPasswordPBKDF2(password, user.password_hash);
  }
  if (!passwordValid) {
    const oldHash = await sha256(password + ':' + phone);
    if (oldHash === user.password_hash) {
      passwordValid = true;
      needsUpgrade = true;
    }
  }

  if (!passwordValid) {
    recordLoginFailure(ip);
    await tryAudit(context, DB, null, 'login_fail', 'auth', 'wrong_pwd', ip);
    return error('手机号或密码错误');
  }

  if (needsUpgrade) {
    const newHash = await hashPasswordPBKDF2(password);
    await DB.prepare('UPDATE users SET password_hash = ?1 WHERE id = ?2')
      .bind(newHash, user.id).run();
  }

  resetLoginFailures(ip);

  const csrf = generateCSRF();
  await tryAudit(context, DB, user.id, 'login_success', 'auth', '', ip);

  const role = effectiveUserRole(user);
  if (role === 'admin' && user.role !== 'admin') {
    await DB.prepare('UPDATE users SET role = ?1 WHERE id = ?2').bind('admin', user.id).run().catch(() => {});
  }

  if (isDisabledValue(user.must_change_password)) {
    const pendingToken = await signPendingSession(env, user, 'password');
    if (!pendingToken) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
    return json({
      success: true,
      data: { csrf, requiresPasswordChange: true, user: { id: user.id, phone: user.phone } },
    }, 200, setCookieHeaders(pendingToken, csrf));
  }

  const tenants = await activeTenantMemberships(DB, user);
  if (!tenants.length) return error('暂无可进入的账套，请联系管理员', 403);
  if (tenants.length > 1) {
    const pendingToken = await signPendingSession(env, user, 'tenant');
    if (!pendingToken) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
    return json({
      success: true,
      data: { csrf, requiresTenantSelect: true, tenants, user: { id: user.id, phone: user.phone } },
    }, 200, setCookieHeaders(pendingToken, csrf));
  }

  const token = await signLoginSession(env, user, tenants[0]);
  if (!token) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  return json({
    success: true,
    data: { csrf, tenant: tenants[0], user: { id: user.id, phone: user.phone, role: tenants[0].role, createdAt: user.created_at } },
  }, 200, setCookieHeaders(token, csrf));
}

// 注册
async function register(DB, body, env, context) {
  await ensureAuthUsersSchema(DB);
  const phone = normalizePhone(body?.phone);
  const idCard = normalizeIdCard(body?.id_card || body?.idCard || body?.identity_no);
  const companyName = String(body?.company_name || body?.companyName || body?.tenant_name || '').trim();
  const password = body?.password || '';
  if (!phone || !idCard || !password || !companyName) return error('手机号、身份证号、公司名称和密码为必填项');
  if (!validPhone(phone)) return error('请输入正确的11位手机号');
  if (!validIdCard(idCard)) return error('请输入正确的身份证号');
  if (password.length < 6) return error('密码至少6位');

  const countRow = await DB.prepare('SELECT COUNT(*) as cnt FROM users').first().catch(() => ({ cnt: 0 }));
  const isFirstUser = !countRow || Number(countRow.cnt || 0) === 0;
  if (!isFirstUser && !isPublicRegisterEnabled(env)) {
    return error('公开注册已关闭，请让管理员创建账号', 403);
  }

  const existing = await DB.prepare('SELECT id FROM users WHERE phone = ?1')
    .bind(phone).first();
  if (existing) return error('该手机号已注册');

  const now = new Date().toISOString();
  const passwordHash = await hashPasswordPBKDF2(password);
  const idCardHash = await hashIdCardValue(env, phone, idCard);

  const role = 'admin';
  const result = await DB.prepare(
    'INSERT INTO users (phone, tenant_id, id_card, id_card_hash, password_hash, salt, role, must_change_password, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)'
  ).bind(phone, '', '', idCardHash, passwordHash, '', role, 'false', now).run();
  const id = String(result.meta.last_row_id || 1);
  await DB.prepare('UPDATE users SET tenant_id = ?1 WHERE id = ?2 AND (tenant_id IS NULL OR tenant_id = \'\')')
    .bind(id, id).run().catch(() => {});
  await DB.prepare('INSERT OR REPLACE INTO tenants (id, name, owner_user_id, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
    .bind(id, companyName, id, 'active', now, now).run();
  await DB.prepare('INSERT INTO tenant_members (tenant_id, user_id, phone, name, role, disabled, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
    .bind(id, id, phone, '', 'admin', 'false', '', now, now).run();

  const token = await signLoginSession(env, { id, phone, role }, { tenantId: id, name: companyName, role: 'admin' });
  if (!token) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);

  const csrf = generateCSRF();

  return json({
    success: true,
    data: { csrf, tenant: { tenantId: id, name: companyName, role: 'admin' }, user: { id, phone, role, createdAt: now } },
  }, 201, setCookieHeaders(token, csrf));
}

// 验证 token
async function verifyToken(context) {
  const { request, env } = context;
  let token = getCookie(request, 'skgl_token');
  if (!token) {
    const authHeader = request.headers.get('Authorization') || '';
    token = authHeader.replace('Bearer ', '');
  }
  if (!token) return error('未提供认证令牌', 401);

  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload) return error('令牌无效或已过期', 401);

  return json({ success: true, data: { userId: payload.uid, valid: true } });
}

// 获取当前用户
async function getCurrentUser(context) {
  const { request, env } = context;
  const DB = env.DB;
  await ensureAuthUsersSchema(DB);
  let token = getCookie(request, 'skgl_token');
  if (!token) {
    const authHeader = request.headers.get('Authorization') || '';
    token = authHeader.replace('Bearer ', '');
  }
  if (!token) return error('未登录', 401);

  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload) return error('登录已过期', 401);

  const user = await DB.prepare('SELECT id, phone, role, disabled, must_change_password, created_at FROM users WHERE id = ?1')
    .bind(payload.uid).first().catch(() => null);
  if (!user) return error('用户不存在', 404);
  if (isDisabledValue(user.disabled)) return error('账号已被禁用，请联系管理员', 403);

  if (isDisabledValue(user.must_change_password)) {
    return json({ success: true, data: { id: user.id, phone: user.phone, requiresPasswordChange: true } });
  }

  const tenants = await activeTenantMemberships(DB, user);
  if (!payload.tid) {
    return json({ success: true, data: { id: user.id, phone: user.phone, requiresTenantSelect: true, tenants } });
  }
  const tenant = tenants.find(t => String(t.tenantId) === String(payload.tid));
  if (!tenant) return error('当前账套已停用或无权限，请重新登录', 403);

  let csrf = getCookie(request, 'skgl_csrf');
  if (!csrf) {
    csrf = generateCSRF();
    // 将新生成的 CSRF 令牌写入 cookie，让后续请求能读到
    return json({
      success: true,
      data: { id: user.id, phone: user.phone, role: tenant.role, tenant, createdAt: user.created_at, csrf },
    }, 200, { 'Set-Cookie': `skgl_csrf=${csrf}; Secure; SameSite=Strict; Path=/; Max-Age=${60*60*24*7}` });
  }
  return json({
    success: true,
    data: { id: user.id, phone: user.phone, role: tenant.role, tenant, createdAt: user.created_at, csrf },
  });
}

async function selectTenant(context) {
  const { request, env, body } = context;
  const DB = env.DB;
  await ensureAuthUsersSchema(DB);
  let token = getCookie(request, 'skgl_token');
  if (!token) token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return error('请先登录', 401);
  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload?.uid) return error('登录已过期', 401);
  const user = await DB.prepare('SELECT id, phone, role, disabled, must_change_password, created_at FROM users WHERE id = ?1')
    .bind(payload.uid).first().catch(() => null);
  if (!user) return error('用户不存在', 404);
  if (isDisabledValue(user.disabled)) return error('账号已被禁用，请联系管理员', 403);
  if (isDisabledValue(user.must_change_password)) return error('请先修改初始密码', 403);
  const tenantId = String(body?.tenant_id || body?.tenantId || '').trim();
  const tenants = await activeTenantMemberships(DB, user);
  const tenant = tenants.find(t => String(t.tenantId) === tenantId);
  if (!tenant) return error('该账套已停用或没有权限', 403);
  const nextToken = await signLoginSession(env, user, tenant);
  if (!nextToken) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  const csrf = generateCSRF();
  await tryAudit(context, DB, user.id, 'tenant_select', 'auth', tenantId, request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '', tenantId);
  return json({ success: true, data: { csrf, tenant, user: { id: user.id, phone: user.phone, role: tenant.role, createdAt: user.created_at } } }, 200, setCookieHeaders(nextToken, csrf));
}

async function changeInitialPassword(context) {
  const { request, env, body } = context;
  const DB = env.DB;
  await ensureAuthUsersSchema(DB);
  let token = getCookie(request, 'skgl_token');
  if (!token) token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return error('请先登录', 401);
  const JWT_SECRET = getJWTSecret(env);
  if (!JWT_SECRET) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload?.uid) return error('登录已过期', 401);
  const password = String(body?.password || body?.new_password || '');
  if (password.length < 6) return error('新密码至少6位');
  if (password === '123456') return error('新密码不能继续使用默认密码');
  const user = await DB.prepare('SELECT id, phone, role, disabled FROM users WHERE id = ?1')
    .bind(payload.uid).first().catch(() => null);
  if (!user) return error('用户不存在', 404);
  if (isDisabledValue(user.disabled)) return error('账号已被禁用，请联系管理员', 403);
  const passwordHash = await hashPasswordPBKDF2(password);
  await DB.prepare('UPDATE users SET password_hash = ?1, must_change_password = ?2 WHERE id = ?3')
    .bind(passwordHash, 'false', user.id).run();
  const tenants = await activeTenantMemberships(DB, { ...user, must_change_password: 'false' });
  const csrf = generateCSRF();
  if (!tenants.length) return error('暂无可进入的账套，请联系管理员', 403);
  if (tenants.length > 1) {
    const pendingToken = await signPendingSession(env, user, 'tenant');
    return json({ success: true, data: { csrf, requiresTenantSelect: true, tenants, user: { id: user.id, phone: user.phone } } }, 200, setCookieHeaders(pendingToken, csrf));
  }
  const nextToken = await signLoginSession(env, user, tenants[0]);
  return json({ success: true, data: { csrf, tenant: tenants[0], user: { id: user.id, phone: user.phone, role: tenants[0].role } } }, 200, setCookieHeaders(nextToken, csrf));
}

// 退出登录
async function logout(context) {
  return json({ success: true, message: '已退出登录' }, 200, clearCookieHeaders());
}
