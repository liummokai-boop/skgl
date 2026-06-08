/**
 * 记账客户管理软件 - Cloudflare Pages Functions 主路由（安全加固版 B+）
 * HttpOnly Cookie + CSRF + CSP + 审计日志
 */

import customers from './customers.js';
import bills from './bills.js';
import auth from './auth.js';
import dataHandler from './data.js';
import incomeItems from './income-items.js';
import incomeHandler from './income.js';
import shoukuan from './shoukuan.js';
import masters from './masters.js';
import allHandler from './all.js';

let CURRENT_ORIGIN = 'https://skgl.pages.dev';
const CSP_HEADER_VALUE = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.zhimg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': CURRENT_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Content-Security-Policy': CSP_HEADER_VALUE, 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0', 'Pragma': 'no-cache', 'Expires': '0', ...extraHeaders },
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

// ========== JWT 工具 ==========
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

// ========== PBKDF2 密码工具 ==========
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
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return bytesToHex(new Uint8Array(hash)) === parts[1];
}

async function sha256(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

function getJWTSecret(env) {
  const secret = env && env.JWT_SECRET;
  if (!secret || secret === 'dev-secret-change-in-production' || secret.length < 32) return null;
  return secret;
}

const SUPER_ADMIN_PHONE = '13399330020';
function isAdminRole(role, userId, phone = '') {
  const r = String(role || '').toLowerCase();
  return r === 'admin' || r === '管理员' || r === '1' || String(phone || '') === SUPER_ADMIN_PHONE;
}

function isDisabledValue(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'disabled' || v === '停用' || v === '禁用' || v === '离职';
}

async function requireAdmin(context) {
  if (isAdminRole(context.userRole, context.userId, context.userPhone)) return true;
  const DB = context.env.DB;
  const userId = context.userId;
  const user = await DB.prepare('SELECT id, phone, role FROM users WHERE id = ?1').bind(userId).first().catch(() => null);
  if (!user || !isAdminRole(user.role, userId, user.phone)) return false;
  context.userRole = String(user.phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (user.role || '');
  return true;
}

const PERMISSION_ALIASES = {
  customers: ['customers', 'kehu', 'kehu_info', '客户信息'],
  kehu: ['customers', 'kehu', 'kehu_info', '客户信息'],
  shoukuan: ['shoukuan', 'sk_records', '收款记录'],
  bills: ['bills', 'shoukuan', 'sk_records', '收款记录'],
  tixing: ['tixing', '收款提醒'],
  'payment-plans': ['payment-plans', 'payment_plans', 'ar_remind', '收款提醒'],
  accounts: ['accounts', 'journal', 'balance', '资金日记账', '资金余额表'],
  departments: ['departments', 'dept_sz_summary', '部门收款汇总'],
  prospects: ['prospects', '意向客户'],
  'income-items': ['income-items', 'income_items', 'item_sk_summary', '收款项目'],
  income: ['income', 'income_items', 'item_sk_summary', '收款项目'],
  reports: ['reports', 'baobiao', 'salesperson_sk_detail', 'salesperson_sk_summary', 'balance', 'journal', 'date_summary', 'dept_sz_summary', 'item_sk_summary', 'wl_summary', 'balance_date'],
  trends: ['trends', 'fenxi', 'date_trend', 'dept_trend', 'wl_trend', 'owner_trend'],
  analysis: ['analysis', 'fenxi', 'date_trend', 'dept_trend', 'wl_trend', 'owner_trend'],
  'ar-reports': ['ar-reports', 'wanglai', 'item_ar', 'wl_ar', 'ar_remind', 'ar_flow'],
  dashboard: ['dashboard', 'dash', '首页'],
  stats: ['stats', 'dashboard', 'dash', '首页'],
  search: ['search'],
  feedback: ['feedback', 'kefu', '联系客服'],
  'change-password': ['change-password', 'change_pwd', '密码更改'],
  'contract-expiry': ['contract-expiry', 'contract_expiry', '合同到期'],
  'item-mgr': ['item-mgr', 'wupin', '物品管理'],
  'wl-info': ['wl-info', 'wupin', '物品管理', 'customers', 'kehu', '客户信息'],
};

function permissionKeysForModule(module) {
  return Array.from(new Set([module, ...(PERMISSION_ALIASES[module] || [])].map(v => String(v || '').trim()).filter(Boolean)));
}

async function hasModulePermission(context) {
  const DB = context.rawEnv?.DB || context.env.DB;
  const module = context.module;
  const userId = context.userId;
  if (!module || !userId) return false;
  if (await requireAdmin(context)) return true;

  const keys = permissionKeysForModule(module);
  const tenantId = String(context.tenantId || '');
  const placeholders = keys.map((_, i) => `?${i + 3}`).join(',');

  const directCount = await DB.prepare("SELECT COUNT(*) as cnt FROM user_permissions WHERE use_id = ?1 AND (user_id = ?2 OR user_id IS NULL OR user_id = '')")
    .bind(parseInt(userId), tenantId).first().catch(() => ({ cnt: 0 }));
  if (Number(directCount?.cnt || 0) > 0) {
    const row = await DB.prepare(`SELECT 1 as ok FROM user_permissions WHERE use_id = ?1 AND (user_id = ?2 OR user_id IS NULL OR user_id = '') AND module IN (${placeholders}) LIMIT 1`)
      .bind(parseInt(userId), tenantId, ...keys).first().catch(() => null);
    return !!row;
  }

  const user = await DB.prepare('SELECT id, phone FROM users WHERE id = ?1').bind(userId).first().catch(() => null);
  const operatorKeys = [String(userId), String(user?.phone || '')].filter(Boolean);
  const legacyPlaceholders = keys.map((_, i) => `?${i + 2}`).join(',');
  for (const opKey of operatorKeys) {
    const op = await DB.prepare('SELECT use_id FROM t_use WHERE use_id = ?1 LIMIT 1').bind(opKey).first().catch(() => null);
    if (!op) continue;
    const opCount = await DB.prepare('SELECT COUNT(*) as cnt FROM t_function_user WHERE use_id = ?1')
      .bind(op.use_id).first().catch(() => ({ cnt: 0 }));
    if (Number(opCount?.cnt || 0) === 0) continue;
    const row = await DB.prepare(`SELECT 1 as ok FROM t_function_user WHERE use_id = ?1 AND gn_no IN (${legacyPlaceholders}) LIMIT 1`)
      .bind(op.use_id, ...keys).first().catch(() => null);
    return !!row;
  }

  return true;
}

async function hasActionPermission(context, action) {
  if (await requireAdmin(context)) return true;
  const DB = context.rawEnv?.DB || context.env.DB;
  const userId = context.userId;
  const tenantId = String(context.tenantId || '');
  const module = context.module;
  if (!module || !userId || !action) return false;
  const count = await DB.prepare("SELECT COUNT(*) as cnt FROM user_permissions WHERE use_id = ?1 AND (user_id = ?2 OR user_id IS NULL OR user_id = '')")
    .bind(parseInt(userId), tenantId).first().catch(() => ({ cnt: 0 }));
  if (Number(count?.cnt || 0) === 0) return true;
  const keys = permissionKeysForModule(module).flatMap(k => [`${k}:${action}`, `${k}.${action}`]);
  keys.push(`all:${action}`, `all.${action}`, action);
  const placeholders = keys.map((_, i) => `?${i + 3}`).join(',');
  const row = await DB.prepare(`SELECT 1 as ok FROM user_permissions WHERE use_id = ?1 AND (user_id = ?2 OR user_id IS NULL OR user_id = '') AND module IN (${placeholders}) LIMIT 1`)
    .bind(parseInt(userId), tenantId, ...keys).first().catch(() => null);
  return !!row;
}

// ========== 频率限制 ==========
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry) {
    entry = { tokens: 59, lastRefill: now };
    rateLimitMap.set(ip, entry);
    return true;
  }
  const elapsed = (now - entry.lastRefill) / 1000;
  entry.tokens = Math.min(60, entry.tokens + elapsed * 1);
  entry.lastRefill = now;
  if (entry.tokens < 1) return false;
  entry.tokens -= 1;
  if (rateLimitMap.size > 10000) {
    for (const [k, v] of rateLimitMap) {
      if (now - v.lastRefill > 300000) rateLimitMap.delete(k);
    }
  }
  return true;
}

// ========== LIKE 转义 ==========
function escapeLike(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}

// ========== CSRF Token 独立端点 ==========
async function handleCsrfToken(context) {
  const { request, env } = context;
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const csrf = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  return json({ success: true, csrfToken: csrf }, 200, {
    'Set-Cookie': `skgl_csrf=${csrf}; Secure; SameSite=Strict; Path=/; Max-Age=604800`
  });
}

function normalizeResetPhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function normalizeIdCard(idCard) {
  return String(idCard || '').trim().toUpperCase().replace(/\s+/g, '');
}

function validResetPhone(phone) {
  return /^1\d{10}$/.test(phone);
}

function validIdCard(idCard) {
  return /^(\d{15}|\d{17}[\dX])$/.test(idCard);
}

function idCardHashSecret(env) {
  return env?.DATA_ENCRYPTION_KEY || env?.SKGL_DATA_KEY || env?.JWT_SECRET || 'skgl-id-card-dev-secret';
}

async function hashIdCardValue(env, phone, idCard) {
  return sha256(`${idCardHashSecret(env)}:id-card:${normalizeResetPhone(phone)}:${normalizeIdCard(idCard)}`);
}

async function ensureResetUsersSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    phone TEXT,
    id_card TEXT,
    id_card_hash TEXT,
    password_hash TEXT,
    salt TEXT,
    role TEXT,
    wx_openid TEXT,
    wx_unionid TEXT,
    created_at TEXT,
    name TEXT,
    disabled TEXT
  )`).run().catch(() => {});
  try { await DB.prepare('ALTER TABLE users ADD COLUMN id_card TEXT').run(); } catch (_) {}
  try { await DB.prepare('ALTER TABLE users ADD COLUMN id_card_hash TEXT').run(); } catch (_) {}
  try { await DB.prepare('ALTER TABLE users ADD COLUMN must_change_password TEXT').run(); } catch (_) {}
}

async function findUserByResetIdentity(DB, env, phone, idCard) {
  const normalized = normalizeIdCard(idCard);
  const idCardHash = await hashIdCardValue(env, phone, normalized);
  const user = await DB.prepare('SELECT id, id_card, id_card_hash FROM users WHERE phone = ?1')
    .bind(phone).first().catch(() => null);
  if (!user) return null;
  if (String(user.id_card_hash || '') === idCardHash) return user;
  if (normalizeIdCard(user.id_card || '') === normalized) {
    await DB.prepare('UPDATE users SET id_card_hash = ?1, id_card = ?2 WHERE id = ?3')
      .bind(idCardHash, '', user.id).run().catch(() => {});
    return user;
  }
  return null;
}

const BACKUP_TABLES = [
  'users', 'tenants', 'tenant_members', 'customers', 'bills', 'shoukuan', 'payment_plans',
  'tixing', 'audit_logs', 'app_settings',
  'wl_info', 'wl_sz', 'wl_sz_plan', 'kh', 'dept_info', 't_use',
  'user_permissions', 'income_items', 'income_categories',
  'customer_types', 'item_manger', 'reminders'
];
const ACCOUNT_BACKUP_TABLES = new Set(['users', 'tenants', 'tenant_members']);

const TENANT_TABLES = new Set([
  'accounts', 'departments', 'prospects', 'customers', 'bills', 'shoukuan',
  'shoukuan_periods', 'payment_plans', 'tixing', 'app_settings', 'data_store', 't_sys',
  'wl_info', 'wl_sz', 'wl_sz_plan', 'kh', 'dept_info', 't_use',
  't_function', 't_function_user', 'user_permissions',
  'income_items', 'income_categories', 'customer_types', 'item_manger',
  'reminders', 'audit_logs', 'feedback_messages'
]);

const TENANT_ID_TABLES = new Set(['users', 'audit_logs', 'feedback_messages']);
const ENCRYPTION_MARKER = 'enc:v1:';
const SENSITIVE_COLUMNS = new Set([
  'company', 'name', 'phone', 'mobile', 'address', 'contact', 'manager', 'remark',
  'tax_no', 'extra_data', 'customer_name', 'kehu_name', 'method', 'salesperson',
  'dept', 'notes', 'notes1', 'notes2', 'invoice_no', 'item_name', 'content',
  'source', 'intent', 'last_follow', 'setting_value', 'value', 'sys_value',
  'sys_value2', 'sys_other1', 'sys_other2', 'detail', 'ip', 'email', 'message',
  'reply', 'metadata', 'deleted_by', 'data'
]);
const NEVER_ENCRYPT_COLUMNS = new Set([
  'id', 'rowid', 'user_id', 'tenant_id', 'use_id', 'module', 'role', 'disabled',
  'password_hash', 'salt', 'id_card', 'created_at', 'updated_at', 'deleted_at',
  'date', 'start_date', 'end_date', 'biz_date', 'shoukuan_date', 'period_start',
  'period_end', 'remind_date', 'invoice_date', 'next_due', 'status', 'flag',
  'type', 'code', 'customer_code', 'account_code', 'item_code', 'category_code',
  'type_code', 'parent_id', 'parent_code', 'level', 'sort', 'sort_order',
  'amount', 'balance', 'total', 'count', 'cnt', 'page', 'limit'
]);

function sqlIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

function normalizeColumnName(name) {
  return String(name || '').trim().replace(/^["'`]|["'`]$/g, '').split('.').pop();
}

function shouldEncryptColumn(column) {
  const col = normalizeColumnName(column);
  if (!col || NEVER_ENCRYPT_COLUMNS.has(col)) return false;
  if (SENSITIVE_COLUMNS.has(col)) return true;
  return /(name|phone|mobile|address|contact|remark|note|content|message|detail|value|email|tax|invoice|data)$/i.test(col);
}

function isEncryptedValue(value) {
  return typeof value === 'string' && value.startsWith(ENCRYPTION_MARKER);
}

function base64EncodeBytes(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64DecodeBytes(text) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}

async function deriveDataEncryptionKey(env, tenantId) {
  const secret = env?.DATA_ENCRYPTION_KEY || env?.SKGL_DATA_KEY || env?.JWT_SECRET || '';
  if (!secret || secret.length < 32) return null;
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(`skgl-tenant:${tenantId || 'global'}`), info: enc.encode('skgl-data-aes-gcm-v1') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptDbValue(env, tenantId, value) {
  if (value === null || value === undefined || value === '' || isEncryptedValue(value)) return value;
  const key = await deriveDataEncryptionKey(env, tenantId);
  if (!key) return value;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(String(value));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  return `${ENCRYPTION_MARKER}${base64EncodeBytes(iv)}:${base64EncodeBytes(cipher)}`;
}

async function decryptDbValue(env, tenantId, value) {
  if (!isEncryptedValue(value)) return value;
  const key = await deriveDataEncryptionKey(env, tenantId);
  if (!key) return value;
  try {
    const payload = value.slice(ENCRYPTION_MARKER.length);
    const [ivText, cipherText] = payload.split(':');
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64DecodeBytes(ivText) }, key, base64DecodeBytes(cipherText));
    return new TextDecoder().decode(plain);
  } catch (_) {
    return value;
  }
}

function splitSqlList(text) {
  const out = [];
  let depth = 0, quote = '', start = 0;
  for (let i = 0; i < String(text).length; i++) {
    const ch = text[i], next = text[i + 1];
    if (quote) {
      if (ch === quote) {
        if (next === quote) i++;
        else quote = '';
      }
      continue;
    }
    if (ch === '\'' || ch === '"' || ch === '`') { quote = ch; continue; }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(String(text).slice(start).trim());
  return out;
}

function parameterIndexes(expr) {
  const matches = [...String(expr).matchAll(/\?(\d+)/g)];
  return matches.map(m => Number(m[1])).filter(Boolean);
}

function tenantColumnForTable(table) {
  return TENANT_ID_TABLES.has(table) ? 'tenant_id' : 'user_id';
}

function normalizeTenantTableName(name) {
  return String(name || '').replace(/^["'`]|["'`]$/g, '');
}

function maxPlaceholderIndex(sql) {
  let max = 0;
  String(sql).replace(/\?(\d+)/g, (_, n) => {
    max = Math.max(max, Number(n) || 0);
    return _;
  });
  return max;
}

function splitSqlTail(sql) {
  const match = String(sql).match(/\s+(ORDER\s+BY|GROUP\s+BY|LIMIT|OFFSET|RETURNING)\b/i);
  if (!match) return { head: sql, tail: '' };
  return { head: sql.slice(0, match.index), tail: sql.slice(match.index) };
}

function findMatchingParen(sql, openIndex) {
  let depth = 0;
  let quote = '';
  for (let i = openIndex; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (quote) {
      if (ch === quote) {
        if (next === quote) {
          i++;
        } else {
          quote = '';
        }
      }
      continue;
    }
    if (ch === '\'' || ch === '"' || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth++;
    if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseInsertStatement(sql) {
  const start = String(sql).match(/^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))\s*\(/i);
  if (!start) return null;
  const colsOpen = start[0].length - 1;
  const colsClose = findMatchingParen(sql, colsOpen);
  if (colsClose < 0) return null;
  const afterCols = sql.slice(colsClose + 1);
  const valuesMatch = afterCols.match(/^\s*VALUES\s*\(/i);
  if (!valuesMatch) return null;
  const valuesOpen = colsClose + 1 + valuesMatch[0].length - 1;
  const valuesClose = findMatchingParen(sql, valuesOpen);
  if (valuesClose < 0) return null;
  return {
    table: normalizeTenantTableName(start[1] || start[2]),
    colsOpen,
    colsClose,
    valuesOpen,
    valuesClose,
    columns: sql.slice(colsOpen + 1, colsClose),
  };
}

function addTenantCondition(sql, table, tenantId) {
  const tablePattern = `(?:"${table}"|${table})`;
  const fromRe = new RegExp(`\\bFROM\\s+(${tablePattern})(?:\\s+(?:AS\\s+)?([A-Za-z_][A-Za-z0-9_]*))?`, 'i');
  const fromMatch = String(sql).match(fromRe);
  const firstWord = String(sql).trim().split(/\s+/, 1)[0].toUpperCase();
  let qualifier = sqlIdent(table);
  if (fromMatch) {
    const alias = fromMatch[2] && !/^(WHERE|LEFT|RIGHT|INNER|FULL|CROSS|JOIN|ORDER|GROUP|LIMIT|OFFSET)$/i.test(fromMatch[2]) ? fromMatch[2] : '';
    qualifier = alias ? sqlIdent(alias) : sqlIdent(table);
  }
  if (firstWord === 'UPDATE' || firstWord === 'DELETE') qualifier = sqlIdent(table);
  const col = `${qualifier}.${sqlIdent(tenantColumnForTable(table))}`;
  const idx = maxPlaceholderIndex(sql) + 1;
  const legacyAdminVisible = tenantId === '1' && table !== 'users';
  const condition = legacyAdminVisible
    ? `(${col} = ?${idx} OR ${col} IS NULL OR ${col} = '')`
    : `${col} = ?${idx}`;
  const { head, tail } = splitSqlTail(sql);
  const whereMatch = head.match(/\bWHERE\b/i);
  const next = whereMatch
    ? `${head.slice(0, whereMatch.index + whereMatch[0].length)} (${head.slice(whereMatch.index + whereMatch[0].length).trim()}) AND ${condition}${tail}`
    : `${head} WHERE ${condition}${tail}`;
  return { sql: next, extraParams: [tenantId] };
}

function transformTenantSql(sql, tenantId) {
  const raw = String(sql);
  const verb = raw.trim().split(/\s+/, 1)[0].toUpperCase();
  if (!tenantId || verb === 'PRAGMA' || verb === 'ALTER' || /\bsqlite_master\b/i.test(raw)) {
    return { sql: raw, extraParams: [] };
  }

  const create = raw.match(/^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))\s*\(/i);
  if (create) {
    const table = normalizeTenantTableName(create[1] || create[2]);
    if ((TENANT_TABLES.has(table) || TENANT_ID_TABLES.has(table)) && !new RegExp(`\\b${tenantColumnForTable(table)}\\b`, 'i').test(raw)) {
      const insertAt = create[0].length;
      return { sql: raw.slice(0, insertAt) + `${sqlIdent(tenantColumnForTable(table))} TEXT, ` + raw.slice(insertAt), extraParams: [] };
    }
    return { sql: raw, extraParams: [] };
  }

  const insert = parseInsertStatement(raw);
  if (insert) {
    const table = insert.table;
    if (TENANT_TABLES.has(table) || TENANT_ID_TABLES.has(table)) {
      const col = tenantColumnForTable(table);
      if (!new RegExp(`(^|,)\\s*"?${col}"?\\s*(,|$)`, 'i').test(insert.columns)) {
        const idx = maxPlaceholderIndex(raw) + 1;
        const next =
          raw.slice(0, insert.colsClose) + `, ${sqlIdent(col)}` +
          raw.slice(insert.colsClose, insert.valuesClose) + `, ?${idx}` +
          raw.slice(insert.valuesClose);
        return { sql: next, extraParams: [tenantId] };
      }
    }
    return { sql: raw, extraParams: [] };
  }

  const tableMatches = [];
  const tableRe = /\b(?:FROM|UPDATE|DELETE\s+FROM)\s+(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))/ig;
  let match;
  while ((match = tableRe.exec(raw))) {
    const table = normalizeTenantTableName(match[1] || match[2]);
    if ((TENANT_TABLES.has(table) || TENANT_ID_TABLES.has(table)) && !tableMatches.includes(table)) tableMatches.push(table);
  }
  if (!tableMatches.length) return { sql: raw, extraParams: [] };

  let transformed = { sql: raw, extraParams: [] };
  for (const table of tableMatches.slice(0, 1)) {
    transformed = addTenantCondition(transformed.sql, table, tenantId);
  }
  return transformed;
}

function encryptedParameterIndexes(sql) {
  const raw = String(sql);
  const indexes = new Set();
  const insert = parseInsertStatement(raw);
  if (insert) {
    const columns = splitSqlList(insert.columns).map(normalizeColumnName);
    const values = splitSqlList(raw.slice(insert.valuesOpen + 1, insert.valuesClose));
    columns.forEach((column, i) => {
      if (!shouldEncryptColumn(column)) return;
      for (const idx of parameterIndexes(values[i] || '')) indexes.add(idx);
    });
    return indexes;
  }

  const update = raw.match(/^\s*UPDATE\s+(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))\s+SET\s+/i);
  if (update) {
    const tailStart = update[0].length;
    const tail = raw.slice(tailStart);
    const whereMatch = tail.match(/\bWHERE\b/i);
    const setPart = whereMatch ? tail.slice(0, whereMatch.index) : tail;
    for (const assignment of splitSqlList(setPart)) {
      const eq = assignment.indexOf('=');
      if (eq < 0) continue;
      const column = normalizeColumnName(assignment.slice(0, eq));
      if (!shouldEncryptColumn(column)) continue;
      for (const idx of parameterIndexes(assignment.slice(eq + 1))) indexes.add(idx);
    }
  }
  return indexes;
}

async function encryptBoundParams(env, tenantId, sql, params) {
  const indexes = encryptedParameterIndexes(sql);
  if (!indexes.size) return params;
  const next = [...params];
  for (const idx of indexes) {
    const arrIdx = idx - 1;
    if (arrIdx >= 0 && arrIdx < next.length) {
      next[arrIdx] = await encryptDbValue(env, tenantId, next[arrIdx]);
    }
  }
  return next;
}

function decryptCandidateColumns(row) {
  if (!row || typeof row !== 'object') return [];
  return Object.keys(row).filter(shouldEncryptColumn);
}

async function decryptRow(env, tenantId, row) {
  if (!row || typeof row !== 'object') return row;
  const next = { ...row };
  for (const column of decryptCandidateColumns(next)) {
    next[column] = await decryptDbValue(env, tenantId, next[column]);
  }
  return next;
}

async function decryptRows(env, tenantId, rows) {
  const list = rows?.results || [];
  const decrypted = [];
  for (const row of list) decrypted.push(await decryptRow(env, tenantId, row));
  return { ...rows, results: decrypted };
}

class TenantStatement {
  constructor(DB, env, tenantId, sql, extraParams) {
    this.DB = DB;
    this.env = env;
    this.tenantId = tenantId;
    this.sql = sql;
    this.extraParams = extraParams || [];
    this.params = [];
    this.hasBind = false;
  }
  bind(...params) {
    this.params = params;
    this.hasBind = true;
    return this;
  }
  async boundStatement() {
    const params = this.hasBind ? [...this.params, ...this.extraParams] : [...this.extraParams];
    const encrypted = await encryptBoundParams(this.env, this.tenantId, this.sql, params);
    const stmt = this.DB.prepare(this.sql);
    return encrypted.length ? stmt.bind(...encrypted) : stmt;
  }
  async all() {
    const stmt = await this.boundStatement();
    return decryptRows(this.env, this.tenantId, await stmt.all());
  }
  async first() {
    const stmt = await this.boundStatement();
    return decryptRow(this.env, this.tenantId, await stmt.first());
  }
  async run() {
    const stmt = await this.boundStatement();
    return stmt.run();
  }
}

class TenantDatabase {
  constructor(DB, tenantId, env) {
    this.DB = DB;
    this.tenantId = String(tenantId || '');
    this.env = env || {};
  }
  prepare(sql) {
    const transformed = transformTenantSql(sql, this.tenantId);
    return new TenantStatement(this.DB, this.env, this.tenantId, transformed.sql, transformed.extraParams);
  }
  async batch(statements) {
    const results = [];
    for (const stmt of statements) results.push(await stmt.run());
    return results;
  }
}

let tenantColumnsReadyAt = 0;
async function ensureTenantColumns(DB) {
  const now = Date.now();
  if (tenantColumnsReadyAt && now - tenantColumnsReadyAt < 300000) return;
  for (const table of [...TENANT_TABLES]) {
    try { await DB.prepare(`ALTER TABLE ${sqlIdent(table)} ADD COLUMN ${sqlIdent(tenantColumnForTable(table))} TEXT`).run(); } catch (_) {}
  }
  try { await DB.prepare('ALTER TABLE users ADD COLUMN tenant_id TEXT').run(); } catch (_) {}
  await backfillSingleTenantLegacyRows(DB).catch(() => {});
  tenantColumnsReadyAt = now;
}

async function backfillSingleTenantLegacyRows(DB) {
  const tenants = await DB.prepare("SELECT DISTINCT COALESCE(NULLIF(tenant_id,''), CAST(id AS TEXT)) AS tenant_id FROM users WHERE COALESCE(disabled,'') NOT IN ('1','true','disabled','停用','禁用') LIMIT 2")
    .all()
    .catch(() => ({ results: [] }));
  const ids = (tenants.results || []).map(r => String(r.tenant_id || '').trim()).filter(Boolean);
  if (ids.length !== 1) return;
  const tenantId = ids[0];
  for (const table of TENANT_TABLES) {
    const column = tenantColumnForTable(table);
    try {
      await DB.prepare(`UPDATE ${sqlIdent(table)} SET ${sqlIdent(column)} = ?1 WHERE ${sqlIdent(column)} IS NULL OR ${sqlIdent(column)} = ''`)
        .bind(tenantId)
        .run();
    } catch (_) {}
  }
}

async function isPlatformAdmin(context, env) {
  const user = await env.DB.prepare('SELECT phone FROM users WHERE id = ?1').bind(context.userId).first().catch(() => null);
  return String(user?.phone || '') === '13399330020';
}

async function ensurePlatformTenantSchema(DB) {
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
  for (const col of tenantCols) { try { await DB.prepare(`ALTER TABLE tenants ADD COLUMN ${col}`).run(); } catch (_) {} }
  const memberCols = ['tenant_id TEXT','user_id INTEGER','phone TEXT','name TEXT','role TEXT','disabled TEXT','notes TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of memberCols) { try { await DB.prepare(`ALTER TABLE tenant_members ADD COLUMN ${col}`).run(); } catch (_) {} }

  const owners = await DB.prepare(`SELECT id, phone, tenant_id, role, name, disabled, created_at
    FROM users
    WHERE COALESCE(phone,'') <> ''
      AND COALESCE(tenant_id,'') <> ''
      AND LOWER(COALESCE(role,'')) IN ('admin','管理员','1')
    LIMIT 1000`).all().catch(() => ({ results: [] }));
  for (const u of owners.results || []) {
    const tenantId = String(u.tenant_id || '').trim();
    if (!tenantId) continue;
    const n = u.created_at || new Date().toISOString();
    await DB.prepare('INSERT OR IGNORE INTO tenants (id, name, owner_user_id, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(tenantId, u.name || `账套${tenantId}`, String(u.id), isDisabledValue(u.disabled) ? 'disabled' : 'active', n, n).run().catch(() => {});
    await DB.prepare('UPDATE tenants SET owner_user_id = COALESCE(NULLIF(owner_user_id, ""), ?2), status = CASE WHEN status IS NULL OR status = "" THEN ?3 ELSE status END WHERE id = ?1')
      .bind(tenantId, String(u.id), isDisabledValue(u.disabled) ? 'disabled' : 'active').run().catch(() => {});
    const exists = await DB.prepare('SELECT id FROM tenant_members WHERE tenant_id = ?1 AND user_id = ?2')
      .bind(tenantId, u.id).first().catch(() => null);
    if (!exists) {
      await DB.prepare('INSERT INTO tenant_members (tenant_id, user_id, phone, name, role, disabled, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
        .bind(tenantId, u.id, u.phone || '', u.name || '', 'admin', u.disabled || 'false', '', n, n).run().catch(() => {});
    }
  }
}

async function tableCountByTenant(DB, table, tenantId, column = 'user_id') {
  try {
    const row = await DB.prepare(`SELECT COUNT(*) AS total FROM ${sqlIdent(table)} WHERE ${sqlIdent(column)} = ?1`)
      .bind(String(tenantId)).first();
    return Number(row?.total || 0);
  } catch (_) {
    return 0;
  }
}

async function tableTotal(DB, table) {
  try {
    const row = await DB.prepare(`SELECT COUNT(*) AS total FROM ${sqlIdent(table)}`).first();
    return Number(row?.total || 0);
  } catch (_) {
    return 0;
  }
}

async function platformTenantStats(DB, tenantId) {
  const businessTables = [
    ['customers', '客户'],
    ['shoukuan', '收款'],
    ['payment_plans', '收款计划'],
    ['tixing', '提醒'],
    ['app_settings', '设置'],
    ['data_store', '同步数据'],
    ['accounts', '资金账户'],
    ['departments', '部门'],
    ['prospects', '意向客户'],
    ['income_items', '收款项目'],
    ['customer_types', '客户类型'],
  ];
  const detail = [];
  for (const [table, label] of businessTables) {
    detail.push({ table, label, count: await tableCountByTenant(DB, table, tenantId, 'user_id') });
  }
  detail.push({ table: 'tenant_members', label: '租户用户', count: await tableCountByTenant(DB, 'tenant_members', tenantId, 'tenant_id') });
  detail.push({ table: 'feedback_messages', label: '反馈', count: await tableCountByTenant(DB, 'feedback_messages', tenantId, 'tenant_id') });
  detail.push({ table: 'audit_logs', label: '审计日志', count: await tableCountByTenant(DB, 'audit_logs', tenantId, 'tenant_id') });
  return detail;
}

async function deleteTenantRows(DB, table, tenantId, column = 'user_id') {
  try {
    const before = await tableCountByTenant(DB, table, tenantId, column);
    if (before > 0) {
      await DB.prepare(`DELETE FROM ${sqlIdent(table)} WHERE ${sqlIdent(column)} = ?1`).bind(String(tenantId)).run();
    }
    return { table, deleted: before };
  } catch (_) {
    return { table, deleted: 0, skipped: true };
  }
}

async function ensurePlatformSettingsTable(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS t_sys (
    sys_id TEXT PRIMARY KEY,
    sys_value TEXT,
    sys_value2 TEXT,
    sys_other1 TEXT,
    sys_other2 TEXT,
    created_at TEXT,
    updated_at TEXT
  )`).run().catch(() => {});
}

const PLATFORM_BUSINESS_VIEWS = {
  customers: {
    label: '客户资料',
    table: 'customers',
    columns: ['id','company','name','code','type','phone','mobile','address','contact','manager','remark','tax_no','start_date','extra_data','created_at','updated_at'],
    order: 'created_at DESC',
    format: row => {
      const r = toKehuFormat(row) || {};
      return {
        id: r.id || row.id || '',
        name: r.name || row.company || '',
        code: r.code || row.code || '',
        type: r.type || row.type || '',
        phone: r.phone || '',
        mobile: r.mobile || '',
        contact: r.contact || '',
        address: r.address || '',
        salesperson: r.salesperson || '',
        notes: r.notes || '',
        tax_no: r.tax_no || '',
        start_date: r.yw_beg || row.start_date || '',
      };
    },
  },
  payments: {
    label: '收款记录',
    table: 'shoukuan',
    columns: ['id','sheet_no','kehu_id','customer_code','kehu_name','amount','method','shoukuan_date','biz_date','period_start','period_end','salesperson','account_code','item_code','item_name','dept','notes','notes2','invoice_no','invoice_date','created_at','updated_at'],
    order: 'shoukuan_date DESC, created_at DESC',
    format: row => ({
      id: row.id || '',
      sheet_no: row.sheet_no || '',
      customer: row.kehu_name || '',
      amount: row.amount || '',
      method: row.method || '',
      date: row.shoukuan_date || row.biz_date || '',
      period: [row.period_start || '', row.period_end || ''].filter(Boolean).join(' ~ '),
      salesperson: row.salesperson || '',
      item: row.item_name || row.item_code || '',
      dept: row.dept || '',
      notes: row.notes || row.notes2 || '',
      invoice_no: row.invoice_no || '',
    }),
  },
  plans: {
    label: '收款计划',
    table: 'payment_plans',
    columns: ['id','kehu_id','kehu_name','item_name','start_month','end_month','interval_months','amount_per','notes','next_due','customer_code','created_at','updated_at'],
    order: 'next_due ASC, created_at DESC',
    format: row => ({
      id: row.id || '',
      customer: row.kehu_name || '',
      item: row.item_name || '',
      start_month: row.start_month || '',
      end_month: row.end_month || '',
      interval_months: row.interval_months || '',
      amount_per: row.amount_per || '',
      next_due: row.next_due || '',
      notes: row.notes || '',
    }),
  },
  reminders: {
    label: '提醒记录',
    table: 'tixing',
    columns: ['id','kehu_id','kehu_name','remind_date','content','status','customer_code','created_at','updated_at'],
    order: 'remind_date ASC, created_at DESC',
    format: row => ({
      id: row.id || '',
      customer: row.kehu_name || '',
      remind_date: row.remind_date || '',
      content: row.content || '',
      status: row.status || '',
      created_at: row.created_at || '',
    }),
  },
  prospects: {
    label: '意向客户',
    table: 'prospects',
    columns: ['id','name','phone','contact','source','intent','last_follow','remark','created_at','updated_at'],
    order: 'created_at DESC',
    format: row => ({
      id: row.id || '',
      name: row.name || '',
      phone: row.phone || '',
      contact: row.contact || '',
      source: row.source || '',
      intent: row.intent || '',
      last_follow: row.last_follow || '',
      remark: row.remark || '',
    }),
  },
};

async function platformBusinessData(DB, env, tenantId, type, limit) {
  const view = PLATFORM_BUSINESS_VIEWS[type] || PLATFORM_BUSINESS_VIEWS.customers;
  const safeLimit = Math.min(200, Math.max(1, Number(limit || 50) || 50));
  const tenantColumn = tenantColumnForTable(view.table);
  const selectList = view.columns.map(sqlIdent).join(', ');
  const rows = await DB.prepare(`SELECT ${selectList} FROM ${sqlIdent(view.table)} WHERE ${sqlIdent(tenantColumn)} = ?1 ORDER BY ${view.order} LIMIT ?2`)
    .bind(String(tenantId), safeLimit)
    .all()
    .catch(() => ({ results: [] }));
  const decrypted = await decryptRows(env, tenantId, rows);
  return {
    type,
    label: view.label,
    limit: safeLimit,
    columns: Object.keys(view.format({})),
    rows: (decrypted.results || []).map(row => view.format(row)),
  };
}

async function handlePlatformAdmin(context) {
  const rawEnv = context.rawEnv || context.env;
  const DB = rawEnv.DB;
  if (!await isPlatformAdmin(context, rawEnv)) return error('只有平台管理员可以操作该功能', 403);

  await ensurePlatformTenantSchema(DB);
  await ensureTenantColumns(DB);
  const method = context.request.method;
  const action = context._segments?.[1] || 'overview';
  const targetId = context._segments?.[2] || '';

  if (method === 'GET' && action === 'overview') {
    const users = await tableTotal(DB, 'users');
    const feedback = await tableTotal(DB, 'feedback_messages');
    const audit = await tableTotal(DB, 'audit_logs');
    const customers = await tableTotal(DB, 'customers');
    const payments = await tableTotal(DB, 'shoukuan');
    const disabledRow = await DB.prepare("SELECT COUNT(*) AS total FROM users WHERE COALESCE(disabled,'') IN ('1','true','disabled','停用','禁用')")
      .first().catch(() => ({ total: 0 }));
    return json({ success: true, data: { users, feedback, audit, customers, payments, disabledUsers: Number(disabledRow?.total || 0) } });
  }

  if (method === 'GET' && action === 'tenants') {
    if (targetId) {
      const tenant = await DB.prepare(`SELECT t.id AS tenant_id, t.name AS tenant_name, t.status AS tenant_status, t.owner_user_id,
          t.created_at AS tenant_created_at, u.id AS owner_id, u.phone, u.role, u.disabled, u.created_at, u.name
        FROM tenants t
        LEFT JOIN users u ON CAST(u.id AS TEXT) = t.owner_user_id
        WHERE t.owner_user_id = ?1 OR t.id = ?1
        LIMIT 1`)
        .bind(targetId).first().catch(() => null);
      if (!tenant) return error('账套不存在', 404);
      const tenantId = String(tenant.tenant_id || '');
      if (context._segments?.[3] === 'business') {
        const type = String(context.query?.type || 'customers');
        const data = await platformBusinessData(DB, rawEnv, tenantId, type, context.query?.limit);
        await auditLog(DB, context.userId, 'platform_decrypt_business_data', data.type, `tenant:${tenantId} rows:${data.rows.length}`, context._clientIp).catch(() => {});
        return json({ success: true, data });
      }
      const [stats, tenantUsers, audits, logins, feedback] = await Promise.all([
        platformTenantStats(DB, tenantId),
        DB.prepare(`SELECT u.id, COALESCE(m.phone, u.phone) AS phone, m.role, m.disabled, m.created_at, COALESCE(m.name, u.name) AS name
          FROM tenant_members m
          LEFT JOIN users u ON u.id = m.user_id
          WHERE m.tenant_id = ?1
          ORDER BY m.id ASC LIMIT 100`).bind(tenantId).all().catch(() => ({ results: [] })),
        DB.prepare('SELECT id, user_id, phone, action, target, ip, created_at FROM audit_logs WHERE tenant_id = ?1 OR user_id IN (SELECT CAST(user_id AS TEXT) FROM tenant_members WHERE tenant_id = ?1) ORDER BY created_at DESC LIMIT 30').bind(tenantId).all().catch(() => ({ results: [] })),
        DB.prepare("SELECT ip, COUNT(*) AS total, MAX(created_at) AS last_at FROM audit_logs WHERE (tenant_id = ?1 OR user_id IN (SELECT CAST(user_id AS TEXT) FROM tenant_members WHERE tenant_id = ?1)) AND action IN ('login_success','login_fail') GROUP BY ip ORDER BY total DESC LIMIT 20").bind(tenantId).all().catch(() => ({ results: [] })),
        DB.prepare('SELECT id, user_id, phone, type, email_sent, email_error, created_at FROM feedback_messages WHERE tenant_id = ?1 ORDER BY created_at DESC LIMIT 20').bind(tenantId).all().catch(() => ({ results: [] })),
      ]);
      const disabled = isDisabledValue(tenant.disabled) || isDisabledValue(tenant.tenant_status) || String(tenant.tenant_status || '') === 'deleted';
      return json({
        success: true,
        data: {
          user: { id: tenant.owner_id || tenantId, phone: tenant.phone || '', tenantId, tenantName: tenant.tenant_name || '', role: tenant.role || '', disabled, createdAt: tenant.tenant_created_at || tenant.created_at || '', name: tenant.name || '' },
          stats,
          tenantUsers: tenantUsers.results || [],
          audits: audits.results || [],
          logins: logins.results || [],
          feedback: feedback.results || [],
        }
      });
    }
    const search = String(context.query?.search || '').trim();
    let rows;
    if (search) {
      rows = await DB.prepare(`SELECT t.id AS tenant_id, t.name AS tenant_name, t.status AS tenant_status, t.owner_user_id,
          t.created_at AS tenant_created_at, u.id, u.phone, u.role, u.disabled, u.created_at, u.name
        FROM tenants t
        LEFT JOIN users u ON CAST(u.id AS TEXT) = t.owner_user_id
        WHERE t.id = ?2 OR COALESCE(t.name,'') LIKE ?1 OR COALESCE(u.phone,'') LIKE ?1 OR COALESCE(u.name,'') LIKE ?1
        ORDER BY COALESCE(t.created_at, u.created_at) DESC LIMIT 200`).bind(`%${search}%`, search).all().catch(() => ({ results: [] }));
    } else {
      rows = await DB.prepare(`SELECT t.id AS tenant_id, t.name AS tenant_name, t.status AS tenant_status, t.owner_user_id,
          t.created_at AS tenant_created_at, u.id, u.phone, u.role, u.disabled, u.created_at, u.name
        FROM tenants t
        LEFT JOIN users u ON CAST(u.id AS TEXT) = t.owner_user_id
        ORDER BY COALESCE(t.created_at, u.created_at) DESC LIMIT 200`)
        .all().catch(() => ({ results: [] }));
    }
    const list = [];
    for (const u of rows.results || []) {
      const tenantId = String(u.tenant_id || '');
      const [customerCount, paymentCount, userCount, feedbackCount, auditCount] = await Promise.all([
        tableCountByTenant(DB, 'customers', tenantId),
        tableCountByTenant(DB, 'shoukuan', tenantId),
        tableCountByTenant(DB, 'tenant_members', tenantId, 'tenant_id'),
        tableCountByTenant(DB, 'feedback_messages', tenantId, 'tenant_id'),
        tableCountByTenant(DB, 'audit_logs', tenantId, 'tenant_id'),
      ]);
      const disabled = isDisabledValue(u.disabled) || isDisabledValue(u.tenant_status) || String(u.tenant_status || '') === 'deleted';
      list.push({
        id: u.id || u.owner_user_id || tenantId,
        tenantId,
        phone: u.phone || '',
        name: u.tenant_name || u.name || '',
        role: u.role || '',
        disabled,
        createdAt: u.tenant_created_at || u.created_at || '',
        stats: { users: userCount, customers: customerCount, payments: paymentCount, feedback: feedbackCount, audit: auditCount },
      });
    }
    return json({ success: true, list, total: list.length });
  }

  if (method === 'PUT' && action === 'users' && targetId && context._segments?.[3] === 'status') {
    if (String(targetId) === String(context.userId)) return error('不能停用当前平台管理员账号', 400);
    const disabled = context.body?.disabled ? '1' : '';
    await DB.prepare('UPDATE users SET disabled = ?1 WHERE id = ?2').bind(disabled, targetId).run();
    await DB.prepare('UPDATE tenants SET status = ?1, updated_at = ?2 WHERE owner_user_id = ?3 OR id = ?3')
      .bind(disabled ? 'disabled' : 'active', new Date().toISOString(), targetId).run().catch(() => {});
    await auditLog(DB, context.userId, disabled ? 'platform_disable_user' : 'platform_enable_user', 'users', String(targetId), context._clientIp).catch(() => {});
    return json({ success: true, message: disabled ? '账号已停用' : '账号已启用' });
  }

  if (method === 'DELETE' && action === 'tenants' && targetId) {
    if (String(targetId) === String(context.userId)) return error('不能删除当前平台管理员账号', 400);
    const tenant = await DB.prepare(`SELECT t.id AS tenant_id, t.owner_user_id, u.id AS owner_id, u.phone
      FROM tenants t LEFT JOIN users u ON CAST(u.id AS TEXT) = t.owner_user_id
      WHERE t.owner_user_id = ?1 OR t.id = ?1 LIMIT 1`).bind(targetId).first().catch(() => null);
    if (!tenant) return error('账套不存在', 404);
    if (String(tenant.owner_id || '') === String(context.userId)) return error('不能删除当前平台管理员账号', 400);
    const confirmPhone = String(context.body?.confirmPhone || context.body?.phone || '').trim();
    if (!confirmPhone || confirmPhone !== String(tenant.phone || '')) return error('请正确输入该账号手机号确认删除', 400);
    const tenantId = String(tenant.tenant_id || targetId);
    const userTables = [...TENANT_TABLES].filter(t => !TENANT_ID_TABLES.has(t));
    const deleted = [];
    for (const table of userTables) deleted.push(await deleteTenantRows(DB, table, tenantId, 'user_id'));
    for (const table of TENANT_ID_TABLES) {
      if (table === 'users') continue;
      deleted.push(await deleteTenantRows(DB, table, tenantId, 'tenant_id'));
    }
    const tenantUsers = await tableCountByTenant(DB, 'tenant_members', tenantId, 'tenant_id');
    await DB.prepare('DELETE FROM tenant_members WHERE tenant_id = ?1').bind(tenantId).run().catch(() => {});
    await DB.prepare('DELETE FROM tenants WHERE id = ?1').bind(tenantId).run().catch(() => {});
    await DB.prepare('DELETE FROM users WHERE tenant_id = ?1 OR id = ?2').bind(tenantId, tenant.owner_id || targetId).run();
    await auditLog(DB, context.userId, 'platform_delete_tenant', 'users', `tenant:${tenantId} phone:${tenant.phone}`, context._clientIp).catch(() => {});
    return json({ success: true, message: '租户已彻底删除', tenantId, deletedUsers: tenantUsers, deleted });
  }

  if (method === 'GET' && action === 'feedback') {
    const rows = await DB.prepare(`SELECT id, tenant_id, user_id, phone, type, email_sent, email_error, created_at
      FROM feedback_messages ORDER BY created_at DESC LIMIT 100`).all().catch(() => ({ results: [] }));
    return json({ success: true, list: rows.results || [] });
  }

  if (method === 'GET' && action === 'audit-logs') {
    const rows = await DB.prepare(`SELECT id, tenant_id, user_id, phone, action, target, created_at
      FROM audit_logs ORDER BY created_at DESC LIMIT 100`).all().catch(() => ({ results: [] }));
    return json({ success: true, list: rows.results || [] });
  }

  if (method === 'GET' && action === 'security') {
    const [loginIps, loginFails, recent] = await Promise.all([
      DB.prepare("SELECT ip, COUNT(*) AS total, MAX(created_at) AS last_at FROM audit_logs WHERE action = 'login_success' GROUP BY ip ORDER BY total DESC LIMIT 50").all().catch(() => ({ results: [] })),
      DB.prepare("SELECT ip, COUNT(*) AS total, MAX(created_at) AS last_at FROM audit_logs WHERE action = 'login_fail' GROUP BY ip ORDER BY total DESC LIMIT 50").all().catch(() => ({ results: [] })),
      DB.prepare("SELECT id, user_id, phone, action, ip, created_at FROM audit_logs WHERE action IN ('login_success','login_fail') ORDER BY created_at DESC LIMIT 100").all().catch(() => ({ results: [] })),
    ]);
    return json({ success: true, data: { loginIps: loginIps.results || [], loginFails: loginFails.results || [], recent: recent.results || [] } });
  }

  if (action === 'settings') {
    await ensurePlatformSettingsTable(DB);
    if (method === 'GET') {
      const rows = await DB.prepare("SELECT sys_id, sys_value, updated_at FROM t_sys WHERE sys_id IN ('platform_notice','platform_version_note')").all().catch(() => ({ results: [] }));
      const map = {};
      for (const row of rows.results || []) map[row.sys_id] = row.sys_value || '';
      return json({ success: true, data: { notice: map.platform_notice || '', versionNote: map.platform_version_note || '' } });
    }
    if (method === 'PUT') {
      const now = new Date().toISOString();
      const notice = String(context.body?.notice || '').slice(0, 1000);
      const versionNote = String(context.body?.versionNote || '').slice(0, 1000);
      await DB.prepare("INSERT OR REPLACE INTO t_sys (sys_id, sys_value, updated_at) VALUES ('platform_notice', ?1, ?2)").bind(notice, now).run();
      await DB.prepare("INSERT OR REPLACE INTO t_sys (sys_id, sys_value, updated_at) VALUES ('platform_version_note', ?1, ?2)").bind(versionNote, now).run();
      await auditLog(DB, context.userId, 'platform_update_settings', 't_sys', 'platform settings', context._clientIp).catch(() => {});
      return json({ success: true, message: '平台设置已保存' });
    }
  }

  return error('未知的平台管理操作', 404);
}

function quoteIdent(name) {
  if (!BACKUP_TABLES.includes(name)) throw new Error(`不允许的表名: ${name}`);
  return `"${name.replace(/"/g, '""')}"`;
}

function backupTablesForContext(DB) {
  const isTenantScoped = !!(DB && DB.tenantId);
  return isTenantScoped ? BACKUP_TABLES.filter(t => !ACCOUNT_BACKUP_TABLES.has(t)) : [...BACKUP_TABLES];
}

function backupTenantIdForContext(context) {
  return String(context.tenantId || context.env?.DB?.tenantId || '').trim();
}

function backupSigningSecret(env) {
  const secret = env?.DATA_ENCRYPTION_KEY || env?.SKGL_DATA_KEY || env?.JWT_SECRET || '';
  return secret && String(secret).length >= 32 ? String(secret) : '';
}

function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function hmacHex(secret, text) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return bytesToHex(new Uint8Array(sig));
}

function timingSafeEqualHex(a, b) {
  const left = String(a || '');
  const right = String(b || '');
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

async function backupTablesHash(tables) {
  return sha256(canonicalJson(tables || {}));
}

function backupSignaturePayload(meta) {
  const clean = { ...meta };
  delete clean.signature;
  return canonicalJson(clean);
}

async function signBackupMeta(env, meta) {
  const secret = backupSigningSecret(env);
  if (!secret) return '';
  return hmacHex(secret, backupSignaturePayload(meta));
}

async function buildBackupMeta(context, tables, createdAt) {
  const signEnv = context.rawEnv || context.env || {};
  const tenantId = backupTenantIdForContext(context);
  if (!tenantId) throw new Error('请先选择账套后再备份');
  const meta = {
    schema: 'skgl-backup-v3',
    tenant_id: tenantId,
    user_id: String(context.userId || ''),
    created_at: createdAt,
    tables_hash: await backupTablesHash(tables),
    signature_version: 'hmac-sha256-v1',
  };
  meta.signature = await signBackupMeta(signEnv, meta);
  if (!meta.signature) throw new Error('备份签名密钥未配置，请先配置 JWT_SECRET 或 DATA_ENCRYPTION_KEY');
  return meta;
}

async function validateBackupPayload(context, payload, tables) {
  const meta = payload?.meta || payload?.backup_meta || null;
  if (!meta || !meta.signature || !meta.tenant_id || !meta.tables_hash) {
    throw new Error('备份文件缺少账套签名，不能恢复。请使用当前版本重新生成备份');
  }
  const tenantId = backupTenantIdForContext(context);
  if (!tenantId) throw new Error('请先选择账套后再恢复');
  if (String(meta.tenant_id) !== tenantId) {
    throw new Error('备份文件属于其他账套，不能恢复到当前账套');
  }
  const actualHash = await backupTablesHash(tables);
  if (String(meta.tables_hash) !== actualHash) {
    throw new Error('备份文件内容已被修改或损坏，不能恢复');
  }
  const expected = await signBackupMeta(context.rawEnv || context.env || {}, meta);
  if (!expected || !timingSafeEqualHex(expected, meta.signature)) {
    throw new Error('备份文件签名无效，不能恢复');
  }
  return meta;
}

// ========== 审计日志 ==========
async function ensureAuditTable(DB) {
  try {
	    await DB.prepare(`CREATE TABLE IF NOT EXISTS audit_logs (
	      id INTEGER PRIMARY KEY AUTOINCREMENT,
	      tenant_id TEXT,
	      user_id TEXT,
	      phone TEXT,
	      action TEXT,
	      target TEXT,
	      detail TEXT,
	      ip TEXT,
	      created_at TEXT
	    )`).run();
	    try { await DB.prepare('ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT').run(); } catch (_) {}
	  } catch (_) {}
	}
	
	async function auditLog(DB, userId, action, target, detail, ip, tenantId = '') {
	  await ensureAuditTable(DB);
	  // 查用户 phone
	  let phone = '';
  if (userId) {
    const lookupDB = DB && DB.DB ? DB.DB : DB;
    const u = await lookupDB.prepare('SELECT phone FROM users WHERE id = ?1').bind(userId).first().catch(() => null);
    if (u) phone = u.phone || '';
	  }
	  // detail 脱敏：不记录密码明文
	  const safeDetail = detail && detail.length > 200 ? detail.substring(0, 200) : (detail || '');
	  const writeTenantId = String(tenantId || DB?.tenantId || '');
	  await DB.prepare(
	    'INSERT INTO audit_logs (tenant_id, user_id, phone, action, target, detail, ip, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)'
	  ).bind(writeTenantId, String(userId || ''), phone, action, target, safeDetail, ip, new Date().toISOString()).run().catch(() => {});
	}

// ========== 白名单 ==========
const AUTH_WHITELIST = ['auth', 'forgot-password', 'reset-password', 'csrf-token'];

// ========== 主路由入口 ==========
export async function onRequest(context) {
  CURRENT_ORIGIN = context.request.headers.get('Origin') || new URL(context.request.url).origin || CURRENT_ORIGIN;
  const { request, env } = context;
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const path = url.pathname.replace(/^\/api\/?/, '');
  const segments = path.split('/').filter(Boolean);
  const module = segments[0] || '';
  const id = segments[1] || null;

  context.id = id;
  context.module = module;
  context._segments = segments;
  context.rawEnv = env;

  // 注入审计日志回调，供 auth.js 使用
  context._auditLog = auditLog;

  // ===== 频率限制 =====
  const clientIp = request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') || '0.0.0.0';
  if (!checkRateLimit(clientIp)) {
    return error('请求过于频繁，请稍后再试', 429);
  }

  context._clientIp = clientIp;

  // ===== JWT 认证中间件（Cookie 优先，Header 兜底） =====
  if (!AUTH_WHITELIST.includes(module)) {
    const JWT_SECRET = getJWTSecret(env);
    if (!JWT_SECRET) return error('系统登录密钥未配置，请先在 Cloudflare 设置 JWT_SECRET', 500);
    let token = getCookie(request, 'skgl_token');
    if (!token) {
      const authHeader = request.headers.get('Authorization') || '';
      token = authHeader.replace('Bearer ', '');
    }
    if (!token) return error('未提供认证令牌', 401);
    const payload = await verifyJWT(token, JWT_SECRET);
    if (!payload) return error('令牌无效或已过期', 401);
    context.userId = payload.uid;

    const user = await env.DB.prepare('SELECT id, phone, role, disabled, tenant_id, must_change_password FROM users WHERE id = ?1')
      .bind(payload.uid).first().catch(() => null);
    if (!user) return error('用户不存在或已被删除', 401);
    if (isDisabledValue(user.disabled)) return error('账号已被禁用，请联系管理员', 403);
    if (isDisabledValue(user.must_change_password)) return error('请先修改初始密码', 403);
    const tokenTenantId = String(payload.tid || payload.tenant_id || '').trim();
    if (!tokenTenantId) return error('请先选择账套', 428);
    const member = await env.DB.prepare(`SELECT role, disabled FROM tenant_members
      WHERE tenant_id = ?1 AND user_id = ?2 LIMIT 1`)
      .bind(tokenTenantId, payload.uid).first().catch(() => null);
    if (!member && String(user.phone || '') !== SUPER_ADMIN_PHONE) return error('没有该账套权限，请重新登录', 403);
    if (member && isDisabledValue(member.disabled)) return error('当前账套账号已停用，请联系管理员', 403);
    context.userPhone = user.phone || '';
    context.userRole = String(user.phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (member?.role || payload.role || user.role || '');
    context.tenantId = tokenTenantId;
  }

  const adminModules = ['users', 'system', 'settings', 'backup', 'restore', 'audit-logs', 'use', 'function', 'function-user'];
  if (adminModules.includes(module) && !(await requireAdmin(context))) {
    return error('只有管理员可以操作该功能', 403);
  }

  const permissionModules = ['customers', 'kehu', 'bills', 'income-items', 'income', 'shoukuan', 'data', 'accounts', 'departments', 'prospects', 'payment-plans', 'tixing', 'stats', 'dashboard', 'search', 'feedback', 'contract-expiry', 'reports', 'trends', 'analysis', 'ar-reports', 'change-password', 'item-mgr', 'wl-info'];
  if (context.userId && permissionModules.includes(module) && !(await hasModulePermission(context))) {
    return error('没有该模块权限，请联系管理员授权', 403);
  }
  if (context.userId && permissionModules.includes(module) && request.method === 'DELETE' && !(await hasActionPermission(context, 'delete'))) {
    return error('没有删除权限，请联系管理员授权', 403);
  }

  if (context.userId && context.tenantId) {
    await ensureTenantColumns(env.DB);
    context.env = { ...env, DB: new TenantDatabase(env.DB, context.tenantId, env) };
  }

  // ===== CSRF 校验（所有 mutating 请求） =====
  if (['POST', 'PUT', 'DELETE'].includes(request.method) && !AUTH_WHITELIST.includes(module)) {
    const csrfCookie = getCookie(request, 'skgl_csrf');
    const csrfHeader = request.headers.get('X-CSRF-Token');
    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
      return error('CSRF 校验失败', 403);
    }
  }

  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    try { context.body = await request.json(); } catch { context.body = {}; }
  }
  context.query = Object.fromEntries(url.searchParams);

  try {
    switch (module) {
      case 'customers':
      case 'kehu':
        return await handleKehu(context);

      case 'bills':
        return await bills(context);

      case 'auth':
        return await auth(context);

      case 'data':
        return await dataHandler(context);

      case 'income-items':
        return await incomeItems(context);

      case 'income':
        return await incomeHandler(context);

      case 'shoukuan':
        return await shoukuan(context);

      case 'accounts':
      case 'departments':
      case 'prospects':
      case 'users':
      case 'payment-plans':
      case 'tixing':
        return await masters(context);

      case 'stats':
        return await handleStats(context);

      case 'dashboard':
        return await handleDashboard(context);

      case 'system':
        return await handleSystem(context);

      case 'settings':
        return await handleSettings(context);

      case 'sys-config':
        return await handleLegacyConfig(context);

      case 'search':
        return await handleSearch(context);

      case 'change-password':
        return await handleChangePassword(context);

      case 'feedback':
        return await handleFeedback(context);

      case 'backup':
        return await handleBackup(context);

      case 'restore':
        return await handleRestore(context);

      case 'forgot-password':
      case 'reset-password':
        return await handleResetPassword(context);

      case 'print':
        return await handlePrint(context);

      case 'contract-expiry':
        return await handleContractExpiry(context);

      case 'reports':
      case 'trends':
      case 'analysis':
      case 'ar-reports':
        return await handleReports(context);

      case 'csrf-token':
        return await handleCsrfToken(context);

      case 'error-report':
        return await handleErrorReport(context);

      case 'audit-logs':
        return await handleAuditLogs(context);

      case 'platform-admin':
        return await handlePlatformAdmin({ ...context, env: context.rawEnv || env });

      // ===== 重构模块 =====
      case 'wl-info':
      case 'use':
      case 'function':
      case 'function-user':
      case 'item-mgr':
        return await allHandler(context);

      default:
        return json({
          success: true,
          message: '记账客户管理软件 API v1.0',
          modules: ['customers','kehu','bills','auth','income-items','shoukuan','accounts','departments','prospects','users','payment-plans','tixing','wl-info','item-mgr','settings','search','stats','dashboard','system','audit-logs'],
        });
    }
  } catch (err) {
    console.error(`[API Error] ${module}:`, err);
    return error(err.message || '服务器内部错误', 500);
  }
}

// ============ 审计日志查询 ============
async function handleAuditLogs(context) {
  const { request, env, query } = context;
  const DB = context.rawEnv?.DB || env.DB?.DB || env.DB;
  await ensureAuditTable(DB);

  if (request.method !== 'GET') return error('仅支持 GET 查询', 405);

  const userId = String(query.user_id || query.phone || '').trim();
  const actionFilter = query.action || '';
  const startDate = query.start || query.date_from || '';
  const endDate = query.end || query.date_to || '';
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(200, Math.max(10, parseInt(query.limit || query.pageSize) || 50));
  const offset = (page - 1) * limit;

  const conditions = [];
  const params = [];
  let p = 1;
  const tenantId = String(context.tenantId || '').trim();
  if (tenantId) {
    conditions.push(`(COALESCE(tenant_id,'') = ?${p} OR user_id IN (SELECT CAST(user_id AS TEXT) FROM tenant_members WHERE tenant_id = ?${p + 1}) OR phone IN (SELECT phone FROM tenant_members WHERE tenant_id = ?${p + 2}))`);
    params.push(tenantId, tenantId, tenantId);
    p += 3;
  }
  if (userId) {
    conditions.push(`(user_id = ?${p} OR phone LIKE ?${p + 1})`);
    params.push(userId, `%${userId}%`);
    p += 2;
  }
  if (actionFilter) { conditions.push(`action = ?${p}`); params.push(actionFilter); p++; }
  if (startDate) { conditions.push(`created_at >= ?${p}`); params.push(startDate); p++; }
  if (endDate) { conditions.push(`created_at <= ?${p}`); params.push(`${endDate}T23:59:59.999Z`); p++; }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const limitIdx = params.length + 1;
    const offsetIdx = params.length + 2;
    const [rows, countR] = await Promise.all([
      DB.prepare(`SELECT * FROM audit_logs ${where} ORDER BY created_at DESC LIMIT ?${limitIdx} OFFSET ?${offsetIdx}`)
        .bind(...params, limit, offset).all(),
      DB.prepare(`SELECT COUNT(*) as total FROM audit_logs ${where}`)
        .bind(...params).first(),
    ]);
    const list = rows.results || [];
    const total = countR?.total || 0;
    return json({ success: true, list, total, data: { list, total } });
  } catch (e) {
    return json({ success: true, list: [], total: 0, data: { list: [], total: 0 } });
  }
}

// ============ 统计面板 ============
async function handleStats(context) {
  const { env } = context;
  const DB = env.DB;
  const [custResult, billResult] = await Promise.all([
    DB.prepare('SELECT COUNT(*) as cnt FROM customers').first().catch(() => ({ cnt: 0 })),
    DB.prepare('SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0) as total FROM bills').first().catch(() => ({ cnt: 0, total: 0 })),
  ]);
  return json({ success: true, data: { customerCount: custResult?.cnt || 0, billCount: billResult?.cnt || 0, totalAmount: billResult?.total || 0 } });
}

// ============ 仪表盘 ============
function dashboardNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function parseDashboardDate(value) {
  const m = String(value || '').trim().match(/^(\d{4})-(\d{1,2})(?:-(\d{1,2}))?/);
  if (!m) return null;
  const y = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3] || 1);
  if (!y || month < 1 || month > 12 || day < 1 || day > 31) return null;
  return new Date(Date.UTC(y, month - 1, day));
}

function parseDashboardMonth(value) {
  const d = parseDashboardDate(value);
  return d ? new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)) : null;
}

function dashboardMonthKey(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

function addDashboardMonths(date, months) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + months, 1));
}

function dashboardPeriodEnd(start, intervalMonths) {
  return new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + intervalMonths, 0));
}

function safeExtraData(value) {
  if (!value) return {};
  try { return JSON.parse(value) || {}; } catch (_) { return {}; }
}

function isInactiveCustomer(row) {
  if (!row || typeof row !== 'object') return false;
  const extra = safeExtraData(row.extra_data);
  const values = [
    row.disabled, row.dis_flag, row.status,
    extra.disabled, extra.dis_flag, extra.status, extra.jinyong, extra.stop_flag,
  ];
  return values.some(v => isDisabledValue(v) || String(v || '').trim() === '不合作');
}

async function ensurePaymentPlansSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS payment_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kehu_id INTEGER,
    kehu_name TEXT,
    item_name TEXT,
    start_month TEXT,
    end_month TEXT,
    interval_months TEXT,
    amount_per REAL,
    notes TEXT,
    next_due TEXT,
    customer_code TEXT,
    created_at TEXT,
    updated_at TEXT
  )`).run().catch(() => {});
  const cols = ['kehu_id INTEGER','kehu_name TEXT','item_name TEXT','start_month TEXT','end_month TEXT','interval_months TEXT','amount_per REAL','notes TEXT','next_due TEXT','customer_code TEXT','created_at TEXT','updated_at TEXT'];
  for (const c of cols) { try { await DB.prepare(`ALTER TABLE payment_plans ADD COLUMN ${c}`).run(); } catch (_) {} }
}

async function ensureShoukuanDashboardSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS shoukuan (
    id INTEGER PRIMARY KEY,
    sheet_no TEXT, kehu_id INTEGER, customer_code TEXT, kehu_name TEXT,
    amount REAL, method TEXT, shoukuan_date TEXT, biz_date TEXT,
    period_start TEXT, period_end TEXT, salesperson TEXT,
    account_code TEXT, item_code TEXT, item_name TEXT, dept TEXT,
    notes TEXT, notes2 TEXT, invoice_no TEXT, invoice_date TEXT,
    created_at TEXT, updated_at TEXT
  )`).run().catch(() => {});
  await migrateLegacyShoukuanDashboardTable(DB).catch(() => {});
  const cols = ['sheet_no TEXT','kehu_id INTEGER','customer_code TEXT','kehu_name TEXT','amount REAL','method TEXT','shoukuan_date TEXT','biz_date TEXT','period_start TEXT','period_end TEXT','salesperson TEXT','account_code TEXT','item_code TEXT','item_name TEXT','dept TEXT','notes TEXT','notes2 TEXT','invoice_no TEXT','invoice_date TEXT','created_at TEXT','updated_at TEXT'];
  for (const c of cols) { try { await DB.prepare(`ALTER TABLE shoukuan ADD COLUMN ${c}`).run(); } catch (_) {} }
}

async function migrateLegacyShoukuanDashboardTable(DB) {
  const info = await DB.prepare('PRAGMA table_info(shoukuan)').all().catch(() => ({ results: [] }));
  const idCol = (info.results || []).find(c => c.name === 'id');
  if (idCol && String(idCol.type || '').toUpperCase() === 'INTEGER' && Number(idCol.pk || 0) === 1) return;
  await DB.prepare('PRAGMA foreign_keys = OFF').run().catch(() => {});
  await DB.prepare(`CREATE TABLE IF NOT EXISTS shoukuan_new (
    id INTEGER PRIMARY KEY,
    sheet_no TEXT, kehu_id INTEGER, customer_code TEXT, kehu_name TEXT,
    amount REAL, method TEXT, shoukuan_date TEXT, biz_date TEXT,
    period_start TEXT, period_end TEXT, salesperson TEXT,
    account_code TEXT, item_code TEXT, item_name TEXT, dept TEXT,
    notes TEXT, notes2 TEXT, invoice_no TEXT, invoice_date TEXT,
    created_at TEXT, updated_at TEXT
  )`).run();
  await DB.prepare(`INSERT INTO shoukuan_new (
    id, sheet_no, kehu_id, customer_code, kehu_name, amount, method, shoukuan_date, biz_date,
    period_start, period_end, salesperson, account_code, item_code, item_name, dept,
    notes, notes2, invoice_no, invoice_date, created_at, updated_at
  )
  SELECT
    COALESCE(NULLIF(id, ''), rowid), sheet_no, kehu_id, customer_code, kehu_name, amount, method, shoukuan_date, biz_date,
    period_start, period_end, salesperson, account_code, item_code, item_name, dept,
    notes, notes2, invoice_no, invoice_date, created_at, updated_at
  FROM shoukuan`).run().catch(() => {});
  await DB.prepare('DROP TABLE shoukuan').run();
  await DB.prepare('ALTER TABLE shoukuan_new RENAME TO shoukuan').run();
  await DB.prepare('DROP TABLE IF EXISTS shoukuan_periods').run().catch(() => {});
  await DB.prepare(`CREATE TABLE IF NOT EXISTS shoukuan_periods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shoukuan_id INTEGER NOT NULL,
    period_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(shoukuan_id, period_id)
  )`).run().catch(() => {});
  await DB.prepare('PRAGMA foreign_keys = ON').run().catch(() => {});
}

async function ensureDashboardSchema(DB) {
  await ensureKehuSchema(DB).catch(() => {});
  await DB.prepare(`CREATE TABLE IF NOT EXISTS bills (id TEXT PRIMARY KEY, customer_id TEXT, customer_name TEXT, amount REAL, date TEXT, method TEXT, remark TEXT, created_at TEXT, updated_at TEXT)`).run().catch(() => {});
  await DB.prepare(`CREATE TABLE IF NOT EXISTS tixing (id INTEGER PRIMARY KEY, kehu_id TEXT, kehu_name TEXT, remind_date TEXT, content TEXT, status TEXT, customer_code TEXT, created_at TEXT, updated_at TEXT)`).run().catch(() => {});
  await ensurePaymentPlansSchema(DB);
  await ensureShoukuanDashboardSchema(DB);
}

function paymentPlanFromCustomerItem(row, extra, item, idx) {
  return {
    id: `kehu-${row.id}-${idx}`,
    kehu_id: row.id,
    kehu_name: row.company || row.name || extra.name || '',
    item_name: item.project_name || item.item_name || item.item_code || '代理记账费用',
    start_month: item.start_month || item.period_start || item.start_date || item.contract_start || extra.yw_beg || row.start_date || '',
    end_month: item.end_month || item.period_end || item.end_date || item.contract_end || extra.yw_end || '2222-12',
    interval_months: item.interval_months || item.month_interval || item.period || item.interval || 12,
    amount_per: item.amount_per || item.month_amount || item.amount || 0,
    notes: item.notes || '',
    customer_code: row.code || extra.code || '',
  };
}

function paymentPlanFromCustomerFallback(row, extra) {
  return {
    id: `kehu-${row.id}-billing`,
    kehu_id: row.id,
    kehu_name: row.company || row.name || extra.name || '',
    item_name: '代理记账费用',
    start_month: extra.yw_beg || row.start_date || '',
    end_month: extra.yw_end || '2222-12',
    interval_months: 12,
    amount_per: extra.billing_amount || extra.amount_per || extra.month_amount || 0,
    notes: '',
    customer_code: row.code || extra.code || '',
  };
}

function collectCustomerPaymentPlans(customerRows, existingPlans) {
  const plannedCustomerIds = new Set((existingPlans || []).map(p => String(p.kehu_id || '')).filter(Boolean));
  const plans = [];
  for (const row of customerRows || []) {
    if (plannedCustomerIds.has(String(row.id || ''))) continue;
    const extra = safeExtraData(row.extra_data);
    const items = Array.isArray(extra.sk_items) ? extra.sk_items : [];
    if (items.length) {
      items.forEach((item, idx) => plans.push(paymentPlanFromCustomerItem(row, extra, item, idx)));
      continue;
    }
    const fallback = paymentPlanFromCustomerFallback(row, extra);
    if (dashboardNumber(fallback.amount_per) > 0 && fallback.start_month) plans.push(fallback);
  }
  return plans;
}

function normalizeDashboardCustomerRows(customerRows, wlRows) {
  const map = new Map();
  const add = row => {
    if (!row) return;
    const id = row.id ?? row.wl_id ?? '';
    const code = row.code || row.wl_bianm || '';
    const name = row.company || row.name || row.wl_name || row.sz_name || '';
    const key = code ? `code:${code}` : (id ? `id:${id}` : `name:${name}`);
    if (!key || key === 'name:') return;
    if (!map.has(key)) {
      map.set(key, {
        id,
        company: row.company || row.wl_name || row.name || '',
        name: row.name || row.wl_name || row.company || '',
        code,
        start_date: row.start_date || row.beg_date || row.beg_m || '',
        extra_data: row.extra_data || '',
      });
    }
  };
  (customerRows || []).forEach(add);
  (wlRows || []).forEach(add);
  return Array.from(map.values());
}

function normalizeDashboardPlanRows(planRows, wlPlanRows, customerRows) {
  const plans = (planRows || []).map(p => ({ ...p }));
  const customerById = new Map((customerRows || []).map(c => [String(c.id || ''), c]));
  for (const p of wlPlanRows || []) {
    const c = customerById.get(String(p.wl_id || '')) || {};
    plans.push({
      id: `wl-plan-${p.autoid || p.id || p.wl_id || plans.length}`,
      kehu_id: p.wl_id || '',
      kehu_name: c.company || c.name || p.kehu_name || '',
      item_name: p.other1 || '定期收款',
      start_month: p.beg_m || p.beg_date || p.oper_date || '',
      end_month: p.end_m || p.end_date || '2222-12',
      interval_months: p.month_jg || p.month_interval || p.period || 12,
      amount_per: p.month_amt || p.amount_per || p.amount || 0,
      notes: p.other1 || '',
      customer_code: c.code || '',
    });
  }
  return plans.concat(collectCustomerPaymentPlans(customerRows, plans));
}

function filterPlansForActiveCustomers(planRows, activeCustomerRows, allCustomerRows) {
  const knownIds = new Set((allCustomerRows || []).map(c => String(c.id || '')).filter(Boolean));
  const activeIds = new Set((activeCustomerRows || []).map(c => String(c.id || '')).filter(Boolean));
  const knownCodes = new Set((allCustomerRows || []).map(c => String(c.code || '')).filter(Boolean));
  const activeCodes = new Set((activeCustomerRows || []).map(c => String(c.code || '')).filter(Boolean));
  return (planRows || []).filter(plan => {
    const id = String(plan.kehu_id || '').trim();
    if (id && knownIds.has(id)) return activeIds.has(id);
    const code = String(plan.customer_code || '').trim();
    if (code && knownCodes.has(code)) return activeCodes.has(code);
    return true;
  });
}

function normalizeDashboardPaymentRows(shoukuanRows, wlSzRows) {
  const rows = (shoukuanRows || []).map(r => ({ ...r, amount: dashboardNumber(r.amount) }));
  for (const r of wlSzRows || []) {
    rows.push({
      id: `wl-sz-${r.flow_id || r.id || rows.length}`,
      kehu_id: r.wl_id || '',
      customer_code: r.customer_code || '',
      kehu_name: r.sz_name || r.kehu_name || '',
      amount: dashboardNumber(r.sr || r.kpje || r.amount),
      method: r.method || '',
      shoukuan_date: r.oper_date || r.shoukuan_date || '',
      period_start: r.beg_m || r.beg_date || '',
      period_end: r.end_m || r.end_date || '',
      account_code: r.cashno || '',
      salesperson: r.oper_id || '',
      notes: r.other1 || r.sz_no || '',
    });
  }
  return rows;
}

function buildCurrentMonthTrend(payments, yearMonth, year, monthNumber) {
  const days = new Date(year, monthNumber, 0).getDate();
  const trend = Array.from({ length: days }, (_, i) => ({ month: `${i + 1}日`, amount: 0 }));
  for (const p of payments || []) {
    const date = String(p.shoukuan_date || p.oper_date || '');
    if (!date.startsWith(yearMonth)) continue;
    const day = parseInt(date.substring(8, 10), 10);
    if (day >= 1 && day <= days) trend[day - 1].amount += dashboardNumber(p.amount || p.sr || p.kpje);
  }
  return trend;
}

function paymentMatchesPeriod(payment, periodStart, periodEnd) {
  const serviceStart = parseDashboardMonth(payment.period_start);
  const serviceEndMonth = parseDashboardMonth(payment.period_end);
  if (serviceStart || serviceEndMonth) {
    const serviceEnd = serviceEndMonth ? dashboardPeriodEnd(serviceEndMonth, 1) : (serviceStart ? dashboardPeriodEnd(serviceStart, 1) : null);
    const start = serviceStart || serviceEndMonth || parseDashboardDate(payment.shoukuan_date);
    const end = serviceEnd || parseDashboardDate(payment.shoukuan_date) || start;
    return !!(start && end && end >= periodStart && start <= periodEnd);
  }
  const payDate = parseDashboardDate(payment.shoukuan_date);
  return !!(payDate && payDate >= periodStart && payDate <= periodEnd);
}

function dashboardItemKey(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, '').replace(/[()（）【】\[\]{}、,，.。/\\-]/g, '');
}

function paymentMatchesPlanItem(payment, plan) {
  const payItem = payment.item_name || payment.item_code || payment.income_item || payment.project_name || '';
  const planItem = plan.item_name || plan.item_code || plan.project_name || '';
  if (!payItem || !planItem) return true;
  return dashboardItemKey(payItem) === dashboardItemKey(planItem);
}

function paymentListForPlan(plan, byKehuId, byCustomerCode) {
  const found = new Map();
  const add = row => { if (row && row.id !== undefined) found.set(String(row.id), row); };
  (byKehuId.get(String(plan.kehu_id || '')) || []).forEach(add);
  (byCustomerCode.get(String(plan.customer_code || '')) || []).forEach(add);
  return Array.from(found.values());
}

function buildDashboardReceivables(plans, payments, now) {
  const byKehuId = new Map();
  const byCustomerCode = new Map();
  for (const p of payments || []) {
    const kid = String(p.kehu_id || '');
    const code = String(p.customer_code || '');
    if (kid) {
      if (!byKehuId.has(kid)) byKehuId.set(kid, []);
      byKehuId.get(kid).push(p);
    }
    if (code) {
      if (!byCustomerCode.has(code)) byCustomerCode.set(code, []);
      byCustomerCode.get(code).push(p);
    }
  }

  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const currentMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  let pendingAmount = 0;
  let dueCount = 0;
  let overdueCount = 0;
  const overdueItems = [];

  for (const plan of plans || []) {
    const amount = dashboardNumber(plan.amount_per || plan.amount || plan.month_amount);
    if (amount <= 0) continue;
    const interval = Math.max(1, parseInt(plan.interval_months || plan.month_interval || plan.period || plan.interval || 12) || 12);
    const start = parseDashboardMonth(plan.start_month || plan.period_start || plan.start_date || plan.contract_start) || currentMonth;
    const endMonth = parseDashboardMonth(plan.end_month || plan.period_end || plan.end_date || plan.contract_end || '2222-12') || parseDashboardMonth('2222-12');
    const planPayments = paymentListForPlan(plan, byKehuId, byCustomerCode);

    for (let periodStart = start, guard = 0; guard < 240 && periodStart <= today && periodStart <= endMonth; guard++, periodStart = addDashboardMonths(periodStart, interval)) {
      const periodEnd = dashboardPeriodEnd(periodStart, interval);
      const isOverdue = periodEnd < today;
      const isCurrent = periodStart <= today && periodEnd >= today;
      if (!isOverdue && !isCurrent) continue;
      const paid = planPayments.reduce((sum, payment) => paymentMatchesPeriod(payment, periodStart, periodEnd) && paymentMatchesPlanItem(payment, plan) ? sum + dashboardNumber(payment.amount) : sum, 0);
      const due = Math.max(0, amount - paid);
      if (due <= 0.009) continue;
      dueCount++;
      pendingAmount += due;
      if (isOverdue) {
        overdueCount++;
        overdueItems.push({
          id: plan.id,
          kehu_name: plan.kehu_name || '',
          amount: due,
          days: Math.max(0, Math.ceil((today - periodEnd) / 86400000)),
          last_date: dashboardMonthKey(periodEnd),
          item_name: plan.item_name || '',
        });
      }
    }
  }

  overdueItems.sort((a, b) => (b.days || 0) - (a.days || 0));
  return { pendingAmount, dueCount, overdueCount, overdueItems };
}

async function handleDashboard(context) {
  const { env } = context;
  const DB = env.DB;
  const now = new Date();
  const year = now.getFullYear();
  const monthNumber = now.getMonth() + 1;
  const month = String(monthNumber).padStart(2, '0');
  const yearMonth = `${year}-${month}`;
  try {
    await ensureDashboardSchema(DB);
    const [customerRowsResult, wlCustomerRowsResult, planRowsResult, wlPlanRowsResult, paymentRowsResult, wlPaymentRowsResult, reminderItemsResult] = await Promise.all([
      DB.prepare('SELECT * FROM customers LIMIT 2000').all().catch(() => ({ results: [] })),
      DB.prepare('SELECT * FROM wl_info LIMIT 2000').all().catch(() => ({ results: [] })),
      DB.prepare('SELECT * FROM payment_plans LIMIT 3000').all().catch(() => ({ results: [] })),
      DB.prepare('SELECT * FROM wl_sz_plan LIMIT 3000').all().catch(() => ({ results: [] })),
      DB.prepare('SELECT * FROM shoukuan ORDER BY id DESC LIMIT 3000').all().catch(() => ({ results: [] })),
      DB.prepare('SELECT * FROM wl_sz ORDER BY rowid DESC LIMIT 3000').all().catch(() => ({ results: [] })),
      DB.prepare("SELECT * FROM tixing WHERE COALESCE(status,'') NOT IN ('已完成','已处理','done','closed') ORDER BY remind_date ASC LIMIT 200").all().catch(() => ({ results: [] })),
    ]);
    const allCustomerRows = normalizeDashboardCustomerRows(customerRowsResult.results || [], wlCustomerRowsResult.results || []);
    const customerRows = allCustomerRows.filter(row => !isInactiveCustomer(row));
    const activePlanRows = filterPlansForActiveCustomers(planRowsResult.results || [], customerRows, allCustomerRows);
    const paymentRows = normalizeDashboardPaymentRows(paymentRowsResult.results || [], wlPaymentRowsResult.results || []);
    const paymentPlans = normalizeDashboardPlanRows(activePlanRows, wlPlanRowsResult.results || [], customerRows);
    const receivables = buildDashboardReceivables(paymentPlans, paymentRows, now);
    const monthlyTrend = buildCurrentMonthTrend(paymentRows, yearMonth, year, monthNumber);
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const allReminderItems = reminderItemsResult.results || [];
    const reminderItems = allReminderItems.filter(r => {
      if (!r.remind_date) return true;
      const d = new Date(`${r.remind_date}T00:00:00`);
      return Number.isNaN(d.getTime()) || d <= today;
    }).map(r => {
      const d = r.remind_date ? new Date(`${r.remind_date}T00:00:00`) : null;
      const days = d && !Number.isNaN(d.getTime()) ? Math.max(0, Math.ceil((today - d) / 86400000)) : 0;
      return { id: r.id, kehu_name: r.kehu_name || '', amount: r.amount || 0, days, last_date: r.remind_date || '', item_name: r.content || '提醒事项' };
    });
    const overdueItems = receivables.overdueItems.concat(reminderItems)
      .sort((a, b) => (b.days || 0) - (a.days || 0))
      .slice(0, 5);
    const monthIncome = paymentRows.reduce((sum, r) => String(r.shoukuan_date || '').startsWith(yearMonth) ? sum + dashboardNumber(r.amount) : sum, 0);
    const yearIncome = paymentRows.reduce((sum, r) => String(r.shoukuan_date || '').startsWith(String(year)) ? sum + dashboardNumber(r.amount) : sum, 0);
    const recentTxs = paymentRows
      .slice()
      .sort((a, b) => String(b.shoukuan_date || '').localeCompare(String(a.shoukuan_date || '')))
      .slice(0, 10)
      .map(r => ({ id: r.id, kehu_name: r.kehu_name || '', amount: r.amount || 0, shoukuan_date: r.shoukuan_date || '', method: r.method || '', account_code: r.account_code || '', salesperson: r.salesperson || '', notes: r.notes || '' }));
    const overdueCount = receivables.overdueCount;
    const dueCount = receivables.dueCount;
    const todayTodoCount = dueCount;
    const reminderBadgeCount = dueCount;
    return json({
      success: true,
      customerCount: customerRows.length,
      monthIncome,
      yearIncome,
      pendingAmount: receivables.pendingAmount,
      overdueCount,
      dueCount,
      todayTodoCount,
      reminderBadgeCount,
      todayTodos: overdueItems,
      monthlyTrend,
      overdueItems,
      recentTxs,
    });
  } catch (e) {
    return json({ success: true, customerCount: 0, monthIncome: 0, yearIncome: 0, pendingAmount: 0, overdueCount: 0, todayTodoCount: 0, reminderBadgeCount: 0, todayTodos: [], monthlyTrend: [], overdueItems: [], recentTxs: [] });
  }
}

const DEFAULT_SETTINGS = {
  companyName: '',
  displayName: '',
  avatarText: '',
  phone: '',
  address: '',
  dblclick_copy: '1',
  hide_disabled: '1',
};

const SETTINGS_ALIASES = {
  company_name: 'companyName',
  company: 'companyName',
  display_name: 'displayName',
  userName: 'displayName',
  avatar_text: 'avatarText',
};

async function ensureSettingsTable(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT,
    updated_at TEXT
  )`).run();
}

function scopedKey(DB, key, prefix = '') {
  const tenantId = DB && DB.tenantId ? String(DB.tenantId) : '';
  const raw = String(key || '');
  return tenantId ? `${prefix}${tenantId}:${raw}` : raw;
}

function unscopedKey(DB, key, prefix = '') {
  const tenantId = DB && DB.tenantId ? String(DB.tenantId) : '';
  const raw = String(key || '');
  const head = tenantId ? `${prefix}${tenantId}:` : '';
  return head && raw.startsWith(head) ? raw.slice(head.length) : raw;
}

function parseSettingsPayload(body) {
  if (!body) return {};
  if (typeof body.value === 'string') {
    try { return JSON.parse(body.value) || {}; } catch (_) { return {}; }
  }
  return body;
}

function sanitizeSettingsObject(source, withDefaults = false) {
  const cleaned = withDefaults ? { ...DEFAULT_SETTINGS } : {};
  if (!source || typeof source !== 'object') return cleaned;
  for (const [key, value] of Object.entries(source)) {
    const settingKey = SETTINGS_ALIASES[key] || key;
    if (Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, settingKey)) {
      cleaned[settingKey] = value;
    }
  }
  if (cleaned.avatarText) cleaned.avatarText = String(cleaned.avatarText).slice(0, 2);
  return cleaned;
}

async function readSettings(DB) {
  await ensureSettingsTable(DB);
  const key = scopedKey(DB, 'settings', 'settings:');
  const row = await DB.prepare('SELECT setting_value FROM app_settings WHERE setting_key = ?1')
    .bind(key).first().catch(() => null);
  if (!row || !row.setting_value) return { ...DEFAULT_SETTINGS };
  try {
    return sanitizeSettingsObject(JSON.parse(row.setting_value), true);
  } catch (_) {
    return { ...DEFAULT_SETTINGS };
  }
}

async function writeSettings(DB, body) {
  await ensureSettingsTable(DB);
  const oldSettings = await readSettings(DB);
  const incoming = sanitizeSettingsObject(parseSettingsPayload(body));
  const next = sanitizeSettingsObject({ ...oldSettings, ...incoming }, true);
  const key = scopedKey(DB, 'settings', 'settings:');
  await DB.prepare('INSERT OR REPLACE INTO app_settings (setting_key, setting_value, updated_at) VALUES (?1, ?2, ?3)')
    .bind(key, JSON.stringify(next), new Date().toISOString()).run();
  return next;
}

// ============ 系统操作 ============
async function handleSystem(context) {
  const { request, env, id, body } = context;
  const DB = env.DB;
  const method = request.method;

  async function tableExists(tableName) {
    const row = await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?1")
      .bind(tableName).first().catch(() => null);
    return !!row;
  }

  async function clearMappedTable(entry, options = {}) {
    const realTables = Array.isArray(entry) ? entry : [entry];
    let found = 0, deleted = 0, errors = [];
    for (const realTable of realTables) {
      if (!await tableExists(realTable)) {
        if (!options.ignoreMissing) errors.push(`${realTable}: 表不存在`);
        continue;
      }
      found++;
      try {
        await DB.prepare(`DELETE FROM ${quoteIdent(realTable)}`).run();
        deleted++;
      } catch (e) {
        errors.push(`${realTable}: ${e.message}`);
      }
    }
    return { ok: errors.length === 0, found, deleted, errors };
  }

  if (method === 'POST' && id === 'clear-table') {
    const table = body?.table;
    if (!table) return error('缺少表名参数');
    const tableMap = {
      kehu: 'customers', shoukuan: 'shoukuan', tixing: 'tixing',
      prospects: 'kh',
      departments: 'dept_info', accounts: 'accounts', income_items: 'income_items',
      income_types: 'income_categories', customer_types: 'customer_types',
      payment_plans: ['payment_plans', 'wl_sz_plan'],
      item_management: 'item_manger', reminders: 'reminders'
    };
    if (!tableMap[table]) return json({ success: true, message: `表 ${table} 已跳过` });
    try {
      const cleared = await clearMappedTable(tableMap[table]);
      if (!cleared.ok) throw new Error(cleared.errors.join('; '));
      await auditLog(DB, context.userId, 'clear_table', table, '', context._clientIp);
      return json({ success: true, message: `表 ${table} 已清除` });
    } catch (e) { return json({ success: true, message: `表 ${table} 清除异常: ${e.message}` }); }
  }

  if (method === 'POST' && id === 'clear-all') {
    const tables = body?.tables;
    if (!tables || !Array.isArray(tables) || tables.length === 0) return error('缺少表名参数');
    const tableMap = {
      kehu: 'customers', shoukuan: 'shoukuan', tixing: 'tixing',
      prospects: 'kh',
      departments: 'dept_info', accounts: 'accounts', income_items: 'income_items',
      income_types: 'income_categories', customer_types: 'customer_types',
      payment_plans: ['payment_plans', 'wl_sz_plan'],
      item_management: 'item_manger', reminders: 'reminders', wl_sz: 'wl_sz'
    };
    let success = 0, failed = [];
    await DB.prepare('PRAGMA foreign_keys = OFF').run();
    for (const table of tables) {
      const realTable = tableMap[table];
      if (!realTable) continue;
      try {
        const cleared = await clearMappedTable(realTable, { ignoreMissing: true });
        if (!cleared.ok) throw new Error(cleared.errors.join('; '));
        await auditLog(DB, context.userId, 'clear_table', table, '', context._clientIp);
        success++;
      } catch (e) { failed.push(table); }
    }
    await DB.prepare('PRAGMA foreign_keys = ON').run();
    return json({ success: true, total: tables.length, successCount: success, failed: failed });
  }

  if (method === 'GET' && id === 'settings') {
    const settings = await readSettings(DB);
    return json({ success: true, data: settings, ...settings });
  }

  if (method === 'PUT' && id === 'settings') {
    const settings = await writeSettings(DB, body);
    await auditLog(DB, context.userId, 'settings_update', 'settings', '', context._clientIp);
    return json({ success: true, message: '设置已保存', data: settings, ...settings });
  }

  return error('未知的系统操作', 404);
}

// ============ 系统设置 ============
async function handleSettings(context) {
  const { request, env, body } = context;
  const DB = env.DB;
  const method = request.method;

  if (method === 'GET') {
    const settings = await readSettings(DB);
    return json({ success: true, data: settings, ...settings });
  }
  if (method === 'PUT' || method === 'POST') {
    const settings = await writeSettings(DB, body);
    await auditLog(DB, context.userId, 'settings_update', 'settings', '', context._clientIp);
    return json({ success: true, message: '设置已保存', data: settings, ...settings });
  }
  return error('不支持的请求方法', 405);
}

// ============ 兼容旧 company_name 读取 ============
async function handleLegacyConfig(context) {
  const { request, env, query, body, id } = context;
  const DB = env.DB;
  await DB.prepare(`CREATE TABLE IF NOT EXISTS t_sys (
    sys_id TEXT PRIMARY KEY,
    sys_value TEXT,
    sys_value2 TEXT,
    sys_other1 TEXT,
    sys_other2 TEXT,
    created_at TEXT,
    updated_at TEXT
  )`).run().catch(() => {});

  const key = query?.key || id || body?.key || body?.sys_id || '';
  const dbKey = key ? scopedKey(DB, key, 'sys:') : '';
  if (request.method === 'GET') {
    if (key) {
      const row = await DB.prepare('SELECT * FROM t_sys WHERE sys_id = ?1').bind(dbKey).first().catch(() => null);
      if (row) return json({ success: true, key, value: row.sys_value || '', data: { ...row, sys_id: key } });
      if (key === 'company_name') {
        const settings = await readSettings(DB);
        return json({ success: true, key, value: settings.companyName || '', data: { sys_id: key, sys_value: settings.companyName || '' } });
      }
      return json({ success: true, key, value: '', data: null });
    }
    const rows = await DB.prepare('SELECT * FROM t_sys ORDER BY sys_id ASC').all().catch(() => ({ results: [] }));
    const list = (rows.results || []).map(r => ({ ...r, sys_id: unscopedKey(DB, r.sys_id, 'sys:') }));
    return json({ success: true, list, data: list });
  }

  if (request.method === 'POST' || request.method === 'PUT') {
    if (!key) return error('缺少配置键');
    const now = new Date().toISOString();
    await DB.prepare(`INSERT OR REPLACE INTO t_sys (sys_id, sys_value, sys_value2, sys_other1, sys_other2, created_at, updated_at)
      VALUES (?1,?2,?3,?4,?5,COALESCE((SELECT created_at FROM t_sys WHERE sys_id=?1),?6),?6)`)
      .bind(dbKey, body?.value ?? body?.sys_value ?? '', body?.sys_value2 ?? '', body?.sys_other1 ?? '', body?.sys_other2 ?? '', now).run();
    return json({ success: true, message: '配置已保存' });
  }

  if (request.method === 'DELETE') {
    if (!key) return error('缺少配置键');
    await DB.prepare('DELETE FROM t_sys WHERE sys_id = ?1').bind(dbKey).run();
    return json({ success: true, message: '配置已删除' });
  }
  return error('不支持的请求方法', 405);
}

// ============ 全局搜索 ============
async function handleSearch(context) {
  const { env, query } = context;
  const DB = env.DB;
  const q = query?.kw || query?.q || query?.keyword || '';
  if (!q || q.trim().length < 1) return json({ success: true, results: [] });

  const keyword = q.trim().toLowerCase();
  try {
    const [kehuRes, skRes] = await Promise.all([
      DB.prepare("SELECT id, company as name, code, phone, mobile, contact, type, status, extra_data FROM customers LIMIT 5000").all().catch(() => ({ results: [] })),
      DB.prepare("SELECT id, kehu_id, kehu_name, amount, shoukuan_date, method, notes, sheet_no FROM shoukuan LIMIT 10000").all().catch(() => ({ results: [] })),
    ]);
    const matches = (row, fields) => fields.some(field => String(row[field] || '').toLowerCase().includes(keyword));

    const results = {
      kehu: (kehuRes.results || []).filter(r => !isInactiveCustomer(r) && matches(r, ['name', 'code', 'phone', 'mobile', 'contact', 'type'])).slice(0, 20).map(r => ({ ...r, type: 'kehu', kind: 'customer' })),
      shoukuan: (skRes.results || []).filter(r => matches(r, ['kehu_name', 'notes', 'sheet_no'])).slice(0, 20).map(r => ({ ...r, name: r.kehu_name || '', date: r.shoukuan_date || '', type: 'shoukuan', kind: 'transaction', tx_type: '收款', occur_date: r.shoukuan_date || '' })),
    };
    const flat = [...results.kehu, ...results.shoukuan];
    return json({ success: true, results: flat, groups: results });
  } catch (e) {
    return json({ success: true, results: [], groups: { kehu: [], shoukuan: [] } });
  }
}

// ============ 修改密码 ============
async function handleChangePassword(context) {
  const { request, body, env, userId } = context;
  if (request.method !== 'POST') return error('不支持的请求方法', 405);

  const { old_password, new_password } = body || {};
  if (!old_password || !new_password) return error('缺少参数');
  if (new_password.length < 6) return error('新密码至少6位');
  if (!userId) return error('未登录', 401);

  const DB = env.DB;
  const rawDB = context.rawEnv?.DB || (DB && DB.DB) || DB;
  const user = await rawDB.prepare('SELECT * FROM users WHERE id = ?1')
    .bind(userId).first().catch(() => null);
  if (!user) return error('用户不存在', 404);

  let valid = false;
  if (user.password_hash && user.password_hash.includes(':')) {
    valid = await verifyPasswordPBKDF2(old_password, user.password_hash);
  } else {
    const oldHash = await sha256(old_password + ':' + user.phone);
    valid = (oldHash === user.password_hash);
  }
  if (!valid) return error('旧密码错误');

  const newHash = await hashPasswordPBKDF2(new_password);
  await rawDB.prepare('UPDATE users SET password_hash = ?1, must_change_password = ?2 WHERE id = ?3')
    .bind(newHash, 'false', userId).run();

  await auditLog(DB, userId, 'change_pwd', 'users', '', context._clientIp);

  return json({ success: true, message: '密码修改成功' });
}

async function userPhoneById(context, userId) {
  if (!userId) return '';
  const rawDB = context.rawEnv?.DB || (context.env?.DB && context.env.DB.DB) || context.env?.DB;
  const user = await rawDB.prepare('SELECT phone FROM users WHERE id = ?1')
    .bind(userId).first().catch(() => null);
  return user?.phone || '';
}

// ============ 反馈 ============
function feedbackConfig(env) {
  const defaultEmail = 'lmmokai@126.com';
  return {
    publicEmail: env.SERVICE_EMAIL || env.FEEDBACK_TO_EMAIL || defaultEmail,
    toEmail: env.FEEDBACK_TO_EMAIL || env.SERVICE_EMAIL || defaultEmail,
    fromEmail: env.FEEDBACK_FROM_EMAIL || '',
    resendApiKey: env.RESEND_API_KEY || '',
    webhookUrl: env.FEEDBACK_WEBHOOK_URL || '',
    wechatQrUrl: env.SERVICE_WECHAT_QR_URL || '/wechat-service-qr.png',
    wechatName: env.SERVICE_WECHAT_NAME || '微信客服'
  };
}

function makeFeedbackId() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return 'fb_' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function ensureFeedbackTable(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS feedback_messages (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    phone TEXT,
    type TEXT,
    content TEXT,
    page TEXT,
    user_agent TEXT,
    ip TEXT,
    email_to TEXT,
    email_sent INTEGER DEFAULT 0,
    email_error TEXT,
    created_at TEXT
  )`).run();
}

async function sendFeedbackEmail(env, payload) {
  const cfg = feedbackConfig(env);
  if (!cfg.toEmail) return { sent: false, error: '未配置 FEEDBACK_TO_EMAIL 或 SERVICE_EMAIL' };

  const subject = `软件意见反馈 - ${payload.typeLabel}`;
  const text = [
    `反馈类型: ${payload.typeLabel}`,
    `提交时间: ${payload.createdAt}`,
    `用户账号: ${payload.phone || payload.userId || '-'}`,
    `来源页面: ${payload.page || '-'}`,
    `IP: ${payload.ip || '-'}`,
    '',
    '反馈内容:',
    payload.content
  ].join('\n');

  if (cfg.resendApiKey && cfg.fromEmail) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${cfg.resendApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: cfg.fromEmail,
        to: [cfg.toEmail],
        subject,
        text
      })
    });
    if (res.ok) return { sent: true, provider: 'resend' };
    const errText = await res.text().catch(() => '');
    return { sent: false, error: errText || `Resend 返回 ${res.status}` };
  }

  if (cfg.webhookUrl) {
    const res = await fetch(cfg.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: cfg.toEmail, subject, text, payload })
    });
    if (res.ok) return { sent: true, provider: 'webhook' };
    const errText = await res.text().catch(() => '');
    return { sent: false, error: errText || `Webhook 返回 ${res.status}` };
  }

  return { sent: false, error: '未配置 RESEND_API_KEY/FEEDBACK_FROM_EMAIL 或 FEEDBACK_WEBHOOK_URL' };
}

async function handleFeedback(context) {
  const { request, env, body } = context;
  const cfg = feedbackConfig(env);

  if (request.method === 'GET') {
    return json({
      success: true,
      data: {
        email: cfg.publicEmail,
        wechatQrUrl: cfg.wechatQrUrl,
        wechatName: cfg.wechatName
      }
    });
  }

  if (request.method !== 'POST') return error('不支持的请求方法', 405);

  const DB = env.DB;
  await ensureFeedbackTable(DB);

  const type = String(body?.type || 'other').slice(0, 30);
  const typeLabelMap = { bug: '问题反馈', feature: '功能建议', other: '其他' };
  const typeLabel = typeLabelMap[type] || type;
  const content = String(body?.content || '').trim();
  if (!content) return error('请填写反馈内容');
  if (content.length > 5000) return error('反馈内容不能超过 5000 字');

  const userId = String(context.userId || '');
  const phone = await userPhoneById(context, userId);
  const page = String(body?.page || '').slice(0, 500);
  const userAgent = String(body?.user_agent || '').slice(0, 500);
  const ip = context._clientIp || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
  const id = makeFeedbackId();
  const createdAt = new Date().toISOString();

  const emailResult = await sendFeedbackEmail(env, { id, userId, phone, type, typeLabel, content, page, userAgent, ip, createdAt }).catch(err => ({ sent: false, error: err.message || String(err) }));
  const emailError = emailResult.sent ? '' : String(emailResult.error || '').slice(0, 500);

  await DB.prepare(`INSERT INTO feedback_messages
    (id, user_id, phone, type, content, page, user_agent, ip, email_to, email_sent, email_error, created_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`)
    .bind(id, userId, phone, type, content, page, userAgent, ip, cfg.toEmail, emailResult.sent ? 1 : 0, emailError, createdAt).run();

  await auditLog(DB, userId, 'feedback', 'feedback_messages', `${type}: ${content.slice(0, 80)}`, ip).catch(() => {});

  return json({
    success: true,
    message: emailResult.sent ? '反馈已提交并发送到客服邮箱' : '反馈已保存',
    id,
    emailSent: !!emailResult.sent,
    emailProvider: emailResult.provider || '',
    emailError
  });
}

// ============ 备份 ============
async function tableExistsForBackup(DB, tableName) {
  const row = await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?1")
    .bind(tableName).first().catch(() => null);
  return !!row;
}

async function readTableSchema(DB, tableName) {
  const row = await DB.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name = ?1")
    .bind(tableName).first().catch(() => null);
  return row?.sql || '';
}

async function createFallbackTable(DB, tableName, rows) {
  const first = Array.isArray(rows) && rows.length ? rows[0] : null;
  if (!first || typeof first !== 'object') return false;
  const cols = Object.keys(first).filter(Boolean);
  if (!cols.length) return false;
  const defs = cols.map(c => `"${String(c).replace(/"/g, '""')}" TEXT`).join(', ');
  await DB.prepare(`CREATE TABLE IF NOT EXISTS ${quoteIdent(tableName)} (${defs})`).run();
  return true;
}

async function restoreTable(DB, tableName, entry) {
  const rows = Array.isArray(entry) ? entry : (Array.isArray(entry?.rows) ? entry.rows : []);
  const schema = Array.isArray(entry) ? '' : String(entry?.schema || '');

  if (schema && /^CREATE TABLE/i.test(schema.trim()) && schema.includes(tableName)) {
    await DB.prepare(schema).run().catch(() => {});
  } else if (!await tableExistsForBackup(DB, tableName)) {
    await createFallbackTable(DB, tableName, rows);
  }

  if (!await tableExistsForBackup(DB, tableName)) {
    return { restored: 0, skipped: true };
  }

  await DB.prepare(`DELETE FROM ${quoteIdent(tableName)}`).run();
  let restored = 0;
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const cols = Object.keys(row);
    if (!cols.length) continue;
    const colSql = cols.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',');
    const ph = cols.map((_, i) => `?${i + 1}`).join(',');
    const vals = cols.map(c => row[c] === undefined ? null : row[c]);
    await DB.prepare(`INSERT INTO ${quoteIdent(tableName)} (${colSql}) VALUES (${ph})`).bind(...vals).run();
    restored++;
  }
  return { restored, skipped: false };
}

async function handleBackup(context) {
  const { request, env } = context;
  const DB = env.DB;
  if (request.method === 'GET') {
    const allowedTables = backupTablesForContext(DB);
    const createdAt = new Date().toISOString();
    const backup = {
      app: 'skgl',
      version: 3,
      created_at: createdAt,
      tables: {},
    };
    for (const table of allowedTables) {
      if (!await tableExistsForBackup(DB, table)) continue;
      const rows = await DB.prepare(`SELECT * FROM ${quoteIdent(table)}`).all().catch(() => ({ results: [] }));
      backup.tables[table] = {
        schema: await readTableSchema(DB, table),
        rows: rows.results || [],
      };
    }
    backup.meta = await buildBackupMeta(context, backup.tables, createdAt);
    await auditLog(DB, context.userId, 'backup_export', 'backup', Object.keys(backup.tables).join(','), context._clientIp);
    return json({ success: true, data: backup });
  }
  if (request.method === 'POST') {
    return await handleBackup({ ...context, request: new Request(request.url, { method: 'GET' }) });
  }
  return error('不支持的请求方法', 405);
}

// ============ 恢复 ============
async function handleRestore(context) {
  const { request, body, env } = context;
  if (request.method !== 'POST') return error('不支持的请求方法', 405);
  const DB = env.DB;
  const payload = body?.data?.tables ? body.data : body;
  const tables = payload?.tables;
  if (!tables || typeof tables !== 'object') return error('备份文件格式不正确');
  let meta;
  try {
    meta = await validateBackupPayload(context, payload, tables);
  } catch (e) {
    return error(e.message || '备份文件校验失败', 403);
  }

  const allowedTables = backupTablesForContext(DB);
  const names = Object.keys(tables).filter(t => allowedTables.includes(t));
  if (!names.length) return error('备份文件中没有可恢复的数据表');

  const restored = {};
  const failed = {};
  await DB.prepare('PRAGMA foreign_keys = OFF').run().catch(() => {});
  try {
    for (const table of names) {
      try {
        restored[table] = await restoreTable(DB, table, tables[table]);
      } catch (e) {
        failed[table] = e.message || '恢复失败';
      }
    }
  } finally {
    await DB.prepare('PRAGMA foreign_keys = ON').run().catch(() => {});
  }

  await auditLog(DB, context.userId, 'backup_restore', 'restore', `${names.join(',')} tenant:${meta.tenant_id}`, context._clientIp);
  return json({ success: Object.keys(failed).length === 0, message: '数据恢复完成', restored, failed, meta: { tenant_id: meta.tenant_id, created_at: meta.created_at, user_id: meta.user_id } });
}

// ============ 重置密码 ============
async function handleResetPassword(context) {
  const { request, body, env, id } = context;
  const method = request.method;
  const DB = env.DB;
  await ensureResetUsersSchema(DB);

  if (method === 'POST' && !id) {
    const phone = normalizeResetPhone(body?.phone);
    const idCard = normalizeIdCard(body?.id_card || body?.idCard || body?.identity_no);
    if (!phone || !idCard) return error('手机号和身份证号为必填项');
    if (!validResetPhone(phone)) return error('请输入正确的11位手机号');
    if (!validIdCard(idCard)) return error('请输入正确的身份证号');

    const user = await findUserByResetIdentity(DB, env, phone, idCard);
    if (!user) {
      return error('手机号和身份证号不匹配', 404);
    }
    return json({ success: true, message: '身份信息匹配，可以设置新密码' });
  }

  if (method === 'POST' && id === 'confirm') {
    const phone = normalizeResetPhone(body?.phone);
    const idCard = normalizeIdCard(body?.id_card || body?.idCard || body?.identity_no);
    const password = body?.password || '';
    if (!phone || !idCard || !password) return error('缺少参数');
    if (!validResetPhone(phone)) return error('请输入正确的11位手机号');
    if (!validIdCard(idCard)) return error('请输入正确的身份证号');
    if (password.length < 6) return error('密码至少6位');

    const newHash = await hashPasswordPBKDF2(password);
    const user = await findUserByResetIdentity(DB, env, phone, idCard);
    if (!user) return error('手机号和身份证号不匹配', 404);
    await DB.prepare('UPDATE users SET password_hash = ?1, must_change_password = ?2 WHERE id = ?3')
      .bind(newHash, 'false', user.id).run();

    // 审计：密码重置
    await auditLog(DB, String(user.id), 'reset_pwd', 'users', '', context._clientIp);

    return json({ success: true, message: '密码重置成功' });
  }

  return error('不支持的请求方法', 405);
}

// ============ 打印 ============
async function handlePrint(context) {
  return json({ success: true, message: '打印功能已就绪' });
}

// ============ 合同到期 ============
async function handleContractExpiry(context) {
  const { env, query } = context;
  const DB = env.DB;
  const search = query?.search || '';
  try {
    let rows;
    if (search) {
      rows = await DB.prepare('SELECT * FROM customers WHERE (company LIKE ?1 OR phone LIKE ?1 OR contact LIKE ?1) AND extra_data IS NOT NULL LIMIT 500').bind(`%${search}%`).all().catch(() => ({ results: [] }));
    } else {
      rows = await DB.prepare('SELECT * FROM customers WHERE extra_data IS NOT NULL LIMIT 500').all().catch(() => ({ results: [] }));
    }
    const list = (rows.results || []).map(r => {
      let extra = {};
      try { extra = JSON.parse(r.extra_data || '{}'); } catch (_) {}
      return {
        id: r.id, code: r.code || '', type: r.type || '', name: r.company || '',
        yw_end: extra.yw_end || '', phone: r.phone || '', mobile: r.mobile || extra.mobile || '',
        address: r.address || extra.address || '', contact: r.contact || '',
        accountant: extra.baoshui || '', salesperson: r.manager || extra.salesperson || '',
        jz: extra.jz || '', bs: extra.bs || '', status: r.type || ''
      };
    });
    return json({ success: true, list, total: list.length, active: list.filter(r => r.status !== '不合作').length, inactive: list.filter(r => r.status === '不合作').length });
  } catch (e) {
    return json({ success: true, list: [], total: 0, active: 0, inactive: 0 });
  }
}

// ============ 报表/趋势/分析 ============
async function handleReports(context) {
  const { env, query, module, _segments } = context;
  const DB = env.DB;
  const year = query?.year || new Date().getFullYear();
  const sub = (_segments && _segments[1]) || '';

  try {
    const readTx = async () => {
      const sk = await DB.prepare('SELECT * FROM shoukuan LIMIT 10000').all().catch(() => ({ results: [] }));
      const skRows = (sk.results || []).map(r => ({ ...r, kind: 'sk', date: r.shoukuan_date || r.biz_date || '', amount: Number(r.amount || 0) }));
      return { skRows };
    };
    const inRange = (r) => {
      if (query?.year && !String(r.date || '').startsWith(String(query.year))) return false;
      if (query?.start && String(r.date || '') < query.start) return false;
      if (query?.start_date && String(r.date || '') < query.start_date) return false;
      if (query?.end && String(r.date || '') > query.end) return false;
      if (query?.end_date && String(r.date || '') > query.end_date) return false;
      if (query?.kehu_id && String(r.kehu_id || '') !== String(query.kehu_id)) return false;
      return true;
    };
    const monthKey = (date) => String(date || '').slice(0, 7) || '未填日期';
    const dayKey = (date) => String(date || '').slice(0, 10) || '未填日期';

    if (module === 'analysis' && sub === 'by-method') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) {
        const k = r.method || '其他';
        if (!map[k]) map[k] = { name: k };
        const m = Number((String(r.date || '').slice(5, 7) || '0'));
        if (m >= 1 && m <= 12) map[k]['m' + m] = (map[k]['m' + m] || 0) + r.amount;
      }
      return json(Object.values(map));
    }

    if (module === 'ar-reports') {
      const { skRows } = await readTx();
      if (sub === 'flow') {
        const rows = skRows.map(r => ({ date: r.date, kehu_name: r.kehu_name || '', type: '应收/收款', amount: r.amount, notes: r.notes || '' }));
        return json(rows.sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 1000));
      }
      const map = {};
      const groupByCustomer = query?.status || query?.group === 'customer';
      for (const r of skRows.filter(inRange)) {
        const k = groupByCustomer ? (r.kehu_id || r.kehu_name || '未分类') : (r.item_name || r.kehu_name || '未分类');
        if (!map[k]) map[k] = { item: groupByCustomer ? (r.kehu_name || '未分类') : k, kehu_name: r.kehu_name || '', ying_shou: 0, yi_shou: 0, wei_shou: 0 };
        map[k].ying_shou += r.amount;
        map[k].yi_shou += r.amount;
        map[k].wei_shou = Math.max(0, map[k].ying_shou - map[k].yi_shou);
      }
      return json(Object.values(map));
    }

    if (sub === 'ar-summary') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) {
        const k = r.kehu_id || r.kehu_name || 'unknown';
        if (!map[k]) map[k] = { kehu_name: r.kehu_name || '', ying_shou: 0, yi_shou: 0, wei_shou: 0, yu_shou: 0 };
        map[k].ying_shou += r.amount;
        map[k].yi_shou += r.amount;
      }
      return json(Object.values(map));
    }

    if (sub === 'by-customer') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) {
        const k = r.kehu_id || r.kehu_name || 'unknown';
        if (!map[k]) map[k] = { kehu_name: r.kehu_name || '', salesperson: r.salesperson || '', sk_count: 0, sk_amount: 0, ar_total: 0, ar_paid: 0, ar_unpaid: 0, count: 0, total: 0 };
        map[k].sk_count++; map[k].sk_amount += r.amount; map[k].ar_total += r.amount; map[k].ar_paid += r.amount; map[k].count++; map[k].total += r.amount;
        const m = Number((String(r.date || '').slice(5, 7) || '0')); if (m >= 1 && m <= 12) map[k]['m' + m] = (map[k]['m' + m] || 0) + r.amount;
      }
      return json(Object.values(map));
    }

    if (sub === 'by-dept') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) {
        const k = r.dept || '未分部门';
        if (!map[k]) map[k] = { department: k, sk_count: 0, sk_amount: 0 };
        map[k].sk_count++; map[k].sk_amount += r.amount;
        const m = Number((String(r.date || '').slice(5, 7) || '0')); if (m >= 1 && m <= 12) map[k]['m' + m] = (map[k]['m' + m] || 0) + r.amount;
      }
      return json(Object.values(map));
    }

    if (sub === 'by-item') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) {
        const k = r.item_name || '未分类';
        if (!map[k]) map[k] = { item: k, count: 0, amount: 0 };
        map[k].count++; map[k].amount += r.amount;
      }
      return json(Object.values(map));
    }

    if (sub === 'daily-summary') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) { const k = dayKey(r.date); if (!map[k]) map[k] = { date: k, sk_count: 0, sk_amount: 0, income: 0, balance: 0 }; map[k].sk_count++; map[k].sk_amount += r.amount; map[k].income += r.amount; }
      const arr = Object.values(map).sort((a, b) => a.date.localeCompare(b.date));
      let running = 0; for (const r of arr) { r.balance = r.income; running += r.balance; r.running_balance = running; r.type = '收款汇总'; r.amount = r.balance; }
      return json(arr);
    }

    if (sub === 'monthly-summary' || sub === 'trend') {
      const { skRows } = await readTx();
      const map = {};
      for (const r of skRows.filter(inRange)) { const k = monthKey(r.date); if (!map[k]) map[k] = { month: k, income: 0, net: 0, ar: 0, balance: 0 }; map[k].income += r.amount; map[k].ar += r.amount; map[k].balance += r.amount; }
      const arr = Object.values(map).sort((a, b) => a.month.localeCompare(b.month));
      for (const r of arr) { r.net = r.income; }
      return json(arr);
    }

    const skRows = await DB.prepare(`SELECT substr(shoukuan_date,1,7) as month, COUNT(*) as count, SUM(amount) as amount FROM shoukuan WHERE shoukuan_date LIKE ?1 GROUP BY substr(shoukuan_date,1,7) ORDER BY month`).bind(`${year}%`).all().catch(() => ({ results: [] }));

    const byMonth = {};
    for (const r of skRows.results || []) { byMonth[r.month] = { month: r.month, sk_count: r.count, sk_amount: r.amount || 0, income: r.amount || 0, balance: r.amount || 0 }; }
    const monthly = Object.values(byMonth).sort((a, b) => a.month.localeCompare(b.month));
    const totalSkAmount = monthly.reduce((s, m) => s + m.sk_amount, 0);

    return json({ success: true, year, monthly, totalSkAmount, totalIncome: totalSkAmount });
  } catch (e) {
    return json({ success: true, year, monthly: [], totalSkAmount: 0, totalIncome: 0 });
  }
}

// ============ 错误报告 ============
async function handleErrorReport(context) {
  const { request, body } = context;
  if (request.method === 'POST') {
    return json({ success: true, message: '错误已记录' });
  }
  return json({ success: true, list: [] });
}

// ============ 客户管理 (handleKehu) — 含审计日志 ============
const FIELD_MAP = {
  name: 'company', company: 'company', code: 'code', type: 'type',
  phone: 'phone', mobile: 'mobile', address: 'address', contact: 'contact',
  salesperson: 'manager', manager: 'manager', notes: 'remark', remark: 'remark',
  tax_no: 'tax_no', yw_beg: 'start_date', start_date: 'start_date',
};

async function ensureKehuSchema(DB) {
  try { await DB.prepare(`CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, company TEXT, created_at TEXT, updated_at TEXT)`).run(); } catch (_) {}
  const cols = ['company TEXT','name TEXT','code TEXT','type TEXT','phone TEXT','mobile TEXT','address TEXT','contact TEXT','manager TEXT','remark TEXT','tax_no TEXT','start_date TEXT','charge_type TEXT','amount REAL','charge_interval TEXT','status TEXT','extra_data TEXT','created_at TEXT','updated_at TEXT'];
  for (const c of cols) { try { await DB.prepare(`ALTER TABLE customers ADD COLUMN ${c}`).run(); } catch (_) {} }
}

function toKehuFormat(row) {
  if (!row) return null;
  let extra = {};
  try { extra = row.extra_data ? JSON.parse(row.extra_data) : {}; } catch (_) { extra = {}; }
  return { id: row.id, code: row.code || extra.code || '', name: row.company || '', type: row.type || '', phone: row.phone || '', mobile: row.mobile || extra.mobile || '', address: row.address || extra.address || '', contact: row.contact || '', salesperson: row.manager || extra.salesperson || '', notes: row.remark || extra.notes || '', tax_no: row.tax_no || extra.tax_no || '', qiyeleixing: extra.qiyeleixing || '', yw_beg: row.start_date || extra.yw_beg || '', yw_end: extra.yw_end || '', ...extra };
}

async function handleKehu(context) {
  const { request, env, id, body, query } = context;
  const DB = env.DB;
  const method = request.method;
  if (method === 'POST' && id === 'import') return handleKehuImport(DB, body);
  switch (method) {
    case 'GET': return id ? getKehuById(DB, id) : listKehu(DB, query);
    case 'POST': return createKehu(context);
    case 'PUT': return id ? updateKehu(context, id, body) : error('缺少客户ID');
    case 'DELETE': return id ? removeKehu(context, id) : error('缺少客户ID');
    default: return error('不支持的请求方法', 405);
  }
}

async function listKehu(DB, query) {
  await ensureKehuSchema(DB);
  const search = query?.search || query?.keyword || '';
  const kehuType = query?.type || '';
  const hideDisabled = String(query?.hide_disabled || query?.hideDisabled || '').toLowerCase() === '1' || String(query?.hide_disabled || query?.hideDisabled || '').toLowerCase() === 'true';
  const page = Math.max(1, parseInt(query?.page) || 1);
  const limit = Math.min(1000, Math.max(1, parseInt(query?.limit) || parseInt(query?.pageSize) || 50));
  const offset = (page - 1) * limit;
  const orderBy = `ORDER BY CASE WHEN code GLOB '[0-9]*' THEN CAST(code AS INTEGER) ELSE 999999999 END ASC, code ASC, created_at ASC`;
  if (search || hideDisabled) {
    try {
      const rows = await DB.prepare(`SELECT * FROM customers ${orderBy} LIMIT 5000`).all();
      const keyword = String(search).toLowerCase();
      const filtered = (rows.results || [])
        .map(row => ({ row, data: toKehuFormat(row) }))
        .filter(item => !hideDisabled || (!isInactiveCustomer(item.row) && !isInactiveCustomer(item.data)))
        .map(item => item.data)
        .filter(r => (!kehuType || r.type === kehuType) && (!keyword || ['name', 'company', 'contact', 'phone', 'mobile', 'code'].some(k => String(r[k] || '').toLowerCase().includes(keyword))));
      return json({ success: true, list: filtered.slice(offset, offset + limit), total: filtered.length });
    } catch (e) {
      return json({ success: true, list: [], total: 0 });
    }
  }
  const conditions = [], params = [];
  let p = 1;
  if (kehuType) { conditions.push(`type = ?${p}`); params.push(kehuType); p++; }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const limitIdx = params.length + 1, offsetIdx = params.length + 2;
    const [rows, countR] = await Promise.all([
      DB.prepare(`SELECT * FROM customers ${where} ${orderBy} LIMIT ?${limitIdx} OFFSET ?${offsetIdx}`).bind(...params, limit, offset).all(),
      DB.prepare(`SELECT COUNT(*) as total FROM customers ${where}`).bind(...params).first(),
    ]);
    return json({ success: true, list: (rows.results || []).map(toKehuFormat), total: countR?.total || 0 });
  } catch (e) { return json({ success: true, list: [], total: 0 }); }
}

async function getKehuById(DB, id) {
  await ensureKehuSchema(DB);
  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  if (!row) return error('客户不存在', 404);
  return json({ success: true, ...toKehuFormat(row) });
}

function monthValueForPlan(value, fallback = '') {
  const raw = String(value || fallback || '').trim();
  const m = raw.match(/^(\d{4})-(\d{1,2})/);
  if (!m) return raw;
  return `${m[1]}-${String(Number(m[2])).padStart(2, '0')}`;
}

async function syncKehuPaymentPlans(DB, customerId, companyName, body) {
  if (!body || !Array.isArray(body.sk_items)) return;
  await ensurePaymentPlansSchema(DB);
  await DB.prepare('DELETE FROM payment_plans WHERE kehu_id = ?1').bind(customerId).run().catch(() => {});
  const now = new Date().toISOString();
  for (const item of body.sk_items) {
    if (!item || typeof item !== 'object') continue;
    const itemName = item.project_name || item.item_name || item.item_code || '';
    const amount = dashboardNumber(item.amount_per || item.month_amount || item.amount);
    if (!itemName && amount <= 0) continue;
    const interval = Math.max(1, parseInt(item.interval_months || item.month_interval || item.period || item.interval || 12) || 12);
    const startMonth = monthValueForPlan(item.start_month || item.period_start || item.start_date || item.contract_start, body.yw_beg || body.start_date || '');
    const endMonth = monthValueForPlan(item.end_month || item.period_end || item.end_date || item.contract_end, body.yw_end || '2222-12');
    await DB.prepare(`INSERT INTO payment_plans (kehu_id, kehu_name, item_name, start_month, end_month, interval_months, amount_per, notes, next_due, customer_code, created_at, updated_at)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`)
      .bind(customerId, companyName, itemName, startMonth, endMonth, String(interval), amount, item.notes || '', startMonth, body.code || '', now, now).run();
  }
}

async function createKehu(context) {
  const { env, body } = context;
  const DB = env.DB;
  await ensureKehuSchema(DB);
  const companyName = body.name || body.company || '';
  if (!companyName) return error('客户名称为必填项');
  const id = Date.now();
  const now = new Date().toISOString();
  const knownKeys = new Set(['name','company','code','type','phone','mobile','address','contact','salesperson','manager','notes','remark','tax_no','yw_beg','start_date']);
  const extra = {};
  for (const k of Object.keys(body)) { if (!knownKeys.has(k) && body[k] !== undefined && body[k] !== null && body[k] !== '') extra[k] = body[k]; }
  if (!extra.yw_end) extra.yw_end = '2222-12-31';
  await DB.prepare(`INSERT INTO customers (id, company, name, code, type, phone, mobile, address, contact, manager, remark, tax_no, start_date, extra_data, created_at, updated_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)`)
    .bind(id, companyName, companyName, body.code || '', body.type || '', body.phone || '', body.mobile || '', body.address || '', body.contact || '', body.salesperson || body.manager || '', body.notes || body.remark || '', body.tax_no || '', body.yw_beg || body.start_date || '', JSON.stringify(extra), now, now).run();
  await syncKehuPaymentPlans(DB, id, companyName, body).catch(() => {});
  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();

  await auditLog(DB, context.userId, 'kehu_create', 'customers', companyName, context._clientIp);

  return json({ success: true, ...toKehuFormat(row) }, 201);
}

async function updateKehu(context, id, body) {
  const { env } = context;
  const DB = env.DB;
  await ensureKehuSchema(DB);
  const existing = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  if (!existing) return error('客户不存在', 404);
  const companyName = body.name || body.company || existing.company || '';
  const now = new Date().toISOString();
  const sets = [], values = [];
  let idx = 1;
  for (const [frontKey, colName] of Object.entries(FIELD_MAP)) {
    if (body[frontKey] !== undefined && body[frontKey] !== null) { sets.push(`${colName} = ?${idx}`); values.push(String(body[frontKey])); idx++; }
  }
  const knownKeys = new Set(['name','company','code','type','phone','mobile','address','contact','salesperson','manager','notes','remark','tax_no','yw_beg','start_date']);
  const existingExtra = existing.extra_data ? JSON.parse(existing.extra_data) : {};
  const newExtra = { ...existingExtra };
  for (const k of Object.keys(body)) { if (!knownKeys.has(k) && body[k] !== undefined && body[k] !== null) { if (body[k] === '') delete newExtra[k]; else newExtra[k] = body[k]; } }
  sets.push(`extra_data = ?${idx}`); values.push(JSON.stringify(newExtra)); idx++;
  if (!sets.length) return error('没有需要更新的字段');
  sets.push(`updated_at = ?${idx}`); values.push(now); idx++; values.push(id);
  await DB.prepare(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?${idx}`).bind(...values).run();
  await syncKehuPaymentPlans(DB, id, companyName, body).catch(() => {});
  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();

  await auditLog(DB, context.userId, 'kehu_update', 'customers', companyName, context._clientIp);

  return json({ success: true, ...toKehuFormat(row) });
}

async function removeKehu(context, id) {
  const { env } = context;
  const DB = env.DB;
  await ensureKehuSchema(DB);
  const existing = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  if (!existing) return error('客户不存在', 404);
  await DB.prepare('DELETE FROM customers WHERE id = ?1').bind(id).run();
  await ensurePaymentPlansSchema(DB).then(() => DB.prepare('DELETE FROM payment_plans WHERE kehu_id = ?1').bind(id).run()).catch(() => {});

  await auditLog(DB, context.userId, 'kehu_delete', 'customers', existing.company || id, context._clientIp);

  return json({ success: true, message: '已删除' });
}

async function handleKehuImport(DB, body) {
  await ensureKehuSchema(DB);
  const customers = body?.customers || [];
  const skipDup = body?.skipDup !== false;
  const updateDup = body?.updateDup === true;
  if (!Array.isArray(customers) || customers.length === 0) return json({ inserted: 0, skipped: 0, errors: 0, importErrors: ['无有效数据'] });
  let inserted = 0, skipped = 0, errors = 0;
  const importErrors = [];
  const now = new Date().toISOString();
  for (let i = 0; i < customers.length; i++) {
    const c = customers[i];
    const companyName = (c.name || c.company || '').trim();
    if (!companyName) { skipped++; importErrors.push({ row: i + 1, msg: '名称为空' }); continue; }
    try {
      const existing = await DB.prepare('SELECT id FROM customers WHERE company = ?1').bind(companyName).first();
      if (existing) {
        if (skipDup && !updateDup) { skipped++; continue; }
        if (updateDup) {
          const existingRow = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(existing.id).first();
          const knownKeys = new Set(['name','company','code','type','phone','mobile','address','contact','salesperson','manager','notes','remark','tax_no','yw_beg','start_date']);
          const existingExtra = existingRow.extra_data ? JSON.parse(existingRow.extra_data) : {};
          const newExtra = { ...existingExtra };
          for (const k of Object.keys(c)) { if (!knownKeys.has(k) && c[k] !== undefined && c[k] !== null && c[k] !== '') newExtra[k] = c[k]; }
          if (!newExtra.yw_end) newExtra.yw_end = '2222-12-31';
          await DB.prepare(`UPDATE customers SET company=?1, name=?2, code=?3, type=?4, phone=?5, mobile=?6, address=?7, contact=?8, manager=?9, remark=?10, tax_no=?11, start_date=?12, extra_data=?13, updated_at=?14 WHERE id=?15`)
            .bind(companyName, companyName, (c.code || existingRow.code || ''), (c.type || existingRow.type || ''), (c.phone || existingRow.phone || ''), (c.mobile || existingRow.mobile || ''), (c.address || existingRow.address || ''), (c.contact || existingRow.contact || ''), (c.salesperson || c.manager || existingRow.manager || ''), (c.notes || c.remark || existingRow.remark || ''), (c.tax_no || existingRow.tax_no || ''), (c.yw_beg || c.start_date || existingRow.start_date || ''), JSON.stringify(newExtra), now, existing.id).run();
          inserted++; continue;
        }
      }
      const id = Date.now() + i;
      const knownKeys = new Set(['name','company','code','type','phone','mobile','address','contact','salesperson','manager','notes','remark','tax_no','yw_beg','start_date']);
      const extra = {};
      for (const k of Object.keys(c)) { if (!knownKeys.has(k) && c[k] !== undefined && c[k] !== null && c[k] !== '') extra[k] = c[k]; }
      await DB.prepare(`INSERT INTO customers (id, company, name, code, type, phone, mobile, address, contact, manager, remark, tax_no, start_date, extra_data, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)`)
        .bind(id, companyName, companyName, (c.code || '').trim(), (c.type || '').trim(), (c.phone || '').trim(), (c.mobile || '').trim(), (c.address || '').trim(), (c.contact || '').trim(), (c.salesperson || c.manager || '').trim(), (c.notes || c.remark || '').trim(), (c.tax_no || '').trim(), (c.yw_beg || c.start_date || '').trim(), JSON.stringify(extra), now, now).run();
      inserted++;
    } catch (e) { errors++; importErrors.push({ row: i + 1, msg: e.message }); }
  }
  return json({ inserted, skipped, errors, importErrors });
}
