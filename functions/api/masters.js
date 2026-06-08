/**
 * 主子模块 API: accounts/departments/prospects/users/payment-plans/tixing
 */

let CURRENT_ORIGIN = 'https://skgl.pages.dev';
const SUPER_ADMIN_PHONE = '13399330020';
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': CURRENT_ORIGIN,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
  };
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0', 'Pragma': 'no-cache', 'Expires': '0' },
  });
}
function err(msg, status = 400) {
  return json({ success: false, error: msg }, status);
}
function now() { return new Date().toISOString(); }
function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}
function validPhone(phone) {
  return /^1\d{10}$/.test(phone);
}
function isDisabledValue(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'disabled' || v === '停用' || v === '禁用' || v === '离职';
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPasswordPBKDF2(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return `${bytesToHex(salt)}:${bytesToHex(new Uint8Array(hash))}`;
}

// 通用 CRUD 工厂
function makeCrud(table, fields, opts = {}) {
  const { extraCreate = [], extraUpdate = [], pk = 'id', defaultValues = {}, sanitize = (row) => row, maxPageSize = 1000 } = opts;
  const allFields = [pk, ...fields];
  const dataFields = [...fields, ...extraCreate];

  function normalizeBody(body = {}) {
    const next = { ...body };
    if (table === 'accounts') {
      if (next.opening_balance !== undefined && next.balance === undefined) next.balance = next.opening_balance;
      if (next.currency !== undefined && next.notes === undefined) next.notes = next.currency;
    }
    if (table === 'prospects') {
      if (next.contact_date !== undefined && next.date === undefined) next.date = next.contact_date;
      if (next.status !== undefined && next.type === undefined) next.type = next.status;
      if (next.requirement !== undefined && next.intent === undefined) next.intent = next.requirement;
      if (next.customer_code !== undefined && next.phone === undefined) next.phone = next.customer_code;
    }
    return next;
  }

  function normalizeRow(row) {
    const safe = sanitize(row);
    if (!safe || typeof safe !== 'object') return safe;
    if (table === 'accounts') {
      safe.opening_balance = safe.balance ?? 0;
      safe.currency = safe.notes || '';
    }
    if (table === 'prospects') {
      safe.contact_date = safe.date || '';
      safe.status = safe.type || '';
      safe.requirement = safe.intent || '';
      safe.customer_code = safe.phone || safe.customer_code || '';
    }
    return safe;
  }

  async function ensureTable(DB) {
    const defs = { id: 'INTEGER PRIMARY KEY', kehu_id: 'INTEGER', amount: 'REAL', paid: 'REAL DEFAULT 0', quantity: 'INTEGER DEFAULT 1', year: 'INTEGER', sort: 'INTEGER DEFAULT 0' };
    const cols = allFields.map(f => {
      if (defs[f]) return `${f} ${defs[f]}`;
      return `${f} TEXT`;
    });
    cols.push('created_at TEXT', 'updated_at TEXT');
    await DB.prepare(`CREATE TABLE IF NOT EXISTS ${table} (${cols.join(', ')})`).run();
    // 补齐旧表缺失的列
    for (const colDef of cols) {
      try { await DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${colDef}`).run(); } catch (_) {}
    }
  }

  return {
    table, fields: dataFields,
    async list(DB, query = {}) {
      const page = Math.max(1, parseInt(query.page) || 1);
      const pageSize = Math.min(maxPageSize, Math.max(1, parseInt(query.pageSize) || 20));
      const offset = (page - 1) * pageSize;
      const conditions = [], params = [];
      let p = 1;
      if (query.kehu_id) { conditions.push(`kehu_id = ?${p}`); params.push(parseInt(query.kehu_id)); p++; }
      if (query.year) { conditions.push(`year = ?${p}`); params.push(parseInt(query.year)); p++; }
      if (query.type) { conditions.push(`type = ?${p}`); params.push(query.type); p++; }
      if (query.status) { conditions.push(`status = ?${p}`); params.push(query.status); p++; }
      if (query.keyword) { conditions.push(`(name LIKE ?${p} OR kehu_name LIKE ?${p} OR notes LIKE ?${p})`); params.push(`%${query.keyword}%`); p++; }
      const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
      const orderBy = table === 'departments' ? 'ORDER BY sort ASC, id ASC' : 'ORDER BY id DESC';
      const [rows, countR] = await Promise.all([
        DB.prepare(`SELECT * FROM ${table} ${where} ${orderBy} LIMIT ?${p} OFFSET ?${p + 1}`).bind(...params, pageSize, offset).all(),
        DB.prepare(`SELECT COUNT(*) as total FROM ${table} ${where}`).bind(...params).first(),
      ]);
      const list = (rows.results || []).map(normalizeRow);
      return json({ success: true, list, data: list, total: countR?.total || 0 });
    },

    async get(DB, id) {
      const row = await DB.prepare(`SELECT * FROM ${table} WHERE ${pk} = ?1`).bind(id).first();
      if (!row) return err('记录不存在', 404);
      return json({ success: true, ...normalizeRow(row) });
    },

    async create(DB, body) {
      body = normalizeBody(body);
      if (table === 'users' && String(body.phone || '') === SUPER_ADMIN_PHONE) body.role = 'admin';
      if (table === 'users' && body.password && !body.password_hash) {
        body.password_hash = await hashPasswordPBKDF2(String(body.password));
        body.salt = '';
      }
      const n = now();
      const placeholders = dataFields.map((_, i) => `?${i + 1}`).join(',');
      const vals = dataFields.map(f => body[f] !== undefined ? body[f] : '');
      // 部分表在 D1 中有 FK 约束但 ensureTable 创建的 schema 不包含，临时关闭 FK 校验
      await DB.prepare('PRAGMA foreign_keys = OFF').run();
      const result = await DB.prepare(`INSERT INTO ${table} (${dataFields.join(',')}, created_at, updated_at) VALUES (${placeholders},?${dataFields.length + 1},?${dataFields.length + 2})`)
        .bind(...vals, n, n).run();
      await DB.prepare('PRAGMA foreign_keys = ON').run();
      const row = await DB.prepare(`SELECT * FROM ${table} WHERE rowid = ?1`).bind(result.meta?.last_row_id).first();
      return json({ success: true, ...normalizeRow(row) }, 201);
    },

    async update(DB, id, body) {
      body = normalizeBody(body);
      if (table === 'users' && String(body.phone || '') === SUPER_ADMIN_PHONE) body.role = 'admin';
      if (table === 'users' && body.password && !body.password_hash) {
        body.password_hash = await hashPasswordPBKDF2(String(body.password));
        body.salt = '';
      }
      const existing = await DB.prepare(`SELECT * FROM ${table} WHERE ${pk} = ?1`).bind(id).first();
      if (!existing) return err('记录不存在', 404);
      const n = now();
      const sets = [], vals = [];
      let i = 1;
      for (const f of fields) {
        if (body[f] !== undefined) { sets.push(`${f}=?${i}`); vals.push(body[f]); i++; }
      }
      if (!sets.length) return err('无更新字段');
      sets.push(`updated_at=?${i}`); vals.push(n); i++; vals.push(id);
      await DB.prepare(`UPDATE ${table} SET ${sets.join(',')} WHERE ${pk}=?${i}`).bind(...vals).run();
      const row = await DB.prepare(`SELECT * FROM ${table} WHERE ${pk}=?1`).bind(id).first();
      return json({ success: true, ...normalizeRow(row) });
    },

    async remove(DB, id) {
      if (await DB.prepare(`SELECT * FROM ${table} WHERE ${pk} = ?1`).bind(id).first()) {
        await DB.prepare(`DELETE FROM ${table} WHERE ${pk} = ?1`).bind(id).run();
        return json({ success: true, message: '已删除' });
      }
      return err('记录不存在', 404);
    },

    ensureTable,
  };
}

// 模块定义
function sanitizeUser(row) {
  if (!row) return row;
  const safe = { ...row };
  if (String(safe.phone || '') === SUPER_ADMIN_PHONE) safe.role = 'admin';
  delete safe.password;
  delete safe.password_hash;
  delete safe.salt;
  return safe;
}

const MODULES = {
  accounts: makeCrud('accounts', ['code', 'name', 'help_code', 'balance', 'notes']),
  departments: makeCrud('departments', ['code', 'name', 'help_code', 'sort', 'parent_code'], { pk: 'id' }),
  prospects: makeCrud('prospects', ['date', 'type', 'name', 'phone', 'source', 'intent', 'notes', 'last_follow', 'follow_count'], { pk: 'id' }),
  users: makeCrud('users', ['phone', 'name', 'role', 'notes', 'register_time', 'username', 'disabled', 'password_hash', 'salt'], { pk: 'id', defaultValues: { disabled: 'false' }, sanitize: sanitizeUser }),
  'payment-plans': makeCrud('payment_plans', ['kehu_id', 'kehu_name', 'item_name', 'start_month', 'end_month', 'interval_months', 'amount_per', 'notes', 'next_due', 'customer_code'], { pk: 'id' }),
  tixing: makeCrud('tixing', ['kehu_id', 'kehu_name', 'remind_date', 'content', 'status', 'customer_code'], { pk: 'id' }),
};

async function ensurePermsTable(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS user_permissions (id INTEGER PRIMARY KEY, use_id INTEGER, module TEXT, created_at TEXT)`).run();
}

async function ensureTenantMemberSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    phone TEXT,
    tenant_id TEXT,
    id_card TEXT,
    id_card_hash TEXT,
    password_hash TEXT,
    salt TEXT,
    role TEXT,
    created_at TEXT,
    name TEXT,
    disabled TEXT,
    must_change_password TEXT
  )`).run().catch(() => {});
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
  const userCols = ['phone TEXT','username TEXT','tenant_id TEXT','id_card TEXT','id_card_hash TEXT','password_hash TEXT','salt TEXT','role TEXT','created_at TEXT','name TEXT','disabled TEXT','must_change_password TEXT'];
  for (const col of userCols) { try { await DB.prepare(`ALTER TABLE users ADD COLUMN ${col}`).run(); } catch (_) {} }
  const tenantCols = ['name TEXT','owner_user_id TEXT','status TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of tenantCols) { try { await DB.prepare(`ALTER TABLE tenants ADD COLUMN ${col}`).run(); } catch (_) {} }
  const memberCols = ['tenant_id TEXT','user_id INTEGER','phone TEXT','name TEXT','role TEXT','disabled TEXT','notes TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of memberCols) { try { await DB.prepare(`ALTER TABLE tenant_members ADD COLUMN ${col}`).run(); } catch (_) {} }
}

function userPublicRow(user, member, tenantInfo = {}) {
  const role = String(user?.phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (member?.role || user?.role || 'user');
  const disabled = isDisabledValue(user?.disabled) ? 'true' : (member?.disabled || user?.disabled || 'false');
  return {
    id: user.id,
    member_id: member?.id || '',
    phone: user.phone || member?.phone || '',
    username: user.phone || member?.phone || '',
    name: member?.name || user.name || '',
    role,
    disabled,
    notes: member?.notes || '',
    created_at: member?.created_at || user.created_at || '',
    must_change_password: user.must_change_password || 'false',
    tenant_count: tenantInfo.count || 0,
    tenant_names: tenantInfo.names || '',
  };
}

async function tenantInfoForUser(DB, userId) {
  const rows = await DB.prepare(`SELECT COALESCE(t.name, m.tenant_id) AS name
    FROM tenant_members m
    LEFT JOIN tenants t ON t.id = m.tenant_id
    WHERE m.user_id = ?1 AND COALESCE(m.disabled,'') NOT IN ('1','true','disabled','停用','禁用')
    ORDER BY m.id ASC LIMIT 20`).bind(userId).all().catch(() => ({ results: [] }));
  const names = (rows.results || []).map(r => String(r.name || '').trim()).filter(Boolean);
  return { count: names.length, names: names.join('，') };
}

async function handleTenantUsers(context) {
  const rawDB = context.rawEnv?.DB || context.env.DB;
  const tenantId = String(context.tenantId || '');
  const method = context.request.method;
  const id = context.id;
  const body = context.body || {};
  if (!tenantId) return err('请先选择账套', 428);
  await ensureTenantMemberSchema(rawDB);

  if (method === 'GET' && id && context._segments?.[2] !== 'permissions') {
    const row = await rawDB.prepare(`SELECT u.*, m.id AS member_id, m.role AS member_role, m.disabled AS member_disabled, m.notes AS member_notes, m.name AS member_name, m.created_at AS member_created_at
      FROM tenant_members m JOIN users u ON u.id = m.user_id
      WHERE m.tenant_id = ?1 AND m.user_id = ?2 LIMIT 1`).bind(tenantId, id).first();
    if (!row) return err('用户不在当前账套中', 404);
    const tenantInfo = await tenantInfoForUser(rawDB, row.id);
    return json({ success: true, ...userPublicRow(row, { id: row.member_id, role: row.member_role, disabled: row.member_disabled, notes: row.member_notes, name: row.member_name, created_at: row.member_created_at }, tenantInfo) });
  }

  if (method === 'GET') {
    const rows = await rawDB.prepare(`SELECT u.*, m.id AS member_id, m.role AS member_role, m.disabled AS member_disabled, m.notes AS member_notes, m.name AS member_name, m.created_at AS member_created_at
      FROM tenant_members m JOIN users u ON u.id = m.user_id
      WHERE m.tenant_id = ?1
      ORDER BY m.id ASC`).bind(tenantId).all().catch(() => ({ results: [] }));
    const list = [];
    for (const row of rows.results || []) {
      const tenantInfo = await tenantInfoForUser(rawDB, row.id);
      list.push(userPublicRow(row, { id: row.member_id, role: row.member_role, disabled: row.member_disabled, notes: row.member_notes, name: row.member_name, created_at: row.member_created_at }, tenantInfo));
    }
    return json({ success: true, list, data: list, total: list.length });
  }

  if (method === 'POST' && id && context._segments?.[2] === 'reset-password') {
    const user = await rawDB.prepare('SELECT id, phone FROM users WHERE id = ?1').bind(id).first().catch(() => null);
    if (!user) return err('用户不存在', 404);
    if (String(user.phone || '') === SUPER_ADMIN_PHONE) return err('超级账号不能重置');
    const member = await rawDB.prepare('SELECT id FROM tenant_members WHERE tenant_id = ?1 AND user_id = ?2')
      .bind(tenantId, id).first().catch(() => null);
    if (!member) return err('用户不在当前账套中', 404);
    const passwordHash = await hashPasswordPBKDF2('123456');
    await rawDB.prepare('UPDATE users SET password_hash = ?1, must_change_password = ?2 WHERE id = ?3')
      .bind(passwordHash, 'true', id).run();
    return json({ success: true, message: '密码已重置为123456，下次登录必须修改', defaultPassword: '123456' });
  }

  if (method === 'POST') {
    const phone = normalizePhone(body.phone || body.username);
    const name = String(body.name || '').trim();
    const role = String(phone) === SUPER_ADMIN_PHONE ? 'admin' : (body.role || 'user');
    const notes = String(body.notes || '').trim();
    if (!validPhone(phone)) return err('手机号必须为11位数字');
    if (!name) return err('请输入姓名');
    let user = await rawDB.prepare('SELECT * FROM users WHERE phone = ?1').bind(phone).first().catch(() => null);
    const n = now();
    if (!user) {
      const passwordHash = await hashPasswordPBKDF2('123456');
      const result = await rawDB.prepare('INSERT INTO users (phone, username, name, password_hash, salt, role, disabled, must_change_password, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
        .bind(phone, phone, name, passwordHash, '', 'user', 'false', 'true', n).run();
      user = await rawDB.prepare('SELECT * FROM users WHERE id = ?1').bind(result.meta?.last_row_id).first();
    }
    const existing = await rawDB.prepare('SELECT id, disabled FROM tenant_members WHERE tenant_id = ?1 AND user_id = ?2')
      .bind(tenantId, user.id).first().catch(() => null);
    if (existing) {
      if (isDisabledValue(existing.disabled)) {
        await rawDB.prepare('UPDATE tenant_members SET disabled = ?1, role = ?2, name = ?3, notes = ?4, updated_at = ?5 WHERE id = ?6')
          .bind('false', role, name, notes, n, existing.id).run();
        return json({ success: true, message: '已重新启用该用户', defaultPassword: user.must_change_password === 'true' ? '123456' : '', ...userPublicRow(user, { id: existing.id, role, disabled: 'false', name, notes, created_at: n }) });
      }
      return err('该手机号已在当前账套中，请勿重复添加');
    }
    const memberResult = await rawDB.prepare('INSERT INTO tenant_members (tenant_id, user_id, phone, name, role, disabled, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
      .bind(tenantId, user.id, phone, name, role, 'false', notes, n, n).run();
    return json({ success: true, message: user.must_change_password === 'true' ? '新增成功，默认密码123456' : '授权成功', defaultPassword: user.must_change_password === 'true' ? '123456' : '', ...userPublicRow(user, { id: memberResult.meta?.last_row_id, role, disabled: 'false', name, notes, created_at: n }) }, 201);
  }

  if (method === 'PUT' && id) {
    const phone = normalizePhone(body.phone || body.username);
    const n = now();
    const member = await rawDB.prepare('SELECT * FROM tenant_members WHERE tenant_id = ?1 AND user_id = ?2')
      .bind(tenantId, id).first().catch(() => null);
    if (!member) return err('用户不在当前账套中', 404);
    const user = await rawDB.prepare('SELECT * FROM users WHERE id = ?1').bind(id).first();
    const role = String(user?.phone || phone || '') === SUPER_ADMIN_PHONE ? 'admin' : (body.role !== undefined ? body.role : member.role || 'user');
    const disabled = String(user?.phone || '') === SUPER_ADMIN_PHONE ? 'false' : (body.disabled !== undefined ? String(body.disabled) : member.disabled || 'false');
    const name = body.name !== undefined ? String(body.name || '').trim() : member.name || user?.name || '';
    const notes = body.notes !== undefined ? String(body.notes || '').trim() : member.notes || '';
    await rawDB.prepare('UPDATE tenant_members SET role = ?1, disabled = ?2, name = ?3, notes = ?4, updated_at = ?5 WHERE id = ?6')
      .bind(role, disabled, name, notes, n, member.id).run();
    if (name) await rawDB.prepare('UPDATE users SET name = COALESCE(NULLIF(name, ""), ?1) WHERE id = ?2').bind(name, id).run().catch(() => {});
    return json({ success: true, ...userPublicRow(user || { id, phone }, { id: member.id, role, disabled, name, notes, created_at: member.created_at }) });
  }

  if (method === 'DELETE' && id) {
    const user = await rawDB.prepare('SELECT phone FROM users WHERE id = ?1').bind(id).first().catch(() => null);
    if (String(user?.phone || '') === SUPER_ADMIN_PHONE) return err('超级账号不能停用');
    await rawDB.prepare('UPDATE tenant_members SET disabled = ?1, updated_at = ?2 WHERE tenant_id = ?3 AND user_id = ?4')
      .bind('true', now(), tenantId, id).run();
    return json({ success: true, message: '已停用' });
  }

  return err('不支持的用户操作', 405);
}

function monthAdd(month, interval) {
  const m = String(month || '').match(/^(\d{4})-(\d{1,2})/);
  if (!m) return '';
  const d = new Date(parseInt(m[1]), parseInt(m[2]) - 1, 1);
  d.setMonth(d.getMonth() + (parseInt(interval) || 1));
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}

async function ensureShoukuanTable(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS shoukuan (
    id INTEGER PRIMARY KEY,
    sheet_no TEXT, kehu_id INTEGER, customer_code TEXT, kehu_name TEXT,
    amount REAL, method TEXT, shoukuan_date TEXT, biz_date TEXT,
    period_start TEXT, period_end TEXT, salesperson TEXT, account_code TEXT,
    item_code TEXT, item_name TEXT, dept TEXT, notes TEXT, notes2 TEXT,
    invoice_no TEXT, invoice_date TEXT, created_at TEXT, updated_at TEXT
  )`).run();
  const cols = ['sheet_no TEXT','kehu_id INTEGER','customer_code TEXT','kehu_name TEXT','amount REAL','method TEXT','shoukuan_date TEXT','biz_date TEXT','period_start TEXT','period_end TEXT','salesperson TEXT','account_code TEXT','item_code TEXT','item_name TEXT','dept TEXT','notes TEXT','notes2 TEXT','invoice_no TEXT','invoice_date TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of cols) {
    try { await DB.prepare(`ALTER TABLE shoukuan ADD COLUMN ${col}`).run(); } catch (_) {}
  }
}

async function batchCollectPaymentPlans(DB, body, context) {
  const ids = Array.isArray(body?.ids) ? body.ids.map(id => parseInt(id)).filter(id => !isNaN(id)) : [];
  if (!ids.length) return err('请选择要收款的计划');

  await ensureShoukuanTable(DB);
  const today = body?.shoukuan_date || new Date().toISOString().slice(0, 10);
  const now = new Date().toISOString();
  let count = 0, total = 0;

  for (let i = 0; i < ids.length; i++) {
    const plan = await DB.prepare('SELECT * FROM payment_plans WHERE id = ?1').bind(ids[i]).first();
    if (!plan) continue;
    const amount = Number(plan.amount_per ?? plan.amount ?? 0);
    if (amount <= 0) continue;
    const periodStart = plan.next_due || plan.start_month || '';
    const periodEnd = periodStart;
    const sheetNo = 'SK' + today.replace(/-/g, '') + String(Date.now()).slice(-6) + String(i + 1).padStart(2, '0');
    await DB.prepare(`INSERT INTO shoukuan (sheet_no, kehu_id, customer_code, kehu_name, amount, method, shoukuan_date, biz_date, period_start, period_end, item_name, notes, created_at, updated_at)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)`).bind(
      sheetNo,
      plan.kehu_id || 0,
      plan.customer_code || '',
      plan.kehu_name || '',
      amount,
      body?.method || '批量收款',
      today,
      today,
      periodStart,
      periodEnd,
      plan.item_name || '',
      body?.notes || '收款生成',
      now,
      now
    ).run();

    const nextDue = monthAdd(periodStart || plan.start_month, plan.interval_months || 1);
    if (nextDue) {
      await DB.prepare('UPDATE payment_plans SET next_due = ?1, updated_at = ?2 WHERE id = ?3')
        .bind(nextDue, now, ids[i]).run();
    }
    count++;
    total += amount;
  }

  if (context && context._auditLog) {
    await context._auditLog(DB, context.userId || '', 'batch_collect', 'payment_plans', `数量:${count} 金额:${total}`, context._clientIp || '').catch(() => {});
  }
  return json({ success: true, message: `已批量收款 ${count} 条`, count, total });
}

export default async function onRequest(context) {
  CURRENT_ORIGIN = context.request.headers.get('Origin') || new URL(context.request.url).origin || CURRENT_ORIGIN;
  const { request, env, module, id, body } = context;
  const DB = env.DB;
  const method = request.method;

  // 操作员权限子路由
  if (module === 'users' && id && context._segments && context._segments[2] === 'permissions') {
    await ensurePermsTable(DB);
    if (method === 'GET') {
      const rows = await DB.prepare('SELECT module FROM user_permissions WHERE use_id = ?1').bind(parseInt(id)).all();
      return json({ success: true, list: rows.results || [] });
    }
    if (method === 'PUT') {
      const modules = body?.modules || [];
      await DB.prepare('DELETE FROM user_permissions WHERE use_id = ?1').bind(parseInt(id)).run();
      const n = now();
      for (const m of modules) {
        await DB.prepare('INSERT INTO user_permissions (use_id, module, created_at) VALUES (?1, ?2, ?3)').bind(parseInt(id), m, n).run();
      }
      return json({ success: true, message: '权限已保存' });
    }
    return err('不支持的操作', 405);
  }

  const mod = MODULES[module];
  if (!mod) return err(`未知模块: ${module}`, 404);

  if (module === 'users') return handleTenantUsers(context);

  await mod.ensureTable(DB);

  if (module === 'payment-plans' && method === 'POST' && id === 'batch-collect') {
    return batchCollectPaymentPlans(DB, body, context);
  }

  if (module === 'payment-plans' && method === 'GET' && !id && (context.query?.year || context.query?.month || context.query?.end_month)) {
    const rows = await DB.prepare('SELECT * FROM payment_plans ORDER BY next_due ASC, id DESC LIMIT 1000').all().catch(() => ({ results: [] }));
    let list = rows.results || [];
    if (context.query?.kehu_id) list = list.filter(r => String(r.kehu_id || '') === String(context.query.kehu_id));
    if (context.query?.end_month) list = list.filter(r => String(r.next_due || r.end_month || '') <= String(context.query.end_month));
    const monthlyMap = {};
    for (const r of list) {
      const key = `${r.kehu_id || r.kehu_name || ''}|${r.item_name || ''}`;
      if (!monthlyMap[key]) monthlyMap[key] = { kehu_id: r.kehu_id, kehu_name: r.kehu_name || '', project_name: r.item_name || '', item_name: r.item_name || '' };
      const monthText = String(r.next_due || r.start_month || '').slice(5, 7);
      const m = parseInt(monthText);
      if (m >= 1 && m <= 12) monthlyMap[key]['m' + m] = (monthlyMap[key]['m' + m] || 0) + Number(r.amount_per || 0);
    }
    return json({ success: true, list, data: list, monthly: Object.values(monthlyMap), total: list.length });
  }

  // 统计
  if (method === 'GET' && id === 'stats') {
    const rows = await DB.prepare(`SELECT * FROM ${mod.table}`).all();
    const list = rows.results || [];
    let totalAmount = 0;
    for (const r of list) { totalAmount += r.amount || 0; }
    return json({ success: true, totalAmount, total: list.length });
  }
  switch (method) {
    case 'GET': return id ? mod.get(DB, id) : mod.list(DB, context.query);
    case 'POST': return mod.create(DB, body);
    case 'PUT': return id ? mod.update(DB, id, body) : err('缺少记录ID');
    case 'DELETE': return id ? mod.remove(DB, id) : err('缺少记录ID');
    default: return err('不支持的请求方法', 405);
  }
}
