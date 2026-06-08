/**
 * 收款 (shoukuan) API - 完整 CRUD + 统计
 * 表: shoukuan
 */

let CURRENT_ORIGIN = 'https://skgl.pages.dev';
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

async function ensureSchema(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS shoukuan (
    id INTEGER PRIMARY KEY,
    sheet_no TEXT, kehu_id INTEGER, customer_code TEXT, kehu_name TEXT,
    amount REAL, method TEXT, shoukuan_date TEXT, biz_date TEXT,
    period_start TEXT, period_end TEXT, salesperson TEXT,
    account_code TEXT, item_code TEXT, item_name TEXT, dept TEXT,
    notes TEXT, notes2 TEXT, invoice_no TEXT, invoice_date TEXT,
    created_at TEXT, updated_at TEXT
  )`).run();
  await migrateLegacyShoukuanTable(DB);
  const cols = ['sheet_no TEXT','kehu_id INTEGER','customer_code TEXT','kehu_name TEXT','amount REAL','method TEXT','shoukuan_date TEXT','biz_date TEXT','period_start TEXT','period_end TEXT','salesperson TEXT','account_code TEXT','item_code TEXT','item_name TEXT','dept TEXT','notes TEXT','notes2 TEXT','invoice_no TEXT','invoice_date TEXT','created_at TEXT','updated_at TEXT'];
  for (const col of cols) {
    try { await DB.prepare(`ALTER TABLE shoukuan ADD COLUMN ${col}`).run(); } catch (_) {}
  }
}

async function migrateLegacyShoukuanTable(DB) {
  const info = await DB.prepare('PRAGMA table_info(shoukuan)').all().catch(() => ({ results: [] }));
  const idCol = (info.results || []).find((c) => c.name === 'id');
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

export default async function onRequest(context) {
  CURRENT_ORIGIN = context.request.headers.get('Origin') || new URL(context.request.url).origin || CURRENT_ORIGIN;
  const { request, env, id, body } = context;
  const DB = env.DB;
  const method = request.method;

  await ensureSchema(DB);

  // 特殊路由
  if (method === 'GET' && id === 'stats') {
    return handleStats(DB, context.query);
  }
  if (method === 'POST' && id === 'batch-invoice') {
    return handleBatchInvoice(DB, body);
  }

  switch (method) {
    case 'GET': return id ? getOne(DB, id) : listShoukuan(DB, context.query);
    case 'POST': return create(DB, body, context);
    case 'PUT': return id ? update(DB, id, body, context) : err('缺少记录ID');
    case 'DELETE': return id ? remove(DB, id, context) : err('缺少记录ID');
    default: return err('不支持的请求方法', 405);
  }
}

async function listShoukuan(DB, query) {
  const page = Math.max(1, parseInt(query?.page) || 1);
  const pageSize = Math.min(1000, Math.max(1, parseInt(query?.pageSize) || 20));
  const offset = (page - 1) * pageSize;

  const conditions = [], params = [];
  let pIdx = 1;
  if (query?.custId) {
    conditions.push(`kehu_id = ?${pIdx}`); params.push(parseInt(query.custId)); pIdx++;
  }
  if (query?.startDate) {
    conditions.push(`shoukuan_date >= ?${pIdx}`); params.push(query.startDate); pIdx++;
  }
  if (query?.endDate) {
    conditions.push(`shoukuan_date <= ?${pIdx}`); params.push(query.endDate); pIdx++;
  }
  if (query?.keyword) {
    conditions.push(`(kehu_name LIKE ?${pIdx} OR notes LIKE ?${pIdx} OR sheet_no LIKE ?${pIdx})`);
    params.push(`%${query.keyword}%`); pIdx++;
  }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  const [rows, countR] = await Promise.all([
    DB.prepare(`SELECT * FROM shoukuan ${where} ORDER BY shoukuan_date DESC, id DESC LIMIT ?${pIdx} OFFSET ?${pIdx + 1}`)
      .bind(...params, pageSize, offset).all(),
    DB.prepare(`SELECT COUNT(*) as total FROM shoukuan ${where}`).bind(...params).first(),
  ]);

  return json({ success: true, list: rows.results || [], total: countR?.total || 0 });
}

async function getOne(DB, id) {
  const row = await DB.prepare('SELECT * FROM shoukuan WHERE id = ?1').bind(id).first();
  if (!row) return err('记录不存在', 404);
  return json({ success: true, ...row });
}

async function create(DB, body, context) {
  const sheetNo = body.sheet_no || ('SK' + Date.now());
  const now = new Date().toISOString();
  const result = await DB.prepare(`INSERT INTO shoukuan (sheet_no, kehu_id, customer_code, kehu_name, amount, method, shoukuan_date, biz_date, period_start, period_end, salesperson, account_code, item_code, item_name, dept, notes, notes2, created_at, updated_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)`).bind(
    sheetNo, body.kehu_id || 0, body.customer_code || '', body.kehu_name || '',
    body.amount || 0, body.method || '', body.shoukuan_date || '', body.biz_date || '',
    body.period_start || '', body.period_end || '', body.salesperson || '',
    body.account_code || '', body.item_code || '', body.item_name || '', body.dept || '',
    body.notes || '', body.notes2 || '', now, now).run();
  
  const row = await DB.prepare('SELECT * FROM shoukuan WHERE rowid = ?1').bind(result.meta?.last_row_id).first();
  if (context._auditLog) { try { await context._auditLog(DB, context.userId || '', 'create_sk', body.kehu_name || '', '金额:'+(body.amount||0)+' 日期:'+(body.shoukuan_date||''), context._clientIp || ''); } catch(_) {} }
  return json({ success: true, ...row }, 201);
}

async function update(DB, id, body, context) {
  const existing = await DB.prepare('SELECT * FROM shoukuan WHERE id = ?1').bind(id).first();
  if (!existing) return err('记录不存在', 404);
  const now = new Date().toISOString();
  
  const fields = ['sheet_no','kehu_id','customer_code','kehu_name','amount','method','shoukuan_date','biz_date','period_start','period_end','salesperson','account_code','item_code','item_name','dept','notes','notes2','invoice_no','invoice_date'];
  const sets = [], vals = [];
  let i = 1;
  for (const f of fields) {
    if (body[f] !== undefined) { sets.push(`${f}=?${i}`); vals.push(body[f]); i++; }
  }
  if (!sets.length) return err('无更新字段');
  sets.push(`updated_at=?${i}`); vals.push(now); i++;
  vals.push(id);
  await DB.prepare(`UPDATE shoukuan SET ${sets.join(',')} WHERE id=?${i}`).bind(...vals).run();
  const row = await DB.prepare('SELECT * FROM shoukuan WHERE id=?1').bind(id).first();
  if (context._auditLog) { try { await context._auditLog(DB, context.userId || '', 'update_sk', row?.kehu_name || existing.kehu_name || '', '收款ID:'+id, context._clientIp || ''); } catch(_) {} }
  return json({ success: true, ...row });
}

async function remove(DB, id, context) {
  const existing = await DB.prepare('SELECT * FROM shoukuan WHERE id = ?1').bind(id).first();
  if (!existing) return err('记录不存在', 404);
  await DB.prepare('DELETE FROM shoukuan WHERE id = ?1').bind(id).run();
  if (context._auditLog) { try { await context._auditLog(DB, context.userId || '', 'delete_sk', existing.kehu_name || '', '收款ID:'+id, context._clientIp || ''); } catch(_) {} }
  return json({ success: true, message: '已删除' });
}

async function handleStats(DB, query) {
  const year = query?.year || new Date().getFullYear();
  const rows = await DB.prepare(`SELECT * FROM shoukuan WHERE shoukuan_date LIKE ?1`).bind(`${year}%`).all();
  const list = rows.results || [];
  let totalAmount = 0;
  const methodMap = {};
  const monthMap = {};
  for (const r of list) {
    totalAmount += r.amount || 0;
    const m = r.method || '其他';
    if (!methodMap[m]) methodMap[m] = { method: m, total_amount: 0, count: 0 };
    methodMap[m].total_amount += r.amount || 0;
    methodMap[m].count += 1;
    const mo = (r.shoukuan_date || '').substring(0,7);
    if (mo) { if (!monthMap[mo]) monthMap[mo] = { month: mo, count: 0, total_amount: 0 }; monthMap[mo].count++; monthMap[mo].total_amount += r.amount || 0; }
  }
  const methodStats = Object.values(methodMap);
  const monthStats = Object.values(monthMap).sort((a,b) => a.month.localeCompare(b.month));
  return json({ success: true, totalAmount, methodStats, monthStats, total: list.length });
}

async function handleBatchInvoice(DB, body) {
  const beforeDate = body?.before_date;
  if (!beforeDate) return err('缺少截止日期');
  const result = await DB.prepare(
    `UPDATE shoukuan SET invoice_date = shoukuan_date, invoice_no = COALESCE(invoice_no, sheet_no) WHERE shoukuan_date <= ?1 AND (invoice_date IS NULL OR invoice_date = '')`
  ).bind(beforeDate).run();
  return json({ success: true, updated: result.meta?.changes || 0, message: `已标记 ${result.meta?.changes || 0} 条记录为已开票` });
}
