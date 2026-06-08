/**
 * 通用数据键值存储 API
 * 用于前端localStorage ↔ D1双向同步
 * GET    /api/data?key=xxx          - 获取单个key
 * GET    /api/data?keys=xxx,yyy     - 批量获取
 * POST   /api/data                  - 写入 {key, value}
 * POST   /api/data/batch            - 批量写入 [{key, value}, ...]
 * DELETE /api/data?key=xxx          - 删除
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
    headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function error(msg, status = 400) {
  return json({ success: false, error: msg }, status);
}

async function ensureTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS data_store (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT
    )
  `).run();
}

function scopedKey(DB, key) {
  const tenantId = DB && DB.tenantId ? String(DB.tenantId) : '';
  const raw = String(key || '');
  return tenantId ? `data:${tenantId}:${raw}` : raw;
}

function unscopedKey(DB, key) {
  const tenantId = DB && DB.tenantId ? String(DB.tenantId) : '';
  const raw = String(key || '');
  const head = tenantId ? `data:${tenantId}:` : '';
  return head && raw.startsWith(head) ? raw.slice(head.length) : raw;
}

export default async function dataHandler(context) {
  const { request, env, query, body } = context;
  CURRENT_ORIGIN = request.headers.get('Origin') || new URL(request.url).origin || CURRENT_ORIGIN;
  const DB = env.DB;
  const method = request.method;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/data\/?/, '');

  await ensureTable(DB);

  switch (method) {
    case 'GET':
      if (path === 'keys') return listKeys(DB, query);
      return query.keys
        ? getBatch(DB, query.keys)
        : query.key ? getOne(DB, query.key)
        : error('缺少 key 参数');
    case 'POST':
      if (path === 'batch') return setBatch(DB, body || {});
      return setOne(DB, body || {});
    case 'DELETE':
      return query.key ? delKey(DB, query.key) : error('缺少 key 参数');
    default:
      return error('不支持的请求方法', 405);
  }
}

async function getOne(DB, key) {
  const row = await DB.prepare('SELECT value FROM data_store WHERE key = ?1').bind(scopedKey(DB, key)).first();
  return json({ success: true, data: row ? row.value : null });
}

async function getBatch(DB, keysStr) {
  const keys = keysStr.split(',').map(k => k.trim()).filter(Boolean);
  if (keys.length === 0) return json({ success: true, data: {} });
  const dbKeys = keys.map(k => scopedKey(DB, k));
  
  const placeholders = dbKeys.map((_, i) => `?${i + 1}`).join(',');
  const rows = await DB.prepare(`SELECT key, value FROM data_store WHERE key IN (${placeholders})`)
    .bind(...dbKeys).all();
  
  const result = {};
  rows.results.forEach(r => { result[unscopedKey(DB, r.key)] = r.value; });
  keys.forEach(k => { if (!(k in result)) result[k] = null; });
  
  return json({ success: true, data: result });
}

async function listKeys(DB, query) {
  const prefix = query.prefix || '';
  const dbPrefix = scopedKey(DB, prefix);
  let rows;
  if (prefix) {
    rows = await DB.prepare('SELECT key FROM data_store WHERE key LIKE ?1 ORDER BY key')
      .bind(dbPrefix + '%').all();
  } else {
    rows = await DB.prepare('SELECT key FROM data_store ORDER BY key').all();
  }
  return json({ success: true, data: rows.results.map(r => unscopedKey(DB, r.key)) });
}

async function setOne(DB, body) {
  const { key, value } = body;
  if (!key) return error('缺少 key');

  await DB.prepare(`
    INSERT INTO data_store (key, value, updated_at) VALUES (?1, ?2, ?3)
    ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3
  `).bind(scopedKey(DB, key), value, new Date().toISOString()).run();

  return json({ success: true, key });
}

async function setBatch(DB, items) {
  if (!Array.isArray(items) || items.length === 0) return error('items 必须是非空数组');

  const now = new Date().toISOString();
  const stmts = items.map(item => 
    DB.prepare(`
      INSERT INTO data_store (key, value, updated_at) VALUES (?1, ?2, ?3)
      ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3
    `).bind(scopedKey(DB, item.key), item.value, now)
  );
  await DB.batch(stmts);

  return json({ success: true, count: items.length });
}

async function delKey(DB, key) {
  await DB.prepare('DELETE FROM data_store WHERE key = ?1').bind(scopedKey(DB, key)).run();
  return json({ success: true, key });
}
