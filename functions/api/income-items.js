/**
 * 收款项目（收入项目）API
 * GET    /api/income-items          - 列表（支持 ?pageSize=）
 * GET    /api/income-items/:id      - 详情
 * POST   /api/income-items          - 新增
 * PUT    /api/income-items/:id      - 修改
 * DELETE /api/income-items/:id      - 删除
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

// 确保 income_items 表存在
async function ensureTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS income_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT DEFAULT '',
      type_code TEXT DEFAULT '',
      category_code TEXT DEFAULT '',
      category_name TEXT DEFAULT '',
      name TEXT NOT NULL DEFAULT '',
      notes1 TEXT DEFAULT '',
      help_code TEXT DEFAULT '',
      flag TEXT DEFAULT 'S',
      calc_commission INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      created_at TEXT,
      updated_at TEXT
    )
  `).run();
  const cols = [
    'type_code TEXT DEFAULT \'\'',
    'category_code TEXT DEFAULT \'\'',
    'category_name TEXT DEFAULT \'\'',
    'notes1 TEXT DEFAULT \'\'',
    'help_code TEXT DEFAULT \'\'',
    'flag TEXT DEFAULT \'S\'',
    'calc_commission INTEGER DEFAULT 1',
    'sort_order INTEGER DEFAULT 0',
    'created_at TEXT',
    'updated_at TEXT',
  ];
  for (const col of cols) {
    try { await DB.prepare(`ALTER TABLE income_items ADD COLUMN ${col}`).run(); } catch (_) {}
  }
}

export default async function incomeItems(context) {
  const { request, env, id, body, query } = context;
  CURRENT_ORIGIN = request.headers.get('Origin') || new URL(request.url).origin || CURRENT_ORIGIN;
  const DB = env.DB;
  const method = request.method;

  await ensureTable(DB);

  switch (method) {
    case 'GET':
      return id ? getById(DB, id) : list(DB, query);
    case 'POST':
      return create(DB, body);
    case 'PUT':
      return id ? update(DB, id, body) : error('缺少项目ID');
    case 'DELETE':
      return id ? remove(DB, id) : error('缺少项目ID');
    default:
      return error('不支持的请求方法', 405);
  }
}

// 列表
async function list(DB, query) {
  const pageSize = Math.min(500, Math.max(1, parseInt(query?.pageSize) || 200));

  const flag = query?.flag || '';
  const where = flag ? 'WHERE COALESCE(flag, \'S\') = ?1' : '';
  const limitPlaceholder = flag ? '?2' : '?1';
  const binds = flag ? [flag, pageSize] : [pageSize];
  const [rows, countResult] = await Promise.all([
    DB.prepare(`SELECT id, code, COALESCE(type_code, category_name, '') as type_code, category_code, category_name, name, COALESCE(help_code, notes1, '') as help_code, COALESCE(notes1, help_code, '') as notes1, COALESCE(flag, 'S') as flag, COALESCE(calc_commission, 1) as calc_commission, sort_order, created_at, updated_at FROM income_items ${where} ORDER BY sort_order ASC, id ASC LIMIT ${limitPlaceholder}`)
      .bind(...binds).all(),
    flag ? DB.prepare('SELECT COUNT(*) as total FROM income_items WHERE COALESCE(flag, \'S\') = ?1').bind(flag).first() : DB.prepare('SELECT COUNT(*) as total FROM income_items').first(),
  ]);

  return json({
    success: true,
    data: rows.results || [],
    pagination: { total: countResult?.total || 0 },
  });
}

// 详情
async function getById(DB, id) {
  const row = await DB.prepare("SELECT id, code, COALESCE(type_code, category_name, '') as type_code, category_code, category_name, name, COALESCE(help_code, notes1, '') as help_code, COALESCE(notes1, help_code, '') as notes1, COALESCE(flag, 'S') as flag, COALESCE(calc_commission, 1) as calc_commission, sort_order, created_at, updated_at FROM income_items WHERE id = ?1").bind(id).first();
  if (!row) return error('项目不存在', 404);
  return json({ success: true, data: row });
}

// 新增
async function create(DB, body) {
  const { code, type_code, name, help_code, sort_order } = body || {};
  if (!name || !name.trim()) return error('项目名称为必填项');

  const now = new Date().toISOString();
  const itemFlag = 'S';
  const categoryName = body?.category_name || type_code || '代理记账类收入';
  const categoryCode = body?.category_code || type_code || '01';
  const notes = body?.notes1 || help_code || '';
  const result = await DB.prepare(
    `INSERT INTO income_items (code, type_code, category_code, category_name, name, notes1, help_code, flag, calc_commission, sort_order, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
  ).bind(
    code || '',
    type_code || categoryName,
    categoryCode,
    categoryName,
    name.trim(),
    notes,
    help_code || notes,
    itemFlag,
    body?.calc_commission !== undefined ? (body.calc_commission ? 1 : 0) : 1,
    sort_order || 0,
    now, now
  ).run();

  return json({ success: true, message: '新增成功', id: result.meta?.last_row_id }, 201);
}

// 更新
async function update(DB, id, body) {
  body = body || {};
  const existing = await DB.prepare('SELECT * FROM income_items WHERE id = ?1').bind(id).first();
  if (!existing) return error('项目不存在', 404);

  const now = new Date().toISOString();
  const nextType = body.type_code !== undefined ? String(body.type_code) : (existing.type_code || existing.category_name || '');
  const nextNotes = body.help_code !== undefined ? String(body.help_code) : (body.notes1 !== undefined ? String(body.notes1) : (existing.help_code || existing.notes1 || ''));
  const fields = {
    code: body.code !== undefined ? String(body.code) : undefined,
    type_code: body.type_code !== undefined ? nextType : undefined,
    category_code: body.category_code !== undefined ? String(body.category_code) : (body.type_code !== undefined ? nextType : undefined),
    category_name: body.category_name !== undefined ? String(body.category_name) : (body.type_code !== undefined ? nextType : undefined),
    name: body.name !== undefined ? String(body.name).trim() : undefined,
    help_code: body.help_code !== undefined ? nextNotes : undefined,
    notes1: body.notes1 !== undefined ? String(body.notes1) : (body.help_code !== undefined ? nextNotes : undefined),
    flag: body.flag !== undefined ? 'S' : undefined,
    calc_commission: body.calc_commission !== undefined ? (body.calc_commission ? 1 : 0) : undefined,
    sort_order: body.sort_order !== undefined ? parseInt(body.sort_order) : undefined,
  };

  const sets = [];
  const values = [];
  let idx = 1;
  for (const [col, val] of Object.entries(fields)) {
    if (val !== undefined) {
      sets.push(`${col} = ?${idx}`);
      values.push(val);
      idx++;
    }
  }

  if (sets.length === 0) return error('没有需要更新的字段');

  sets.push(`updated_at = ?${idx}`);
  values.push(now);
  idx++;
  values.push(id);

  await DB.prepare(`UPDATE income_items SET ${sets.join(', ')} WHERE id = ?${idx}`)
    .bind(...values).run();

  return json({ success: true, message: '修改成功' });
}

// 删除
async function remove(DB, id) {
  const existing = await DB.prepare('SELECT * FROM income_items WHERE id = ?1').bind(id).first();
  if (!existing) return error('项目不存在', 404);

  await DB.prepare('DELETE FROM income_items WHERE id = ?1').bind(id).run();
  return json({ success: true, message: `项目「${existing.name}」已删除` });
}
