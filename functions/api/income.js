/**
 * 收入类别与收入项目 API
 * GET    /api/income/categories        - 获取所有类别（树形结构）
 * POST   /api/income/categories        - 新增类别
 * PUT    /api/income/categories/:id    - 修改类别
 * DELETE /api/income/categories/:id    - 删除类别
 * GET    /api/income/items             - 列表（支持 ?category= & ?pageSize=）
 * POST   /api/income/items             - 新增项目
 * PUT    /api/income/items/:id         - 修改项目
 * DELETE /api/income/items/:id         - 删除项目
 * POST   /api/income/items/batch       - 批量保存
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

// 确保表存在
async function ensureTables(DB) {
  // 收入类别表
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS income_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL DEFAULT '',
      name TEXT NOT NULL DEFAULT '',
      parent_id INTEGER DEFAULT 0,
      level INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      created_at TEXT,
      updated_at TEXT
    )
  `).run();

  // 收入项目表 - 检测旧表是否有 type_code 等旧列，有则重建
  const newItemSchema = `
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
      created_at TEXT DEFAULT '',
      updated_at TEXT DEFAULT ''
    )
  `;

  let itemTableOk = false;
  try {
    const cols = await DB.prepare("PRAGMA table_info(income_items)").all();
    const colNames = (cols.results || []).map(c => c.name);
    const needRebuild = colNames.includes('help_code') && !colNames.includes('category_code')
      || colNames.includes('flag') && !colNames.includes('category_code')
      || !colNames.includes('category_code')
      || !colNames.includes('category_name')
      || !colNames.includes('notes1')
      || !colNames.includes('calc_commission')
      || !colNames.includes('created_at')
      || !colNames.includes('updated_at');

    if (colNames.length > 0 && needRebuild) {
      // 旧表存在且结构不匹配 → 重建
      await DB.prepare("ALTER TABLE income_items RENAME TO income_items_old").run();
      await DB.prepare(newItemSchema).run();
      // 迁移旧数据
      const oldCols = (cols.results || []).map(c => c.name);
      const safeSelect = (name, fallback) => oldCols.includes(name) ? name : `'${fallback}'`;
      const migrateSQL = `INSERT INTO income_items (id, code, type_code, category_code, category_name, name, notes1, help_code, flag, calc_commission, sort_order, created_at, updated_at)
        SELECT id, code, ${safeSelect('type_code', '')}, ${safeSelect('category_code', '')}, ${safeSelect('category_name', '')},
               ${safeSelect('name', '')}, ${safeSelect('notes1', '')}, ${safeSelect('help_code', '')}, ${safeSelect('flag', 'S')}, ${safeSelect('calc_commission', '1')},
               ${safeSelect('sort_order', '0')}, ${safeSelect('created_at', '')}, ${safeSelect('updated_at', '')}
        FROM income_items_old`;
      await DB.prepare(migrateSQL).run();
      await DB.prepare("DROP TABLE income_items_old").run();
      itemTableOk = true;
    } else if (colNames.length === 0) {
      // 表不存在 → 新建
      await DB.prepare(newItemSchema).run();
      itemTableOk = true;
    } else {
      // 表结构已匹配
      itemTableOk = true;
    }
  } catch (e) {
    // 兜底：直接尝试新建
    try { await DB.prepare(newItemSchema).run(); itemTableOk = true; } catch (e2) { /* ignore */ }
  }

  if (!itemTableOk) {
    // 最终兜底：逐列补充
    const itemCols = [
      'type_code TEXT DEFAULT \'\'',
      'category_code TEXT DEFAULT \'\'',
      'category_name TEXT DEFAULT \'\'',
      'notes1 TEXT DEFAULT \'\'',
      'help_code TEXT DEFAULT \'\'',
      'flag TEXT DEFAULT \'S\'',
      'calc_commission INTEGER DEFAULT 1',
      'created_at TEXT DEFAULT \'\'',
      'updated_at TEXT DEFAULT \'\'',
    ];
    for (const colDef of itemCols) {
      const colName = colDef.split(' ')[0];
      try {
        await DB.prepare(`ALTER TABLE income_items ADD COLUMN ${colDef}`).run();
      } catch (e) { /* column already exists */ }
    }
  }

  const compatItemCols = [
    'type_code TEXT DEFAULT \'\'',
    'help_code TEXT DEFAULT \'\'',
    'flag TEXT DEFAULT \'S\'',
  ];
  for (const colDef of compatItemCols) {
    try { await DB.prepare(`ALTER TABLE income_items ADD COLUMN ${colDef}`).run(); } catch (e) {}
  }

  // 补充可能缺失的列（income_categories）
  const catCols = [
    'created_at TEXT DEFAULT \'\'',
    'updated_at TEXT DEFAULT \'\'',
  ];
  for (const colDef of catCols) {
    const colName = colDef.split(' ')[0];
    try {
      await DB.prepare(`ALTER TABLE income_categories ADD COLUMN ${colDef}`).run();
    } catch (e) { /* column already exists */ }
  }

  // 初始化默认类别数据（如果为空）
  const countResult = await DB.prepare('SELECT COUNT(*) as cnt FROM income_categories').first();
  if ((countResult?.cnt || 0) === 0) {
    const now = new Date().toISOString();
    const defaults = [
      { code: '01', name: '代理记账类收入', parent_id: 0, level: 1, sort_order: 1 },
      { code: '02', name: '其它收入', parent_id: 0, level: 1, sort_order: 2 },
    ];
    for (const d of defaults) {
      await DB.prepare(
        'INSERT INTO income_categories (code, name, parent_id, level, sort_order, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7)'
      ).bind(d.code, d.name, d.parent_id, d.level, d.sort_order, now, now).run();
    }
  }

  // 初始化默认项目数据（如果 income_items 没有 category_code 相关数据）
  const itemCount = await DB.prepare('SELECT COUNT(*) as cnt FROM income_items WHERE category_code IS NOT NULL AND category_code != \'\'').first();
  if ((itemCount?.cnt || 0) === 0) {
    const now = new Date().toISOString();
    const items = [
      { code: '011', category_code: '01', category_name: '代理记账类收入', name: '开票托管费', notes1: '', calc_commission: 1, sort_order: 1 },
      { code: '003', category_code: '01', category_name: '代理记账类收入', name: '审计验资费', notes1: '', calc_commission: 1, sort_order: 2 },
      { code: '013', category_code: '01', category_name: '代理记账类收入', name: '开票托管*申报费', notes1: '', calc_commission: 1, sort_order: 3 },
      { code: '012', category_code: '01', category_name: '代理记账类收入', name: '报税费', notes1: '', calc_commission: 1, sort_order: 4 },
      { code: '010', category_code: '01', category_name: '代理记账类收入', name: '代理记账费用', notes1: '', calc_commission: 1, sort_order: 5 },
      { code: '004', category_code: '01', category_name: '代理记账类收入', name: '资产评估费', notes1: '', calc_commission: 1, sort_order: 6 },
      { code: '009', category_code: '02', category_name: '其它收入', name: '变更服务费', notes1: '', calc_commission: 1, sort_order: 7 },
      { code: '007', category_code: '02', category_name: '其它收入', name: '代办服务费', notes1: '', calc_commission: 1, sort_order: 8 },
      { code: '008', category_code: '02', category_name: '其它收入', name: '注册服务费', notes1: '', calc_commission: 1, sort_order: 9 },
      { code: '006', category_code: '02', category_name: '其它收入', name: '培训费', notes1: '', calc_commission: 1, sort_order: 10 },
    ];
    for (const item of items) {
      await DB.prepare(
        `INSERT INTO income_items (code, type_code, category_code, category_name, name, notes1, help_code, flag, calc_commission, sort_order, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`
      ).bind(item.code, '', item.category_code, item.category_name, item.name, item.notes1, '', 'S', item.calc_commission, item.sort_order, now, now).run();
    }
  }
}

export default async function incomeHandler(context) {
  const { request, env, body, query } = context;
  CURRENT_ORIGIN = request.headers.get('Origin') || new URL(request.url).origin || CURRENT_ORIGIN;
  const DB = env.DB;
  const method = request.method;

  // 解析路径: 从完整 URL 中提取子路由
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/income\/?/, '');
  const segments = path.split('/').filter(Boolean);

  await ensureTables(DB);

  // 路由分发
  if (segments[0] === 'categories' || segments[0] === 'category') {
    const catId = segments[1] || null;
    return handleCategories(DB, method, catId, body);
  }

  if (segments[0] === 'items' || segments[0] === 'item') {
    const itemId = segments[1] || null;
    return handleItems(DB, method, itemId, body, query);
  }

  // 默认返回所有数据
  if (method === 'GET') {
    const [cats, items] = await Promise.all([
      DB.prepare('SELECT * FROM income_categories ORDER BY sort_order ASC, id ASC').all(),
      DB.prepare("SELECT * FROM income_items WHERE category_code IS NOT NULL AND category_code != '' AND COALESCE(flag, 'S') != 'F' ORDER BY sort_order ASC, id ASC").all(),
    ]);
    return json({
      success: true,
      categories: cats.results || [],
      items: items.results || [],
    });
  }

  return error('不支持的请求方法', 405);
}

// === 类别 CRUD ===
async function handleCategories(DB, method, id, body) {
  switch (method) {
    case 'GET':
      if (id) {
        const row = await DB.prepare('SELECT * FROM income_categories WHERE id = ?1').bind(parseInt(id)).first();
        if (!row) return error('类别不存在', 404);
        return json({ success: true, data: row });
      }
      const rows = await DB.prepare('SELECT * FROM income_categories ORDER BY sort_order ASC, id ASC').all();
      return json({ success: true, data: rows.results || [] });

    case 'POST': {
      const { code, name, parent_id, level } = body || {};
      if (!name || !name.trim()) return error('类别名称为必填项');
      const now = new Date().toISOString();
      const result = await DB.prepare(
        `INSERT INTO income_categories (code, name, parent_id, level, sort_order, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
      ).bind(
        code || '',
        name.trim(),
        parent_id || 0,
        level || 1,
        body.sort_order || 0,
        now, now
      ).run();
      return json({ success: true, message: '新增成功', id: result.meta?.last_row_id }, 201);
    }

    case 'PUT': {
      if (!id) return error('缺少类别ID');
      const existing = await DB.prepare('SELECT * FROM income_categories WHERE id = ?1').bind(parseInt(id)).first();
      if (!existing) return error('类别不存在', 404);
      const now = new Date().toISOString();
      const b = body || {};
      await DB.prepare(
        `UPDATE income_categories SET code=?1, name=?2, parent_id=?3, level=?4, sort_order=?5, updated_at=?6 WHERE id=?7`
      ).bind(
        b.code !== undefined ? String(b.code) : existing.code,
        b.name !== undefined ? String(b.name).trim() : existing.name,
        b.parent_id !== undefined ? parseInt(b.parent_id) : existing.parent_id,
        b.level !== undefined ? parseInt(b.level) : existing.level,
        b.sort_order !== undefined ? parseInt(b.sort_order) : existing.sort_order,
        now,
        parseInt(id)
      ).run();
      return json({ success: true, message: '修改成功' });
    }

    case 'DELETE': {
      if (!id) return error('缺少类别ID');
      const existing = await DB.prepare('SELECT * FROM income_categories WHERE id = ?1').bind(parseInt(id)).first();
      if (!existing) return error('类别不存在', 404);
      // 同时删除子类别
      await DB.prepare('DELETE FROM income_categories WHERE id = ?1 OR parent_id = ?1').bind(parseInt(id)).run();
      return json({ success: true, message: `类别「${existing.name}」已删除` });
    }

    default:
      return error('不支持的请求方法', 405);
  }
}

// === 项目 CRUD ===
async function handleItems(DB, method, id, body, query) {
  // 批量保存
  if (method === 'POST' && id === 'batch') {
    return batchSaveItems(DB, body);
  }

  switch (method) {
    case 'GET':
      return id ? getItemById(DB, id) : listItems(DB, query);

    case 'POST':
      return createItem(DB, body);

    case 'PUT':
      return id ? updateItem(DB, id, body) : error('缺少项目ID');

    case 'DELETE':
      return id ? removeItem(DB, id) : error('缺少项目ID');

    default:
      return error('不支持的请求方法', 405);
  }
}

async function listItems(DB, query) {
  const category = query?.category || query?.category_code || '';
  const pageSize = Math.min(500, Math.max(1, parseInt(query?.pageSize) || 200));

  let where = "WHERE category_code IS NOT NULL AND category_code != '' AND COALESCE(flag, 'S') != 'F'";
  const params = [];

  if (category) {
    where += ' AND category_code = ?1';
    params.push(category);
  }

  const limitIdx = params.length + 1;
  const [rows, countResult] = await Promise.all([
    DB.prepare(`SELECT * FROM income_items ${where} ORDER BY sort_order ASC, id ASC LIMIT ?${limitIdx}`)
      .bind(...params, pageSize).all(),
    DB.prepare(`SELECT COUNT(*) as total FROM income_items ${where}`).bind(...params).first(),
  ]);

  return json({
    success: true,
    data: rows.results || [],
    total: countResult?.total || 0,
  });
}

async function getItemById(DB, id) {
  const row = await DB.prepare('SELECT * FROM income_items WHERE id = ?1').bind(parseInt(id)).first();
  if (!row) return error('项目不存在', 404);
  return json({ success: true, data: row });
}

async function createItem(DB, body) {
  const { code, category_code, category_name, name, notes1, calc_commission } = body || {};
  if (!name || !name.trim()) return error('项目名称为必填项');

  const now = new Date().toISOString();
  const result = await DB.prepare(
    `INSERT INTO income_items (code, type_code, category_code, category_name, name, notes1, help_code, flag, calc_commission, sort_order, created_at, updated_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`
  ).bind(
    code || '',
    body?.type_code || category_name || '',
    category_code || '',
    category_name || '',
    name.trim(),
    notes1 || '',
    body?.help_code || notes1 || '',
    body?.flag || 'S',
    calc_commission !== undefined ? (calc_commission ? 1 : 0) : 1,
    body.sort_order || 0,
    now, now
  ).run();
  return json({ success: true, message: '新增成功', id: result.meta?.last_row_id }, 201);
}

async function updateItem(DB, id, body) {
  const existing = await DB.prepare('SELECT * FROM income_items WHERE id = ?1').bind(parseInt(id)).first();
  if (!existing) return error('项目不存在', 404);

  const now = new Date().toISOString();
  const b = body || {};
  await DB.prepare(
    `UPDATE income_items SET code=?1, type_code=?2, category_code=?3, category_name=?4, name=?5, notes1=?6, help_code=?7, flag=?8, calc_commission=?9, sort_order=?10, updated_at=?11 WHERE id=?12`
  ).bind(
    b.code !== undefined ? String(b.code) : existing.code,
    b.type_code !== undefined ? String(b.type_code) : (b.category_name !== undefined ? String(b.category_name) : (existing.type_code || '')),
    b.category_code !== undefined ? String(b.category_code) : (existing.category_code || ''),
    b.category_name !== undefined ? String(b.category_name) : (existing.category_name || ''),
    b.name !== undefined ? String(b.name).trim() : existing.name,
    b.notes1 !== undefined ? String(b.notes1) : (existing.notes1 || ''),
    b.help_code !== undefined ? String(b.help_code) : (b.notes1 !== undefined ? String(b.notes1) : (existing.help_code || '')),
    b.flag !== undefined ? String(b.flag) : (existing.flag || 'S'),
    b.calc_commission !== undefined ? (b.calc_commission ? 1 : 0) : (existing.calc_commission || 0),
    b.sort_order !== undefined ? parseInt(b.sort_order) : existing.sort_order,
    now,
    parseInt(id)
  ).run();
  return json({ success: true, message: '修改成功' });
}

async function removeItem(DB, id) {
  const existing = await DB.prepare('SELECT * FROM income_items WHERE id = ?1').bind(parseInt(id)).first();
  if (!existing) return error('项目不存在', 404);
  await DB.prepare('DELETE FROM income_items WHERE id = ?1').bind(parseInt(id)).run();
  return json({ success: true, message: `项目「${existing.name}」已删除` });
}

async function batchSaveItems(DB, body) {
  const items = body?.items || [];
  if (!Array.isArray(items) || items.length === 0) return error('没有可保存的数据');

  const now = new Date().toISOString();
  let saved = 0;

  for (const item of items) {
    if (item._deleted) {
      if (item.id) {
        await DB.prepare('DELETE FROM income_items WHERE id = ?1').bind(item.id).run();
      }
      saved++;
      continue;
    }
    if (item.id) {
      // 更新
      await DB.prepare(
        `UPDATE income_items SET code=?1, type_code=?2, category_code=?3, category_name=?4, name=?5, notes1=?6, help_code=?7, flag=?8, calc_commission=?9, sort_order=?10, updated_at=?11 WHERE id=?12`
      ).bind(
        item.code || '', item.type_code || item.category_name || '', item.category_code || '', item.category_name || '',
        (item.name || '').trim(), item.notes1 || '', item.help_code || item.notes1 || '', item.flag || 'S',
        item.calc_commission ? 1 : 0, item.sort_order || 0, now, item.id
      ).run();
    } else {
      // 新增
      await DB.prepare(
        `INSERT INTO income_items (code, type_code, category_code, category_name, name, notes1, help_code, flag, calc_commission, sort_order, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`
      ).bind(
        item.code || '', item.type_code || '', item.category_code || '', item.category_name || '',
        (item.name || '').trim(), item.notes1 || '', item.help_code || item.notes1 || '', item.flag || 'S',
        item.calc_commission ? 1 : 0, item.sort_order || 0, now, now
      ).run();
    }
    saved++;
  }

  return json({ success: true, message: `保存成功，共 ${saved} 条`, count: saved });
}
