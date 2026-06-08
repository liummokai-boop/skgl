/**
 * 客户管理 API
 * GET    /api/customers       - 列表（支持 ?search= & ?page= & ?limit=）
 * GET    /api/customers/:id   - 详情
 * POST   /api/customers       - 新增
 * PUT    /api/customers/:id   - 更新
 * DELETE /api/customers/:id   - 删除（移入回收站）
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

export default async function customers(context) {
  const { request, env, id, body, query } = context;
  CURRENT_ORIGIN = request.headers.get('Origin') || new URL(request.url).origin || CURRENT_ORIGIN;
  const DB = env.DB;
  const method = request.method;

  switch (method) {
    case 'GET':
      return id ? getById(DB, id) : list(DB, query);
    case 'POST':
      return create(DB, body);
    case 'PUT':
      return id ? update(DB, id, body) : error('缺少客户ID');
    case 'DELETE':
      return id ? remove(DB, id, body) : error('缺少客户ID');
    default:
      return error('不支持的请求方法', 405);
  }
}

// 客户列表（支持搜索和分页）
async function list(DB, query) {
  const search = query?.search || '';
  const page = Math.max(1, parseInt(query?.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query?.limit) || 50));
  const offset = (page - 1) * limit;

  let whereClause = '';
  const params = [];

  if (search) {
    whereClause = 'WHERE company LIKE ?1 OR contact LIKE ?1 OR phone LIKE ?1';
    params.push(`%${search}%`);
  }

  const [rows, countResult] = await Promise.all([
    DB.prepare(
      `SELECT * FROM customers ${whereClause} ORDER BY created_at DESC LIMIT ?2 OFFSET ?3`
    )
      .bind(...params, limit, offset)
      .all(),
    DB.prepare(`SELECT COUNT(*) as total FROM customers ${whereClause}`)
      .bind(...params)
      .first(),
  ]);

  return json({
    success: true,
    data: rows.results,
    pagination: {
      page,
      limit,
      total: countResult?.total || 0,
      totalPages: Math.ceil((countResult?.total || 0) / limit),
    },
  });
}

// 客户详情
async function getById(DB, id) {
  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1')
    .bind(id)
    .first();

  if (!row) return error('客户不存在', 404);

  return json({ success: true, data: row });
}

// 新增客户
async function create(DB, body) {
  const {
    company, type, taxNo, phone, contact, startDate,
    chargeType, amount, chargeInterval, status, manager, remark,
  } = body;

  if (!company) return error('公司名称为必填项');

  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const now = new Date().toISOString();

  await DB.prepare(
    `INSERT INTO customers (id, company, type, tax_no, phone, contact, start_date,
     charge_type, amount, charge_interval, status, manager, remark, created_at, updated_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)`
  ).bind(
    id, company || '', type || '', taxNo || '', phone || '', contact || '',
    startDate || '', chargeType || '', amount || '', chargeInterval || '',
    status || 'active', manager || '', remark || '', now, now
  ).run();

  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  return json({ success: true, data: row }, 201);
}

// 更新客户
async function update(DB, id, body) {
  const existing = await DB.prepare('SELECT * FROM customers WHERE id = ?1')
    .bind(id).first();
  if (!existing) return error('客户不存在', 404);

  const now = new Date().toISOString();
  const fields = [
    'company', 'type', 'tax_no', 'phone', 'contact', 'start_date',
    'charge_type', 'amount', 'charge_interval', 'status', 'manager', 'remark',
  ];

  const sets = [];
  const values = [];
  let idx = 1;

  fields.forEach((field) => {
    const camelKey = field.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    if (body[camelKey] !== undefined || body[field] !== undefined) {
      sets.push(`${field} = ?${idx}`);
      values.push(body[camelKey] ?? body[field]);
      idx++;
    }
  });

  if (sets.length === 0) return error('没有需要更新的字段');

  sets.push(`updated_at = ?${idx}`);
  values.push(now);
  idx++;
  values.push(id);

  await DB.prepare(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?${idx}`)
    .bind(...values)
    .run();

  const row = await DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  return json({ success: true, data: row });
}

// 删除客户（软删除：移入回收站）
async function remove(DB, id, body) {
  const existing = await DB.prepare('SELECT * FROM customers WHERE id = ?1')
    .bind(id).first();
  if (!existing) return error('客户不存在', 404);

  const now = new Date().toISOString();
  const deletedBy = body?.deletedBy || 'system';
  const recycleId = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  // 写入回收站
  await DB.prepare(
    `INSERT INTO recycle_bin (id, original_id, type, name, deleted_by, deleted_at, data)
     VALUES (?1, ?2, 'customer', ?3, ?4, ?5, ?6)`
  ).bind(recycleId, id, existing.company || '', deletedBy, now, JSON.stringify(existing)).run();

  // 删除原记录
  await DB.prepare('DELETE FROM customers WHERE id = ?1').bind(id).run();

  return json({
    success: true,
    message: `客户「${existing.company}」已删除`,
    recycleId,
  });
}
