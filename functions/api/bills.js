/**
 * 收款账单 API
 * GET    /api/bills          - 列表（支持 ?search= & ?customerId= & ?page= & ?limit=）
 * GET    /api/bills/:id      - 详情
 * POST   /api/bills          - 新增收款记录
 * PUT    /api/bills/:id      - 更新收款记录
 * DELETE /api/bills/:id      - 删除收款记录
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

function tenantJoinClause(DB, alias, placeholderIndex) {
  return DB && DB.tenantId ? ` AND ${alias}.user_id = ?${placeholderIndex}` : '';
}

function tenantJoinParams(DB) {
  return DB && DB.tenantId ? [String(DB.tenantId)] : [];
}

export default async function bills(context) {
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
      return id ? update(DB, id, body) : error('缺少账单ID');
    case 'DELETE':
      return id ? remove(DB, id) : error('缺少账单ID');
    default:
      return error('不支持的请求方法', 405);
  }
}

// 账单列表
async function list(DB, query) {
  const search = query?.search || '';
  const customerId = query?.customerId || '';
  const page = Math.max(1, parseInt(query?.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query?.limit) || 50));
  const offset = (page - 1) * limit;

  const conditions = [];
  const params = [];
  let idx = 1;

  if (search) {
    conditions.push(`(b.customer_name LIKE ?${idx} OR b.remark LIKE ?${idx})`);
    params.push(`%${search}%`);
    idx++;
  }
  if (customerId) {
    conditions.push(`b.customer_id = ?${idx}`);
    params.push(customerId);
    idx++;
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const joinParams = tenantJoinParams(DB);
  const joinClause = tenantJoinClause(DB, 'c', idx);
  if (joinParams.length) idx++;

  const [rows, countResult] = await Promise.all([
    DB.prepare(
      `SELECT b.*, c.company as customer_company, c.phone as customer_phone
       FROM bills b
       LEFT JOIN customers c ON b.customer_id = c.id${joinClause}
       ${whereClause}
       ORDER BY b.date DESC, b.created_at DESC
       LIMIT ?${idx} OFFSET ?${idx + 1}`
    )
      .bind(...params, ...joinParams, limit, offset)
      .all(),
    DB.prepare(
      `SELECT COUNT(*) as total FROM bills b ${whereClause}`
    )
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

// 账单详情
async function getById(DB, id) {
  const joinParams = tenantJoinParams(DB);
  const joinClause = tenantJoinClause(DB, 'c', 2);
  const row = await DB.prepare(
    `SELECT b.*, c.company as customer_company, c.phone as customer_phone
     FROM bills b
     LEFT JOIN customers c ON b.customer_id = c.id${joinClause}
     WHERE b.id = ?1`
  )
    .bind(id, ...joinParams)
    .first();

  if (!row) return error('账单不存在', 404);

  return json({ success: true, data: row });
}

// 新增收款
async function create(DB, body) {
  const { customerId, customerName, amount, date, method, remark } = body;

  if (!customerName && !customerId) return error('客户信息为必填项');
  if (!amount) return error('金额为必填项');

  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const now = new Date().toISOString();

  await DB.prepare(
    `INSERT INTO bills (id, customer_id, customer_name, amount, date, method, remark, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
  ).bind(
    id,
    customerId || '',
    customerName || '',
    parseFloat(amount) || 0,
    date || new Date().toISOString().split('T')[0],
    method || '银行转账',
    remark || '',
    now,
    now
  ).run();

  const row = await DB.prepare(
    `SELECT b.*, c.company as customer_company
     FROM bills b LEFT JOIN customers c ON b.customer_id = c.id${tenantJoinClause(DB, 'c', 2)}
     WHERE b.id = ?1`
  ).bind(id, ...tenantJoinParams(DB)).first();

  return json({ success: true, data: row }, 201);
}

// 更新账单
async function update(DB, id, body) {
  const existing = await DB.prepare('SELECT * FROM bills WHERE id = ?1')
    .bind(id).first();
  if (!existing) return error('账单不存在', 404);

  const now = new Date().toISOString();
  const fields = ['customer_id', 'customer_name', 'amount', 'date', 'method', 'remark'];

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

  await DB.prepare(`UPDATE bills SET ${sets.join(', ')} WHERE id = ?${idx}`)
    .bind(...values)
    .run();

  const row = await DB.prepare(
    `SELECT b.*, c.company as customer_company
     FROM bills b LEFT JOIN customers c ON b.customer_id = c.id${tenantJoinClause(DB, 'c', 2)}
     WHERE b.id = ?1`
  ).bind(id, ...tenantJoinParams(DB)).first();

  return json({ success: true, data: row });
}

// 删除账单
async function remove(DB, id) {
  const existing = await DB.prepare('SELECT * FROM bills WHERE id = ?1')
    .bind(id).first();
  if (!existing) return error('账单不存在', 404);

  await DB.prepare('DELETE FROM bills WHERE id = ?1').bind(id).run();

  return json({
    success: true,
    message: `收款记录 ¥${existing.amount} 已删除`,
  });
}
