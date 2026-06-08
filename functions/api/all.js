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

function err(message, status = 400) {
  return json({ success: false, error: message }, status);
}

function nowISO() {
  return new Date().toISOString();
}

function quoteIdent(name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error('非法字段名');
  return `"${name.replace(/"/g, '""')}"`;
}

function makeCrud(table, fields, opts = {}) {
  const pk = opts.pk || 'id';
  const searchFields = opts.searchFields || [];
  const sortField = opts.sortField || `${pk} DESC`;
  const dataFields = fields.filter(f => f !== pk);

  async function ensureTable(DB) {
    const defs = {
      [pk]: 'INTEGER PRIMARY KEY AUTOINCREMENT',
      wl_id: 'INTEGER',
      use_id: 'TEXT',
      gn_no: 'TEXT',
      num: 'INTEGER DEFAULT 1',
      srp: 'INTEGER DEFAULT 0',
    };
    const cols = [`${quoteIdent(pk)} ${defs[pk]}`];
    for (const field of dataFields) cols.push(`${quoteIdent(field)} ${defs[field] || 'TEXT'}`);
    cols.push('created_at TEXT', 'updated_at TEXT');
    await DB.prepare(`CREATE TABLE IF NOT EXISTS ${quoteIdent(table)} (${cols.join(', ')})`).run();
    for (const col of cols) {
      try { await DB.prepare(`ALTER TABLE ${quoteIdent(table)} ADD COLUMN ${col}`).run(); } catch (_) {}
    }
  }

  function normalizeRow(row) {
    if (!row || typeof row !== 'object') return row;
    const out = { ...row };
    out.id = row.id || row[pk] || '';
    if (table === 'item_manger') {
      out.num = Number(row.num || row.quantity || 1);
      out.recv_date = row.recv_date || row.receive_date || '';
      out.return_date = row.return_date || '';
    }
    return out;
  }

  function normalizeBody(body = {}) {
    const next = { ...body };
    if (table === 'item_manger') {
      if (next.quantity !== undefined && next.num === undefined) next.num = next.quantity;
      if (next.receive_date !== undefined && next.recv_date === undefined) next.recv_date = next.receive_date;
    }
    return next;
  }

  async function list(DB, query = {}) {
    await ensureTable(DB);
    const page = Math.max(1, parseInt(query.page) || 1);
    const pageSize = Math.min(1000, Math.max(1, parseInt(query.pageSize) || 20));
    const offset = (page - 1) * pageSize;
    const conditions = [];
    const params = [];
    let p = 1;
    const keyword = String(query.keyword || query.q || query.kw || '').trim();
    if (keyword && searchFields.length) {
      conditions.push('(' + searchFields.map(f => `${quoteIdent(f)} LIKE ?${p}`).join(' OR ') + ')');
      params.push(`%${keyword}%`);
      p++;
    }
    for (const field of dataFields) {
      if (query[field] !== undefined && query[field] !== '') {
        conditions.push(`${quoteIdent(field)} = ?${p}`);
        params.push(query[field]);
        p++;
      }
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const [rows, count] = await Promise.all([
      DB.prepare(`SELECT * FROM ${quoteIdent(table)} ${where} ORDER BY ${sortField} LIMIT ?${p} OFFSET ?${p + 1}`).bind(...params, pageSize, offset).all(),
      DB.prepare(`SELECT COUNT(*) AS total FROM ${quoteIdent(table)} ${where}`).bind(...params).first(),
    ]);
    const list = (rows.results || []).map(normalizeRow);
    return json({ success: true, list, data: list, total: count?.total || 0 });
  }

  async function get(DB, id) {
    await ensureTable(DB);
    const row = await DB.prepare(`SELECT * FROM ${quoteIdent(table)} WHERE ${quoteIdent(pk)} = ?1`).bind(id).first();
    if (!row) return err('记录不存在', 404);
    return json({ success: true, ...normalizeRow(row) });
  }

  async function create(DB, body) {
    await ensureTable(DB);
    body = normalizeBody(body || {});
    const now = nowISO();
    const vals = dataFields.map(f => body[f] !== undefined ? body[f] : '');
    const placeholders = dataFields.map((_, i) => `?${i + 1}`).join(',');
    const result = await DB.prepare(`INSERT INTO ${quoteIdent(table)} (${dataFields.map(quoteIdent).join(',')}, created_at, updated_at) VALUES (${placeholders}, ?${dataFields.length + 1}, ?${dataFields.length + 2})`)
      .bind(...vals, now, now).run();
    const row = await DB.prepare(`SELECT * FROM ${quoteIdent(table)} WHERE rowid = ?1`).bind(result.meta?.last_row_id).first();
    return json({ success: true, ...normalizeRow(row) }, 201);
  }

  async function update(DB, id, body) {
    await ensureTable(DB);
    body = normalizeBody(body || {});
    const existing = await DB.prepare(`SELECT * FROM ${quoteIdent(table)} WHERE ${quoteIdent(pk)} = ?1`).bind(id).first();
    if (!existing) return err('记录不存在', 404);
    const sets = [];
    const vals = [];
    let i = 1;
    for (const field of dataFields) {
      if (body[field] !== undefined) {
        sets.push(`${quoteIdent(field)} = ?${i}`);
        vals.push(body[field]);
        i++;
      }
    }
    if (!sets.length) return err('无更新字段');
    sets.push(`updated_at = ?${i}`);
    vals.push(nowISO());
    i++;
    vals.push(id);
    await DB.prepare(`UPDATE ${quoteIdent(table)} SET ${sets.join(', ')} WHERE ${quoteIdent(pk)} = ?${i}`).bind(...vals).run();
    const row = await DB.prepare(`SELECT * FROM ${quoteIdent(table)} WHERE ${quoteIdent(pk)} = ?1`).bind(id).first();
    return json({ success: true, ...normalizeRow(row) });
  }

  async function remove(DB, id) {
    await ensureTable(DB);
    await DB.prepare(`DELETE FROM ${quoteIdent(table)} WHERE ${quoteIdent(pk)} = ?1`).bind(id).run();
    return json({ success: true, message: '已删除' });
  }

  return { ensureTable, list, get, create, update, remove };
}

const MODULES = {
  'wl-info': makeCrud('wl_info', [
    'wl_type', 'wl_bianm', 'wl_name', 'wl_tel', 'wl_fax', 'wl_add', 'wl_person',
    'wl_other1', 'wl_other2', 'wl_other3', 'wl_help', 'qiyezcno', 'faren', 'faren_id',
    'guoshui_mm', 'dishui_mobileno', 'dishui_useid', 'zz_tax_type', 'sd_tax_type',
    'yh_tax_type', 'fj_tax_type', 'qiyeleixing', 'bank_no',
    'bank_kaihu', 'sanfang_xy', 'yw_beg', 'yw_end', 'is_fapiao',
    'banshuifenju', 'banshui_zhuangy', 'jz_kuaiji',
    'ywy', 'bs_flag', 'jz_flag', 'baoshui', 'dis_flag', 'tx_flag', 'sz_no',
    'sz_name', 'jz_amt', 'ys_amt', 'yz_amt', 'leixin', 'other1', 'other2',
    'tipmsg', 'gs_create_date', 'gdnum', 'zjinfo',
  ], { pk: 'wl_id', searchFields: ['wl_name', 'wl_bianm', 'wl_tel', 'wl_person', 'faren', 'qiyezcno'], sortField: 'wl_id DESC' }),
  use: makeCrud('t_use', ['use_id', 'use_name', 'use_pass', 'use_is_in', 'ruzhi_date', 'lizhi_date', 'use_help', 'use_other1', 'use_other2', 'srp'], { pk: 'useautoid', searchFields: ['use_name', 'use_id'], sortField: 'srp ASC' }),
  function: makeCrud('t_function', ['gn_no', 'gn_name', 'gn_type_name', 'gn_pic', 'gn_sort', 'show_flag'], { pk: 'autoid', searchFields: ['gn_name'], sortField: 'gn_sort ASC' }),
  'function-user': makeCrud('t_function_user', ['use_id', 'gn_no'], { pk: 'autoid', searchFields: ['use_id'], sortField: 'autoid ASC' }),
  'item-mgr': makeCrud('item_manger', ['wl_id', 'wl_name', 'sheet_no', 'dj_no', 'item_name', 'item_type', 'item_status', 'item_other', 'num', 'recv_date', 'return_date'], { pk: 'autoid', searchFields: ['item_name', 'wl_name'], sortField: 'autoid DESC' }),
};

export default async function onRequest(context) {
  CURRENT_ORIGIN = context.request.headers.get('Origin') || new URL(context.request.url).origin || CURRENT_ORIGIN;
  const { request, env, module, id, body } = context;
  const DB = env.DB;
  const method = request.method;
  const mod = MODULES[module];
  if (!mod) return err(`未知模块: ${module}`, 404);

  switch (method) {
    case 'GET':
      return id ? mod.get(DB, id) : mod.list(DB, context.query || {});
    case 'POST':
      if (id === 'import') {
        const rows = body?.rows || body?.list || [];
        let inserted = 0;
        let errors = 0;
        const importErrors = [];
        for (let i = 0; i < rows.length; i++) {
          try {
            const res = await mod.create(DB, rows[i]);
            if (res.status === 201) inserted++;
            else errors++;
          } catch (e) {
            errors++;
            importErrors.push({ row: i + 1, error: e.message });
          }
        }
        return json({ success: true, inserted, skipped: 0, errors, importErrors });
      }
      return mod.create(DB, body);
    case 'PUT':
      return id ? mod.update(DB, id, body) : err('缺少记录ID');
    case 'DELETE':
      return id ? mod.remove(DB, id) : err('缺少记录ID');
    default:
      return err('不支持的请求方法', 405);
  }
}

export { MODULES };
