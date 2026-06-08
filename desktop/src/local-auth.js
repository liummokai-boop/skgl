import { webcrypto } from 'node:crypto';

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPasswordPBKDF2(password) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await webcrypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await webcrypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return `${bytesToHex(salt)}:${bytesToHex(new Uint8Array(hash))}`;
}

export async function seedLocalAdmin(DB) {
  await DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    phone TEXT,
    tenant_id TEXT,
    id_card TEXT,
    password_hash TEXT,
    salt TEXT,
    role TEXT,
    wx_openid TEXT,
    wx_unionid TEXT,
    created_at TEXT,
    name TEXT,
    disabled TEXT
  )`).run();

  const count = await DB.prepare('SELECT COUNT(*) as cnt FROM users').first().catch(() => ({ cnt: 0 }));
  if (Number(count?.cnt || 0) > 0) return;

  const passwordHash = await hashPasswordPBKDF2('123456');
  const now = new Date().toISOString();
  await DB.prepare(
    'INSERT INTO users (id, phone, tenant_id, id_card, password_hash, salt, role, created_at, name, disabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)'
  ).bind(1, '13399330020', '1', '110101199001010010', passwordHash, '', 'admin', now, '本地管理员', '').run();
}
