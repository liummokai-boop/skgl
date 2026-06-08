import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

function normalizeValue(value) {
  if (typeof value === 'bigint') return Number(value);
  return value;
}

function normalizeRow(row) {
  if (!row) return null;
  const out = {};
  for (const [key, value] of Object.entries(row)) {
    out[key] = normalizeValue(value);
  }
  return out;
}

function normalizeRows(rows) {
  return (rows || []).map(normalizeRow);
}

function toError(err) {
  const e = new Error(err && err.message ? err.message : String(err));
  e.cause = err;
  return e;
}

export class LocalD1Database {
  constructor(filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this.filePath = filePath;
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA foreign_keys = ON');
  }

  prepare(sql) {
    return new LocalD1Statement(this, sql);
  }

  async batch(statements) {
    const results = [];
    this.db.exec('BEGIN');
    try {
      for (const stmt of statements) {
        results.push(await stmt.run());
      }
      this.db.exec('COMMIT');
      return results;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (_) {}
      throw toError(err);
    }
  }

  close() {
    this.db.close();
  }
}

class LocalD1Statement {
  constructor(owner, sql) {
    this.owner = owner;
    this.sql = sql;
    this.params = [];
  }

  bind(...params) {
    this.params = params;
    return this;
  }

  statement() {
    return this.owner.db.prepare(this.sql);
  }

  async all() {
    try {
      const rows = this.statement().all(...this.params);
      return { success: true, results: normalizeRows(rows) };
    } catch (err) {
      throw toError(err);
    }
  }

  async first() {
    try {
      return normalizeRow(this.statement().get(...this.params));
    } catch (err) {
      throw toError(err);
    }
  }

  async run() {
    try {
      const result = this.statement().run(...this.params);
      return {
        success: true,
        meta: {
          changes: normalizeValue(result.changes || 0),
          last_row_id: normalizeValue(result.lastInsertRowid || 0),
          lastRowId: normalizeValue(result.lastInsertRowid || 0)
        }
      };
    } catch (err) {
      throw toError(err);
    }
  }
}
