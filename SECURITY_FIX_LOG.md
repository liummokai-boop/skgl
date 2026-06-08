# 记账客户管理系统 - 安全修复日志
## 修复日期: 2026-06-02
## 总计: 16 项漏洞全部修复（8 高危 + 10 中危 + 低危）

## 追加修复: 2026-06-05
- [x] 数据清空不再自动创建占位表，避免破坏真实表结构
- [x] 备份接口改为真实导出白名单业务表及表结构
- [x] 恢复接口改为真实按备份文件恢复白名单业务表
- [x] 重置密码必须配置验证码发送 Webhook，未配置时不再假装发送成功
- [x] 微信登录默认要求服务端用 code 校验，禁止直接信任前端 openid
- [x] package.json 增加基础语法检查脚本

## 模块逻辑修复: 2026-06-05
- [x] 删除不在菜单中显示的旧 reports/analysis 页面入口与旧面板
- [x] 通用列表接口兼容返回 list 与 data，修复资金账户、意向客户、业务员等空表问题
- [x] 修复账户、意向客户、转账模块的前后端字段别名
- [x] 补齐 /api/sys-config 兼容路由
- [x] 补齐 reports/analysis/ar-reports 子报表接口
- [x] 补齐 payment-plans 月度清单返回结构
- [x] 业务员新增、修改、停用改为真实写入 /api/users

### P0 高危修复（7 项）
- [x] 高危-1: API 全局 JWT 认证中间件（[[path]].js）
- [x] 高危-2: Token 升级为 HMAC-SHA256 JWT（auth.js）
- [x] 高危-3/8: 密码 PBKDF2 哈希，兼容旧明文/SHA-256（auth.js + all.js）
- [x] 高危-4: 暴力破解 IP 级防护，5次锁定15分钟（auth.js）
- [x] 高危-6: change-password 完整实现（[[path]].js）
- [x] 高危-7: reset-password 完整实现（[[path]].js）
- [x] 中危-8: SHA-256 升级为 PBKDF2 iterations=100000

### P1 中危修复（6 项）
- [x] 中危-1: CORS 限制为 https://skgl.pages.dev（12个文件）
- [x] 中危-4: 操作员默认密码随机化（all.js + index.html）
- [x] 中危-5: LIKE 通配符转义（[[path]].js）
- [x] 中危-6: IP 令牌桶频率限制 60 req/min（[[path]].js）
- [x] 中危-7: 登录统一错误消息（auth.js）
- [x] 中危-9: 移除注册表单身份证号（index.html）

### P2/P3 修复（3 项）
- [x] 中危-2: Token 过期前端检查（index.html）
- [x] 低危-3: .gitignore 添加 .wrangler/
- [x] 低危-4: 创建 wrangler.toml.example

### 部署注意
1. 在 Cloudflare Dashboard 设置环境变量 JWT_SECRET（建议 `openssl rand -base64 32`）
2. 修复了 reset-password 路由（前端改为 /api/reset-password/confirm），需确认部署后功能正常
3. 旧密码兼容：SHA-256 用户首次登录后自动升级为 PBKDF2
4. all.js 操作员旧明文密码首次登录后自动升级
