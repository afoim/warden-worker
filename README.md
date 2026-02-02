# Warden Worker

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）作为数据存储，核心代码用 Rust 编写，目标是“个人/家庭可用、部署成本低、无需维护服务器”。

本项目不接触你的明文密码：Bitwarden 系列客户端会在本地完成加密，服务端只保存密文数据。

> [!WARNING]
> 如果你曾经部署过旧版本并准备升级，建议在客户端导出密码库 → 重新部署本项目（全新初始化数据库）→ 再导入密码库（可显著降低迁移/兼容成本）。

## 功能

- 无服务器部署：Cloudflare Workers + D1
- 兼容多端：官方 Bitwarden（浏览器扩展 / 桌面 / 安卓）与多数第三方客户端
- 核心能力：注册/登录、同步、密码项（Cipher）增删改、文件夹、TOTP（Authenticator）二步验证
- 官方安卓兼容：支持 `/api/devices/knowndevice` 与 remember-device（twoFactorProvider=5）流程

## 自动部署（Github Action）

### 0. 前置条件
- Cloudflare 账号 + R2数据库
- Github 账号 + Action构建权

### 1. 部署仓库 

1. 点击[Fork本项目](https://github.com/PIKACHUIM/warden-worker/fork)，克隆到你的Github账号
![QQ20260127-153440.jpg](images/QQ20260127-153440.jpg)

2.
2. 
![QQ20260127-150742.jpg](images/QQ20260127-150742.jpg)



## 手动部署（Cloudflare）

### 0. 前置条件

- Cloudflare 账号
- Node.js + Wrangler：`npm i -g wrangler`
- Rust 工具链（建议稳定版）
- 安装 worker-build：`cargo install worker-build`

### 1. 创建 D1 数据库

```bash
wrangler d1 create cfwarden-db
```

把输出的 `database_id` 写入 `wrangler.jsonc` 的 `d1_databases`。

### 2. 初始化数据库

注意：`sql/schema_full.sql` 会 `DROP TABLE`，仅用于全新部署（会清空数据）。

```bash
wrangler d1 execute cfwarden-db --remote --file=sql/schema_full.sql
```

`sql/schema.sql` 仅保留为历史/兼容用途；推荐新部署直接使用 `sql/schema_full.sql`。

### 3. 配置密钥（Secrets）

```bash
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put TWO_FACTOR_ENC_KEY
```

- JWT_SECRET：访问令牌签名密钥
- JWT_REFRESH_SECRET：刷新令牌签名密钥
- ALLOWED_EMAILS：注册白名单，多个邮箱用英文逗号分隔；可使用 `*` 表示允许所有邮箱注册
- TWO_FACTOR_ENC_KEY：可选，Base64 的 32 字节密钥；用于加密存储 TOTP 秘钥（不设置则以 `plain:` 形式存储）

### 4. 部署

```bash
wrangler deploy
```

部署后，把 Workers URL 或自定义域名（例如 `https://warden.2x.nz`）填入 Bitwarden 客户端的“自托管服务器 URL”。

## 客户端使用建议

- 官方安卓如果之前指向过其它自托管地址，建议“删除账号/清缓存后重新添加服务器”，避免 remember token 跨服务端复用导致登录失败。
- 首次启用 TOTP 后，建议在同一台设备上完成一次“输入 TOTP 登录”，后续官方安卓会自动走 remember-device（provider=5）。

## 已实现的关键接口（部分）

- 配置与探测：`GET /api/config`、`GET /api/alive`、`GET /api/now`、`GET /api/version`
- 登录：`POST /identity/accounts/prelogin`、`POST /identity/connect/token`
- 同步：`GET /api/sync`
- 密码项：`POST /api/ciphers/create`、`PUT /api/ciphers/{id}`、`PUT /api/ciphers/{id}/delete`
- 文件夹：`POST /api/folders`、`PUT /api/folders/{id}`、`DELETE /api/folders/{id}`
- 2FA：`GET /api/two-factor`、`/api/two-factor/authenticator/*`
- 官方安卓设备探测：`GET /api/devices/knowndevice`

## 本地开发

```bash
wrangler d1 execute cfwarden-db --local --file=sql/schema_full.sql
wrangler dev
```

本地可用 `.dev.vars`（Wrangler 支持）注入 secrets。

## 许可证

MIT
