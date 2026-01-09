# Warden Worker

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务器。它利用 Cloudflare D1 作为数据库，使用 Rust 编写，旨在提供一个免费、无需维护且易于部署的个人密码管理解决方案。

## 🌟 功能特性

- **完全无服务器架构**：运行在 Cloudflare Workers 上，无需购买 VPS 或维护服务器。
- **低延迟数据库**：使用 Cloudflare D1 (基于 SQLite) 存储数据。
- **广泛的客户端兼容性**：
  - ✅ 官方 Bitwarden 浏览器扩展（Chrome, Edge, Firefox, Safari 等）。
  - ✅ 官方 Bitwarden 移动端应用（Android, iOS）。
  - ✅ 官方 Bitwarden 桌面端应用。
- **核心功能支持**：
  - 🔐 密码库管理（查看、添加、编辑、删除）。
  - 📂 文件夹管理。
  - 🔢 TOTP（两步验证码）生成与存储。
  - 🔄 多端同步。
- **免费托管**：充分利用 Cloudflare Workers 和 D1 的免费层额度，适合个人及家庭使用。

## 🚀 部署指南

### 前置要求

- 一个 [Cloudflare](https://www.cloudflare.com/) 账号。
- 安装 [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (`npm install -g wrangler`)。
- 安装 [Rust](https://www.rust-lang.org/tools/install) 开发环境。

### 1. 克隆项目

```bash
git clone https://github.com/your-username/warden-worker.git
cd warden-worker
```

### 2. 创建 D1 数据库

在 Cloudflare 上创建一个新的 D1 数据库：

```bash
wrangler d1 create vault1
```

执行成功后，控制台会输出 `database_id`。

### 3. 配置 Wrangler

打开项目根目录下的 `wrangler.jsonc` 文件，找到 `d1_databases` 配置块，将 `database_id` 替换为你刚才创建的 ID：

```jsonc
  "d1_databases": [
    {
      "binding": "vault1",
      "database_id": "你的_DATABASE_ID"
    }
  ],
```

### 4. 初始化数据库

使用提供的 SQL 脚本初始化数据库表结构：

```bash
# 初始化远程数据库（用于生产环境）
wrangler d1 execute vault1 --remote --file=sql/schema.sql
```

### 5. 设置环境变量

为了安全起见，需要设置以下环境变量。请使用 `wrangler secret put` 命令逐个设置：

- **`JWT_SECRET`**: 用于签发 JWT 访问令牌的密钥（建议生成一个随机的长字符串）。
- **`JWT_REFRESH_SECRET`**: 用于签发刷新令牌的密钥（建议生成一个随机的长字符串）。
- **`ALLOWED_EMAILS`**: 允许注册的邮箱白名单，多个邮箱用逗号分隔（例如 `me@example.com,family@example.com`）。**注意：不在列表中的邮箱将无法注册。**

```bash
wrangler secret put JWT_SECRET
# 输入你的密钥，回车

wrangler secret put JWT_REFRESH_SECRET
# 输入你的密钥，回车

wrangler secret put ALLOWED_EMAILS
# 输入允许注册的邮箱，回车
```

### 6. 部署项目

```bash
wrangler deploy
```

部署成功后，Wrangler 会输出你的 Worker 访问地址（例如 `https://warden-worker.你的子域名.workers.dev` 或你配置的自定义域名）。

## 💻 客户端配置

1. 下载并安装官方 Bitwarden 客户端（浏览器插件、手机 App 或桌面程序）。
2. 在登录界面的左上角或设置中，找到 **"自托管环境" (Self-hosted environment)** 设置。
3. 在 **"服务器 URL" (Server URL)** 字段中，输入你部署的 Worker 地址（例如 `https://warden.2x.nz`）。
4. 保存设置。
5. 点击 **"创建账号" (Create Account)**。
   - **注意**：注册的邮箱必须在 `ALLOWED_EMAILS` 环境变量配置的白名单中。
6. 注册完成后登录即可开始使用。

## 🛠️ 本地开发

如果你想在本地运行和调试：

1. **初始化本地数据库**：
   ```bash
   wrangler d1 execute vault1 --local --file=sql/schema.sql
   ```

2. **配置本地环境变量**：
   创建 `.dev.vars` 文件：
   ```env
   JWT_SECRET="local_dev_secret"
   JWT_REFRESH_SECRET="local_dev_refresh_secret"
   ALLOWED_EMAILS="test@example.com"
   ```

3. **启动本地服务器**：
   ```bash
   wrangler dev
   ```

## 📝 待办事项 / 已知限制

- 目前主要支持个人使用，组织分享功能尚未完善。
- 邮件发送功能目前仅打印日志，未对接实际邮件服务（注册验证主要依赖白名单机制）。
- 部分高级 Bitwarden 功能（如 Bitwarden Send）尚未实现。

## 🤝 贡献

欢迎提交 Issue 反馈 bug 或 提交 Pull Request 改进代码！

## 📄 许可证

本项目基于 MIT 许可证开源。
