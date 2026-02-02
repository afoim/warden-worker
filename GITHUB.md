# Cloudflare Worker 部署指南

本文档说明如何使用GitHub Actions自动部署Cloudflare Worker。

## 前置条件

在运行GitHub Action之前，您需要在GitHub仓库中配置以下环境变量：

### 必需的环境变量

1. **CLOUDFLARE_API_TOKEN**
   - 描述：Cloudflare API令牌，用于认证和部署
   - 获取方式：在Cloudflare仪表板中创建API令牌，需要包含以下权限：
     - Account: Workers Scripts: Edit
     - Account: Workers KV Storage: Edit  
     - Account: D1: Edit
     - User: User Details: Read

2. **CLOUDFLARE_ACCOUNT_ID**
   - 描述：您的Cloudflare账户ID
   - 获取方式：在Cloudflare仪表板的Overview页面找到Account ID

3. **JWT_SECRET**
   - 描述：JWT访问令牌签名密钥
   - 要求：至少32字符的随机字符串

4. **JWT_REFRESH_SECRET**
   - 描述：JWT刷新令牌签名密钥
   - 要求：至少32字符的随机字符串，与JWT_SECRET不同

5. **ALLOWED_EMAILS**
   - 描述：注册白名单，多个邮箱用英文逗号分隔
   - 示例：`user1@example.com,user2@example.com`
   - 特殊值：使用`*`表示允许所有邮箱注册

### 可选的环境变量

6. **TWO_FACTOR_ENC_KEY**（可选）
   - 描述：Base64编码的32字节密钥，用于加密存储TOTP秘钥
   - 如果不设置，TOTP秘钥将以明文形式存储（不推荐）

7. **D1_DATABASE_ID**（可选）
   - 描述：现有的D1数据库ID
   - 如果已存在数据库，可以设置此变量跳过数据库创建步骤

## 配置步骤

### 1. 在GitHub仓库中设置环境变量

1. 进入您的GitHub仓库
2. 点击 Settings → Secrets and variables → Actions
3. 点击 "New repository secret"
4. 为每个必需的环境变量添加对应的值

### 2. 手动触发部署

配置完成后，您可以：

1. 推送代码到main分支（自动触发）
2. 或者在GitHub仓库的Actions标签页中手动运行工作流

## 工作流执行流程

GitHub Action将按以下顺序执行：

1. **环境准备**：安装Node.js、Rust、Wrangler CLI等必要工具
2. **数据库创建**：创建新的D1数据库（如果D1_DATABASE_ID未设置）
3. **数据库初始化**：执行sql/schema_full.sql初始化数据库结构
4. **密钥配置**：配置JWT密钥、白名单等环境变量
5. **构建部署**：构建Worker并部署到Cloudflare

## 注意事项

- 首次部署时会创建新的D1数据库，后续部署会重用现有数据库
- sql/schema_full.sql会清空现有数据，仅适用于全新部署
- 如需保留数据，请使用sql/schema.sql进行增量更新
- 确保所有环境变量都已正确设置，否则部署会失败

## 故障排除

如果部署失败，请检查：

1. Cloudflare API令牌权限是否足够
2. 环境变量值是否正确
3. Cloudflare账户是否有效
4. 网络连接是否正常