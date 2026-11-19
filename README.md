# YYB_GO

应用宝（YYB）协议的 Go 实现：用手机微信扫码授权后，为已保存的微信账号提供小程序
`wx.login` code、手机号、云函数等能力的 HTTP 服务。

协议栈为纯 Go 实现（mmtls 握手、HybridECDH ManualAuth、PSK 0-RTT 短连接），不依赖
微信客户端；内置扫码登录、账号管理、凭据定时续期、上游请求保护与掉线通知。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up -d
```

镜像由 GitHub Actions 构建并发布到 GHCR（`linux/amd64` / `linux/arm64`）。启动后打开
<http://127.0.0.1:8000/>，用 `docker-compose.yml` 中的 `YYB_AUTH_USER` /
`YYB_AUTH_PASSWORD` 登录（默认 `admin` / `change-me-please`，**部署前务必修改**）。
把 `YYB_AUTH_PASSWORD` 置空即可关闭鉴权。

数据（SQLite 数据库、二维码、头像）在命名卷 `yyb-resource` 中；若想直接访问文件，把
`docker-compose.yml` 里的卷改成 `- ./data:/app/resource`。

### 源码运行

需要 Go 1.23+：

```bash
cd yyb_go
go run ./cmd/yyb-go -host 127.0.0.1 -port 8000
```

运行时目录默认是 `./resource`，首次启动会自动创建 `db/`、`qr/`、`avatars/` 等子目录。

## 配置

启动参数优先，环境变量兜底。

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-host` | — | `127.0.0.1` | 监听地址；容器内镜像默认 `0.0.0.0` |
| `-port` | — | `8000` | 监听端口 |
| `-resource-root` | — | `./resource` | 运行时资源目录 |
| `-db` | — | `yyb.db` | SQLite 文件名（位于 `<resource-root>/db/`） |
| `-tcp-proxy` | — | 空 | 出站 TCP 代理：`socks5://host:port` 或 `http-connect://host:port` |
| `-auth-user` | `YYB_AUTH_USER` | `admin` | 控制台登录用户名 |
| `-auth-password` | `YYB_AUTH_PASSWORD` | 空 | 登录密码；为空时**不启用鉴权** |
| `-cookie-secure` | `YYB_COOKIE_SECURE` | `false` | 会话 Cookie 加 `Secure` 标记；HTTPS 反向代理后部署时开启（直连 HTTPS 自动启用） |
| — | `YYB_NOTIFY_CHANNEL` | 空 | 掉线通知渠道：`serverchan` / `pushplus` / `wecom` |
| — | `YYB_NOTIFY_TOKEN` | 空 | 对应渠道的 SendKey / token / webhook key |
| — | `YYB_NOTIFY_TOPIC` | 空 | 通知分组（渠道支持时使用） |
| — | `YYB_CODE_DENY_APPIDS` | 空 | 追加取码黑名单，逗号分隔 |
| — | `YYB_CODE_ALLOW_APPIDS` | 空 | 放行 AppID（优先于内置与 `DENY` 名单），逗号分隔 |

`YYB_NOTIFY_CHANNEL` 与 `YYB_NOTIFY_TOKEN` 需同时设置，缺一时通知关闭并在启动日志中告警。
`YYB_CODE_*_APPIDS` 在进程启动时读取，修改后需重启服务。

## 鉴权

默认不鉴权，仅建议绑定 `127.0.0.1` 自用。对外暴露时设置 `YYB_AUTH_PASSWORD`：

- **浏览器**：打开首页会跳转 `/login`，登录后通过 HttpOnly、SameSite=Lax 的 Cookie
  维持会话（7 天，进程内存储，重启需重新登录）。`/logout` 退出。
- **脚本 / curl**：不经过登录页，用密码作为 Bearer 令牌：

```bash
curl -H "Authorization: Bearer $YYB_AUTH_PASSWORD" \
     -H 'Content-Type: application/json' \
     -d '{"ref":"1","app_id":"wx..."}' \
     http://127.0.0.1:8000/wxapp/getCode
```

受保护前缀：`/qr`、`/accounts`、`/wxapp`。`/health`、`/login`、`/docs`、`/openapi.json`
与页面外壳不鉴权（页面本身不含数据）。

公网部署建议在前面加一层 HTTPS 反向代理。

## 接口

响应统一为 `{"code":0,"msg":"success","data":...}` 信封；出错时 `code` 为 HTTP 状态码，
`msg` 为原因。完整契约见 `/docs`（Swagger UI）与 `/openapi.json`。

### 扫码登录

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/qr` | 创建扫码会话，返回 `session_id`、`status`、`image_url`；`?as_base64=true` 额外返回 data URI |
| `GET` | `/qr/{id}/image` | 二维码图片（JPEG） |
| `GET` | `/qr/{id}/poll` | 长轮询状态（最长约 35 秒）：`pending` / `scanned` / `authorized` / `confirmed` / `expired` / `cancelled` / `unknown` |
| `POST` | `/qr/{id}/confirm` | 授权完成后换取凭据并入库，返回账号信息 |

### 账号

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/accounts` | 账号列表（不含凭据） |
| `DELETE` | `/accounts?ref=...` | 删除账号 |
| `GET` | `/accounts/avatar?ref=...` | 头像；本地有缓存则直接返回，否则 302 到远程地址 |
| `POST` | `/accounts/refresh` | 刷新凭据与存活状态；不传 `ref` 时处理全部账号 |
| `POST` | `/accounts/resync` | 重新同步昵称与头像；不传 `ref` 时处理全部账号 |

`ref` 可以是账号 ID、UIN 或 openid。账号状态：`alive`（可用）、`expired`（授权失效，
需重新扫码）、`unknown`（网络等原因未判定）。

### 小程序能力

| 方法 | 路径 | 请求体 |
| --- | --- | --- |
| `POST` | `/wxapp/getCode` | `{"ref":"...","app_id":"..."}` |
| `POST` | `/wxapp/getPhoneNumber` | `{"ref":"...","app_id":"..."}` |
| `POST` | `/wxapp/operateWxData` | `{"ref":"...","app_id":"...","payload":{...}}` |

成功响应为 `{"openid":"...","result":{...}}`。

### 其他

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查，返回 `{"ok":true}` |
| `GET` | `/docs` | Swagger UI（重定向到 `/docs/index.html`） |
| `GET` | `/openapi.json` | OpenAPI 3.0 描述 |

## 错误码

脚本可按状态码决定是否重试：

| 状态码 | 含义 | 建议动作 |
| --- | --- | --- |
| `400` | 请求参数缺失或非法 | 修正请求 |
| `401` | 未登录 | 登录或补 Bearer 令牌 |
| `403` | `app_id` 在服务端黑名单中（网站应用不能用于取码，会打死授权） | 换小程序 AppID；确需使用设 `YYB_CODE_ALLOW_APPIDS` |
| `404` | 账号或扫码会话不存在 | 检查 `ref` |
| `409` | 账号授权已失效，刷新被拒 | **需重新扫码**，重试无用 |
| `429` | 本地流量控制拒绝（见下），请求未发往上游 | 按 `Retry-After` 退避后重试 |
| `502` | 上游调用失败（含会话恢复后仍失败） | 可稍后重试；持续失败查看日志 |

`409` 与 `429` 的区别很重要：`409` 是授权真的死了，重试只会加深风控；`429` 是本地
主动限流，账号状态未被改变。

## 上游保护

所有保护都只做流量控制，**不会修改账号状态或清除凭据**：

| 机制 | 默认值 | 作用 |
| --- | --- | --- |
| 同账号限速 | 间隔 3 秒，排队上限 20 秒 | 防止整点脚本突发；超限返回 `429` + `Retry-After: 3` |
| 取码熔断 | 同一 `(账号, app_id)` 连续 3 次空 code 冷却 10 分钟；5 分钟内 3 个不同 app_id 空码则整账号冷却 15 分钟 | 停止对已知失败的组合重复请求；命中返回 `429` + `Retry-After: 900` |
| 登录预算 | 每账号 10 分钟 3 次 OAuth 层调用 | 防止频繁重登触发风控；超限时以原错误失败 |
| 凭据续期 | 每 2 分钟检查，token 到期前 4 分钟续期 | 定时小额续期，替代"出错才刷新" |
| 登录票据 | 每次登录前用当前 access token 现取 | 票据寿命短于 token，现取可避免首登失败与多余的凭据轮换 |
| AppID 黑名单 | 内置电脑管家、京东护照等网站应用 | 这类 AppID 取码会在数秒内使账号授权失效 |

一次成功取码会立即清除该账号的熔断状态。`/accounts/refresh` 不受登录预算限制。

## 脚本集成

配套脚本（青龙等）通过环境变量 `YYB_SERVER` 寻址，一行一个账号：

```bash
# 地址@账号标识（ID / UIN / openid）
export YYB_SERVER='http://yyb-go:8000@1'
```

同一 Docker 网络内可直接用容器名。若服务开启了密码，脚本侧需带 Bearer 令牌（见「鉴权」）。

## 数据与备份

| 路径 | 内容 |
| --- | --- |
| `<resource-root>/db/yyb.db` | 账号、凭据、会话缓存、设备身份种子 |
| `<resource-root>/qr/` | 扫码会话图片（自动清理） |
| `<resource-root>/avatars/` | 头像缓存 |

数据库中的凭据与令牌为明文存储（协议要求），**该文件等同于微信账号凭证**，备份与
迁移时按密钥处理。

## 开发

```bash
cd yyb_go
go build ./...
go vet ./...
go test -race ./...
```

`internal/protocol` 为协议层（不含 HTTP），`internal/httpapi` 为接口与业务编排，
`internal/store` 为 SQLite 持久化，`internal/qr` 为扫码会话。
