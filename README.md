# YYB_GO

应用宝协议 —— 通过应用宝（YYB）的微信登录链路，为已授权的微信账号提供小程序
`wx.login` code、手机号、云函数等调用能力，并以 HTTP API 形式暴露。

## 运行

本地：

```bash
go run ./cmd/yyb-go -host 127.0.0.1 -port 8000 -resource-root ./resource
```

Docker（镜像由 GitHub Actions 自动发布到 GHCR）：

```bash
docker run -p 8000:8000 -v yyb-resource:/app/resource ghcr.io/justin0406/yyb_go
```

## 访问令牌（强烈建议）

服务默认不鉴权，仅建议绑定 `127.0.0.1` 本机使用。对外部署时请设置访问令牌：

```bash
docker run -e YYB_AUTH_TOKEN=your-secret -p 8000:8000 ...
# 或
./yyb-go -auth-token your-secret
```

设置后，`/qr`、`/accounts`、`/wxapp` 下的所有接口需要携带令牌，支持三种方式：

- `Authorization: Bearer <token>`
- `X-YYB-Token: <token>`
- URL 查询参数 `?token=<token>`（供 `<img>` 等无法自定义请求头的场景）

网页控制台用 `/?token=<token>` 或 `/scan?token=<token>` 打开一次即可，令牌会存入
localStorage 并从地址栏清除。

## 接口

- `POST /qr` 创建扫码会话，`GET /qr/{id}/poll` 轮询，`POST /qr/{id}/confirm` 确认入库
- `GET /accounts` 账号列表，`POST /accounts/refresh` 刷新存活，`POST /accounts/resync` 同步资料
- `POST /wxapp/getCode`、`POST /wxapp/getPhoneNumber`、`POST /wxapp/operateWxData`
- 完整文档：`/docs`（Swagger UI）、`/openapi.json`；健康检查：`/health`
