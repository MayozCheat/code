# 网络验证系统架构说明

本仓库包含两套服务器逻辑（同一代码仓内维护）：

1. **`src/vendor` 相关路由**：作为“总控服务器”（Vendor Control Plane）。
2. **其余 `src/app + src/services` 主体**：作为“开发者使用的 EXE 所连接的业务服务器”（Auth/API Plane）。

下面按“调用关系 + 数据流”梳理。

---

## 1) 整体调用关系（高层）

```text
┌────────────────────────────┐
│ 总控服务器（vendor routes） │
│  - /vendor/check            │
│  - /vendor/activate         │
│  - /admin/vendor/*          │
└──────────────┬─────────────┘
               │ HMAC 签名校验 + nonce/ts 防重放
               │
               ▼
┌─────────────────────────────────────────────────────┐
│ 开发者业务服务器（main/app/services）               │
│ 启动时调用 VendorClient::CheckOrExit               │
│   -> POST /vendor/check                             │
│ 若失败则退出，若成功才启动 8080 API                  │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
    开发者工具/EXE 调用业务 API（/login /card/activate /license/check 等）
```

关键点：**业务服务器依赖总控服务器“放行”后才启动**，这构成了上游授权门禁。

---

## 2) 启动链路（谁先调用谁）

### 2.1 业务服务器启动流程（`src/main.cpp`）

- 在启动 HTTP 服务前，先读取 `vendorUrl/vendorKey/vendorSecret/machine`。
- 调用 `VendorClient::CheckOrExit(...)`。
- 仅当总控校验成功，才继续初始化 `DbPool / Services / Router / HttpServer` 并监听 `0.0.0.0:8080`。

这意味着：

- 总控不可用或校验失败时，业务服务器不会对外提供 API。
- 总控是业务服务实例的“运行许可证中心”。

### 2.2 业务服务器到总控的请求结构（`VendorClient`）

`VendorClient` 会向总控发起 `POST /vendor/check`，字段包含：

- `vendor_key`
- `machine_code`
- `ts`（Unix 秒）
- `nonce`（随机）
- `sign`（HMAC-SHA256）

签名载荷格式：

```text
METHOD + "\n" + PATH + "\n" + canonical_fields
```

其中 canonical 是按 key 排序拼接（不含 `sign`）。

---

## 3) 总控服务器（`src/vendor`）职责

总控主路由在 `SetupVendorRoutes(...)` 注册，核心分为三层职责：

1. **实例授权校验**
   - `POST /vendor/check`
   - 对业务服务器启动授权进行验签、时钟窗口校验、nonce 防重放、机器码绑定、过期检查。

2. **续期/开通能力**
   - `POST /vendor/activate`
   - 使用 `vendor_card` 对 `vendor_license` 增加时长（续期）。

3. **总控后台管理**
   - `/admin/vendor/card/*`：创建/禁用/备注/列表
   - `/admin/vendor/license/*`：总控 license 列表与封禁
   - `/admin/vendor/log/list`：查看总控侧审计日志

### 3.1 总控侧安全校验顺序（`/vendor/check`）

总控对 `POST /vendor/check` 的典型顺序是：

1. 基础字段合法性检查。
2. `ts` 在允许窗口内（默认 ±60 秒）。
3. DB 事务读取 `vendor_license`（含 `vendor_secret`）。
4. 用该 `vendor_secret` 验证 `sign`。
5. 验签通过后插入 `vendor_nonce`（防重放）。
6. 检查状态（是否封禁）、是否过期、机器码绑定/一致性。
7. 写 `vendor_log` 审计并返回结果。

这条链路保证了：**签名、时效、防重放、设备绑定**同时生效。

---

## 4) 业务服务器（给 EXE 用）职责

业务接口由 `Router::bind(...)` 注册，主要是：

- 会话认证：`POST /login`
- 卡密激活：`POST /card/activate`
- 授权检查：`POST /license/check`
- 管理接口：`/admin/card/*`、`/admin/user/*`、`/admin/log/list`

除 `login` 之外，多数敏感 POST 接口先经过 `RequireSign(...)`，即 `SignService::verify(...)` 进行签名验真。

### 4.1 业务侧授权数据流（EXE 常见路径）

```text
EXE/客户端
  └─ POST /login
       └─ SessionService 校验账号密码并生成 token

EXE/客户端
  └─ POST /card/activate (token + machine_code + card_key + sign)
       └─ CardService 执行卡密激活/机器绑定

EXE/客户端
  └─ POST /license/check (token + machine_code + sign)
       └─ LicenseService: token -> user -> status/machine/expire_time
       └─ 返回 valid / reason / expire_time
```

---

## 5) 两套服务器的边界定义（你当前描述的落地版）

- **总控（`vendor`）**：控制“服务器是否有资格运行”，管理开发者 license 与续期卡，偏平台治理。
- **业务（其余模块）**：服务最终 EXE/客户端登录与授权校验，偏业务访问控制。

可理解为：

- 总控管“**服**”（server instance / developer server）。
- 业务管“**人和端**”（end user / machine / token / card）。

---

## 6) 建议的联调检查清单

1. 先启动总控（确保 `/vendor/check` 可达）。
2. 启动业务服务器，确认日志打印 `Vendor OK` 后再监听 `8080`。
3. 再做 EXE 侧 `login -> activate -> license/check` 调用链测试。
4. 校验异常场景：
   - 修改签名（应 401）
   - 重放 nonce（应失败）
   - 改机器码（应 machine_mismatch）
   - 总控 license 过期或禁用（业务启动应失败）
