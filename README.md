# 固定内网区域主备 DNS（FastAPI + SQLite + dnslib）

为固定内网区域 `internal.local`（可用 `DNS_ZONE` 修改）提供主备两台权威 DNS，
支持**按网段选址的 A 记录**（就近接入内部服务入口）：

- **主机 (primary)**：通过 REST API 接收一次提交、最多 8 条 A 记录的**完整区域**；
  每条记录带一个默认 IPv4，可再挂**最多 2 条 CIDR→IPv4 选址规则**；
  仅在整份区域校验并落库成功后才把序号 (serial) 加 1。发布不依赖备用机。
- **备用机 (backup)**：从主机 HTTP 拉取**整份版本**（含选址规则），支持手动同步、
  后台自动同步和版本查询；两机各自使用独立 SQLite 数据库（不同文件/卷）。
- 两机都通过 **UDP 端口（默认 5053）** 回答区域内 A 查询，每个回答只取自
  **一份不可变的完整版本**快照，绝不混版。

## 按网段选址（views）与 EDNS Client Subnet

每条记录 = 默认 IPv4 + 0~2 条 `CIDR → IPv4` 规则：

```json
{
  "name": "svc.internal.local",
  "ip": "192.0.2.1",
  "rules": [
    {"cidr": "10.1.0.0/16", "ip": "10.1.1.1"},
    {"cidr": "10.0.0.0/8",  "ip": "10.8.8.8"}
  ]
}
```

- **交叠按最长前缀选址**：客户端 `10.1.2.3` 命中 `10.1.0.0/16`（比 `/8` 更长）→
  `10.1.1.1`；`10.9.9.9` 只命中 `/8` → `10.8.8.8`；规则之外 → 默认 `192.0.2.1`。
- **直连 UDP 查询**按报文来源地址选址。
- **EDNS Client Subnet (ECS)** 仅当 UDP 来源属于 `TRUSTED_ECS_RESOLVERS`
  配置的网段时才采信；其余来源的 ECS 一律忽略，仍按来源地址选址，
  应答也不带 ECS 选项。
- **防跨网段缓存**：
  - 可信递归器上报的 ECS 前缀内若存在**不同选址结果**（如 `10.0.0.0/8`
    同时盖住 `10.1.0.0/16` 规则区和默认区），直接回 **SERVFAIL**（应答带
    ECS、scope=0），绝不给出可能被递归器跨网段缓存的 A 记录；
  - 成功应答的 ECS **scope 只覆盖选址结果一致的网段**：取客户端所在、
    结果唯一的最大 CIDR（例如客户端在 `10.0.0.0/8` 规则区但旁边有
    `10.1.0.0/16` 的"洞"，scope 会收缩到不含洞的边界，如上例应答
    scope=16 而不是 8）。
- 非法规则（CIDR 格式错、规则数超 2、重复 CIDR、`0.0.0.0/0`、IPv6 等）
  导致整份发布被 422 拒绝，**已发布区域不变、序号不升**。

## 设计要点与需求对应

| 需求 | 实现方式 |
| --- | --- |
| 单次提交 ≤8 条 A 记录的完整区域 | `app/models.py`：非空、≤8、仅 IPv4、名称必须在固定区域内、禁止重名 |
| 每服务名默认 IPv4 + ≤2 条 CIDR→IPv4 | `ViewRuleInput`/`RecordInput.rules`：CIDR 归一化、禁 `/0`、禁重复、仅 IPv4 |
| 交叠按最长前缀选址 | `app/views.py::select_answer`：命中规则中取 prefixlen 最长者 |
| 原有 A 记录仍可提交 | `rules` 缺省为 `[]`，旧报文/旧库记录原样可用 |
| 直连按来源地址选址 | `dns_server._client_view`：无（可信）ECS 时用 UDP 源地址 |
| 仅可信递归器采信 ECS | `TRUSTED_ECS_RESOLVERS` 启动时解析（非法配置启动即报错），来源不在列表则忽略 ECS |
| 前缀内结果不一 → SERVFAIL | `views.results_in_prefix` 枚举前缀内全部可能应答，>1 种即 SERVFAIL |
| 成功应答 scope 不覆盖不同结果网段 | `views.safe_scope`：从命中规则（或 0/0）逐位收缩到结果唯一的最大 CIDR |
| 非法规则不改变已发布区域 | 校验失败在进事务前返回 422；`next_publish()` 单事务提交，序号不变 |
| 发布成功才递增序号 | `Storage.next_publish()`：`BEGIN IMMEDIATE` 内插新版本并切换 active 指针 |
| 两机独立数据库 | 各自 `DB_PATH`（compose 中 `primary-data` / `backup-data` 两个卷） |
| 单次回答只用一份完整版本 | `zone_versions` 存不可变整份快照；解析前一次性读取 active 版本再查表 |
| 手动同步 + 版本查询 | `POST /api/sync`、`GET /api/version`、`GET /api/zone` |
| 慢传/断传期间沿旧版选址 | 传输失败（连接拒绝、超时、HTTP 错误、坏报文）不触碰 active 版本，旧版继续服务 |
| 坏报文不污染备用机 | 备用机对拉到的整份区域用同一套 `ZonePayload` 规则重新校验，非法即 `failed` |
| 断开/重启后自动追到最新版 | 备用机启动即拉取一次，之后按 `SYNC_INTERVAL` 后台循环，直到与上游同序号 |
| 迟到旧传输不得回退 | `commit_version()` 拒绝任何 `serial <= active_serial`（返回 `ignored_stale`/False） |
| 任一方失败仍供原版 | 发布失败保留旧 active；同步失败保留旧 active；DNS 与 HTTP 同进程独立运行 |
| 主机发布无需等待备用 | 主机 API 不调用备用机；e2e 中备用停机时发布仍在毫秒级成功 |
| Docker Compose 双服务 + Swagger | `docker-compose.yml` 起 primary/backup；`http://<host>:8080/docs`、`http://<host>:8081/docs` |

### 数据模型（SQLite，WAL 模式）

```
zone_versions(serial INTEGER PRIMARY KEY, records_json TEXT,
              record_count INTEGER, published_at TEXT)   -- 不可变整份版本
state(key TEXT PRIMARY KEY, value TEXT)
        active_serial      当前生效版本指针
        last_sync_*        备用机最近一次同步状态（at/status/error）
        upstream_serial    最近看到的上游序号
```

`records_json` 元素：`{"name", "ip", "rules": [{"cidr", "ip"}, ...]}`（`rules`
可缺省，兼容旧版本数据）。版本切换 = 插入新版本行 + 更新 `active_serial`
指针，在同一个事务里提交，外部观察到的永远是"某一份完整版本"。

## 端口与 API

| 角色 | API/Swagger | UDP DNS |
| --- | --- | --- |
| primary | 主机 8080 → 容器 8000 | 主机 5053 → 容器 5053/udp |
| backup  | 主机 8081 → 容器 8000 | 主机 5054 → 容器 5053/udp |

- `GET  /health` 健康检查
- `GET  /api/version` 角色、当前序号、记录数、备用机同步状态
- `GET  /api/zone` 当前完整区域（含 serial、records[].rules、published_at）
- `POST /api/zone` **仅主机**，成功返回 201 与新 serial
- `POST /api/sync` **仅备用机**，立即拉取一次，返回 `synced` / `ignored_stale` / `failed`

DNS 行为：区域内 A 查询命中返回 NOERROR+A（按网段选址）；区域内不存在的
名称 NXDOMAIN；区域内非 A 查询（如 AAAA）返回 NOERROR NODATA；区域外查询
REFUSED；可信 ECS 前缀内选址结果不唯一时 SERVFAIL。

## 运行方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 主机 Swagger:  http://localhost:8080/docs
# 备用 Swagger:  http://localhost:8081/docs
```

发布一份带选址规则的区域（纯 A 记录照旧可发）：

```bash
curl -sX POST http://localhost:8080/api/zone -H 'content-type: application/json' \
  -d '{"records":[
        {"name":"svc.internal.local","ip":"192.0.2.1","rules":[
          {"cidr":"10.1.0.0/16","ip":"10.1.1.1"},
          {"cidr":"10.0.0.0/8","ip":"10.8.8.8"}]},
        {"name":"db.internal.local","ip":"10.0.0.11"}]}'

curl -sX POST http://localhost:8081/api/sync   # 手动同步（后台也每 3 秒自动同步）
```

### 网段查询示例

直连查询按**本机来源地址**选址：

```bash
dig @127.0.0.1 -p 5053 svc.internal.local A +short
```

经递归器时，权威只采信来自 `TRUSTED_ECS_RESOLVERS` 的 ECS（compose 默认
放行 docker 网桥 `172.16.0.0/12`，便于宿主机直接验证）：

```bash
# 命中 10.1.0.0/16 规则 -> 10.1.1.1，应答 ECS scope=16
dig @127.0.0.1 -p 5053 svc.internal.local A +subnet=10.1.5.0/24

# 命中 10.0.0.0/8 规则（绕开 /16 的地址）-> 10.8.8.8，scope 收缩避开 /16 的洞
dig @127.0.0.1 -p 5053 svc.internal.local A +subnet=10.9.0.0/16

# 规则之外 -> 默认 192.0.2.1
dig @127.0.0.1 -p 5053 svc.internal.local A +subnet=198.51.100.0/24

# 前缀内选址结果不唯一 -> SERVFAIL（不会给出可被跨网段缓存的 A）
dig @127.0.0.1 -p 5053 svc.internal.local A +subnet=10.0.0.0/8

# 备用机同样按本机版本选址
dig @127.0.0.1 -p 5054 svc.internal.local A +subnet=10.1.5.0/24
```

### 本地直接运行（无 Docker 时）

```bash
python3 -m venv .venv --without-pip   # 或普通 venv
.venv/bin/pip install -r requirements.txt
DNS_ROLE=primary DB_PATH=./data/primary.db DNS_PORT=15053 API_PORT=18000 \
  TRUSTED_ECS_RESOLVERS=127.0.0.1 \
  .venv/bin/python -m uvicorn app.main:app --port 18000
DNS_ROLE=backup  DB_PATH=./data/backup.db  DNS_PORT=15054 API_PORT=18001 \
  PRIMARY_API_URL=http://127.0.0.1:18000 TRUSTED_ECS_RESOLVERS=127.0.0.1 \
  .venv/bin/python -m uvicorn app.main:app --port 18001
```

## 测试

```bash
.venv/bin/python -m pytest tests/test_unit.py tests/test_views_unit.py -q  # 校验/事务/选址/ECS 编解码
.venv/bin/python -I tests/e2e_test.py          # 主备端到端 30 项
.venv/bin/python -I tests/ecs_e2e_test.py      # 网段选址/ECS/缓存边界 39 项
.venv/bin/python -I tests/auto_sync_test.py    # 自动同步/幂等/Swagger 8 项
.venv/bin/python -I tests/slow_transfer_test.py  # 慢传输期间旧版持续服务
DB_PATH=./data/leakcheck.db .venv/bin/python -I tests/leak_check.py  # 连接泄漏检查
```

`ecs_e2e_test.py` 覆盖：交叠规则最长前缀选址、直连按源地址（绑定 127/8
不同源）、可信 ECS 的应答与 scope 边界（`/32` 扩展到一致区、`10.2.0.0/16`
收缩到 `/15` 避开规则洞）、跨结果前缀 SERVFAIL（`10.0.0.0/8`、`0.0.0.0/0`）、
不可信来源 ECS 被忽略、非法规则 422 且区域不变、断流期间备用机沿旧版
选址、恢复后追新版、迟到旧版本注入被拒。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DNS_ROLE` | `primary` | `primary` 或 `backup` |
| `DNS_ZONE` | `internal.local` | 固定内网区域名 |
| `DB_PATH` | `/data/dns.db` | 本机独立 SQLite 文件 |
| `DNS_PORT` / `API_PORT` | `5053` / `8000` | UDP DNS / HTTP 端口 |
| `PRIMARY_API_URL` | `http://primary:8000` | 备用机指向上机 API |
| `SYNC_INTERVAL` | `5` | 备用机后台同步间隔秒 |
| `HTTP_TIMEOUT` | `10` | 拉取区域 HTTP 超时秒 |
| `MAX_RECORDS` | `8` | 单次区域最大 A 记录数（按名称计） |
| `MAX_VIEW_RULES` | `2` | 每个名称最多几条 CIDR 选址规则 |
| `TRUSTED_ECS_RESOLVERS` | 空 | 可信递归器 IP/CIDR，逗号分隔；空=不采信任何 ECS |

## 已知边界

- 仅支持 A 记录与 IPv4（题目范围）；ECS 仅处理 IPv4 family，其他 family 忽略。
- 区域固定为一个；传输为整份区域拉取（无增量/AXFR 分帧）。
- 每条记录的选址规则上限 2 条（`MAX_VIEW_RULES` 可调）；`0.0.0.0/0` 不允许
  作为规则（等价语义请用默认 IPv4）。
- 同一请求出现多个 ECS 选项时取第一个；畸形 ECS 按"未携带"处理（不回 FORMERR）。
- 应答 TTL 固定 30s；SERVFAIL 应答带 ECS scope=0 表示无可缓存范围。
- 单机内嵌一个 UDP 解析线程与一个 uvicorn 进程；未做水平扩展与 TSIG 鉴权，
  内网部署时应限制 `/api/zone` 的调用来源，并把 `TRUSTED_ECS_RESOLVERS`
  收紧到真实递归器地址。
