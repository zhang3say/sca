# Task Checklist: CH 07 产品架构与工程技术设计课程（Phase 4）

Source spec: `SPEC-ch07-product-and-tech-design.md` | Plan: `tasks/plan.md`

---

## Task 1: 工作区基线升级、Phase 4 样式骨架与学习记录更新

**Description:** 将教学工作区从 3 阶段 22 课平稳扩展为 4 阶段 27 课基线：修订 `MISSION.md` 纳入 CH 07 产品与工程设计范围，新增 `learning-records/0003-solo-ai-agent-go-python-dual-mode.md` 记录「1 人 + AI Agent / Go+Python / 双模兼容 / 模式 A」新约束，在 `assets/tufte-course.css` 补充 `.phase-divider.phase-4` 样式，并在 `index.html` 与 `NOTES.md` 加入 Phase 4 / CH 07 课程大纲（新增 `PROD` 层级筛选胶囊，`0023` 设为下一课 ZPD，`0024`–`0027` 设为规划中）。

**Acceptance criteria:**
- [x] `MISSION.md` 与 `learning-records/0003-solo-ai-agent-go-python-dual-mode.md` 准确反映 Solo+AI / Go+Python / 双模约束及扩展后的边界，仍保持精简可读。
- [x] `index.html` 新增 `PROD` 筛选胶囊、Phase 4 分割条与 CH 07 卡片（`0023` 为 `next`，`0024`–`0027` 为 `planned`），筛选按钮计数准确反映当前状态且已发布 `0001`–`0022` 链接零破坏。
- [x] `assets/tufte-course.css` 包含 `.phase-divider.phase-4` 样式，`NOTES.md` 同步更新为 4 阶段 7 章 27 课大纲。

**Verification:**
- [x] Static check: `for f in assets/*.js; do node --check "$f" || exit 1; done` 及 Python 相对链接检查通过。
- [x] Browser UI/UX check: 本地启动 `python3 -m http.server` 访问 `index.html`（1280px & 375px），验证无控制台报错、无横向溢出、点击 `Phase 4` 与 `PROD` 筛选胶囊计数与隐藏逻辑精确工作。

**Dependencies:** None

**Files likely touched:**
- `MISSION.md`
- `learning-records/0003-solo-ai-agent-go-python-dual-mode.md`
- `assets/tufte-course.css`
- `index.html`
- `NOTES.md`

**Estimated scope:** Medium (5 files)

### Checkpoint 1: 工作区基线与首页筛选门禁
- [x] `index.html` 筛选器（`all` / `p4` / `PROD` / `SYS` / `next` / `planned`）全部工作准确
- [x] 1280px 与 375px 浏览器渲染无横向溢出、无控制台报错

---

## Task 2: Lesson 0023（产品域模型、五角色旅程与核心闭环）+ 交互实验台 + Ref 08 启篇

**Description:** 调研并核验一手标准（CycloneDX 1.7、OpenVEX、SPDX 3.0.1、Dependency-Track v5 域对象、OWASP SAMM 等）写入 `RESOURCES.md`。编写第 23 课微课与交互实验台 `assets/product-domain-lab.js`（产品域对象关联仿真 + 五类角色闭环旅程 + SKU Entitlement 策略门切换），同步创建 `reference/ch7-product-arch-and-tech-design-matrix.html`（Ref 08 启篇，沉淀域模型字典与闭环矩阵），更新 `index.html`（`0023` → `ready`、`0024` → `next`）与 `NOTES.md`。

**Acceptance criteria:**
- [x] `lessons/0023-product-domain-model-and-persona-workflows.html` 讲清 `Tenant → Workspace → Project → Asset → Snapshot → Finding → Policy/Waiver → Remediation` 产品域对象分离、五角色 4 条主闭环及 SaaS/私有化统一 Feature Entitlement 网关，与 `0002`/`0022` 零内容重叠。
- [x] `assets/product-domain-lab.js` 零外部依赖正常运行，主动回忆测验 4 题选项字数差 ≤ 6 且 `answerIndex` 分散。
- [x] `reference/ch7-product-arch-and-tech-design-matrix.html`（Ref 08）完成第 01–02 节并在 `index.html`、`NOTES.md` 同步链接。

**Verification:**
- [x] Content accuracy check: 核验所有引用标准/开源参考源并在 `RESOURCES.md` 登记来源与许可。
- [x] Static check: `node --check assets/*.js` 与 Python Quiz/链接检查全部通过。
- [x] Browser UI/UX check: 本地 HTTP 服务实测 `0023`、`Ref 08` 与 `index.html`（1280px & 375px），确认零控制台错误、零横向溢出、实验台切换与测验计分交互正常，随后执行 `git add -A && git commit && git push`。

**Dependencies:** Task 1

**Files likely touched:**
- `RESOURCES.md`
- `assets/product-domain-lab.js`
- `lessons/0023-product-domain-model-and-persona-workflows.html`
- `reference/ch7-product-arch-and-tech-design-matrix.html`
- `index.html`, `NOTES.md`

**Estimated scope:** Medium (5–6 files)

### Checkpoint 2: Lesson 0023 双门禁核验与发布
- [x] 内容准确性核验通过（一手源已登记 `RESOURCES.md`，无重复 `0002`/`0022`）
- [x] 静态脚本检查通过（JS 语法 + Quiz 均衡 + 相对链接）
- [x] 真实浏览器 1280px & 375px UI/UX 交互与溢出检查通过
- [x] 已同步 `Ref 08`、`index.html`、`NOTES.md` 并推送 `origin/main`

---

## Task 3: Lesson 0024（1 人 + AI 模块化单体、Go↔Python 契约与快慢双路径任务编排）+ 交互实验台 + Ref 08 第 03 节

**Description:** 查验并登记一手源（ConnectRPC / Protobuf、PostgreSQL `FOR UPDATE SKIP LOCKED`、River 协议边界、NATS JetStream、Apache Kafka、Temporal MIT、Go `errgroup` / Python `asyncio`/Process Pool 等）。编写第 24 课微课与 `assets/service-orchestration-lab.js`（模块化单体拆分边界对比 + 快路径/慢路径队列与背压限流沙盘），扩展 Ref 08 第 03 节并同步 `index.html`（`0024` → `ready`、`0025` → `next`）与 `NOTES.md`。

**Acceptance criteria:**
- [x] `lessons/0024-solo-ai-modular-monolith-and-scan-orchestration.html` 讲清「1 人 + AI」为何首选 Go 模块化单体 + Python 独立 Worker 进程而非早产微服务、Protobuf/ConnectRPC 强类型跨语言边界、三段式队列演进（PG `SKIP LOCKED` → NATS JetStream → Kafka）、快慢双路径隔离、状态机与幂等防雪崩。
- [x] 所有引用工具与队列组件均经一手仓库核实并标明精确开源协议（含 River `MPL-2.0` 边界、ConnectRPC `Apache-2.0`、NATS `Apache-2.0`）。
- [x] 交互实验台与 4 题测验符合规范，`Ref 08` 新增第 03 节并双向互链。

**Verification:**
- [x] Content accuracy check: 逐条核对一手源与开源协议写入 `RESOURCES.md`。
- [x] Static check: `node --check assets/*.js` 与 Python Quiz/链接检查通过。
- [x] Browser UI/UX check: 本地 HTTP 服务在 1280px & 375px 实测 `0024`、`Ref 08` 与 `index.html`，通过后 `git commit && git push`。

**Dependencies:** Task 2

**Files likely touched:**
- `RESOURCES.md`
- `assets/service-orchestration-lab.js`
- `lessons/0024-solo-ai-modular-monolith-and-scan-orchestration.html`
- `reference/ch7-product-arch-and-tech-design-matrix.html`
- `index.html`, `NOTES.md`

**Estimated scope:** Medium (5–6 files)

### Checkpoint 3: Lesson 0024 双门禁核验与发布
- [x] 内容准确性核验通过（Go↔Python 契约与队列组件协议经一手查验）
- [x] 静态脚本检查通过
- [x] 真实浏览器 1280px & 375px UI/UX 交互与溢出检查通过
- [x] 已同步 `Ref 08`、`index.html`、`NOTES.md` 并推送 `origin/main`

---

## Task 4: Lesson 0025（多租户隔离、Finding 稳定指纹状态机与 Transactional Outbox 一致性）+ 交互实验台 + Ref 08 第 04 节

**Description:** 查验并登记一手源（PostgreSQL 16+ Row-Level Security、`FORCE ROW LEVEL SECURITY` / `NOBYPASSRLS`、`sqlc` MIT、`pgx` MIT、Transactional Outbox 模式、Debezium `Apache-2.0`、ClickHouse `ReplacingMergeTree` `Apache-2.0`）。编写第 25 课微课与 `assets/multitenant-consistency-lab.js`（多租户 RLS 隔离/防泄漏模拟器 + Finding 稳定指纹与状态机演化沙盘 + Outbox 一致性演示），扩展 Ref 08 第 04 节并同步 `index.html`（`0025` → `ready`、`0026` → `next`）与 `NOTES.md`。

**Acceptance criteria:**
- [x] `lessons/0025-multitenant-storage-finding-lifecycle-and-consistency.html` 讲清“一套 PG Schema 同时跑 SaaS 多租户与私有化单租户”的 `tenant_id` + RLS + Go 连接池事务注入机制、Finding 跨目录重构/分支切换的稳定指纹与 Waiver/VEX 继承状态机、Transactional Outbox 同步 ClickHouse/RoaringBitmap 原理，以及 Python Worker 只读或经 Go 控制面受控落库的写入防绕过边界。
- [x] 不重复 `0021` 的 CAS 去重与 `CYCLE` 查询内容，只聚焦在多租户安全隔离、Finding 生命周期与多存储事务一致性。
- [x] 交互实验台、4 题测验与 `Ref 08` 第 04 节全部完成并互链。

**Verification:**
- [x] Content accuracy check: 核验 PG RLS、`sqlc`/`pgx`、ClickHouse 引擎与 Outbox 一手资料并更新 `RESOURCES.md`。
- [x] Static check: `node --check assets/*.js` 与 Python Quiz/链接检查通过。
- [x] Browser UI/UX check: 本地 HTTP 服务在 1280px & 375px 实测 `0025`、`Ref 08` 与 `index.html`，通过后 `git commit && git push`。

**Dependencies:** Task 3

**Files likely touched:**
- `RESOURCES.md`
- `assets/multitenant-consistency-lab.js`
- `lessons/0025-multitenant-storage-finding-lifecycle-and-consistency.html`
- `reference/ch7-product-arch-and-tech-design-matrix.html`
- `index.html`, `NOTES.md`

**Estimated scope:** Medium (5–6 files)

### Checkpoint 4: Lesson 0025 双门禁核验与发布
- [x] 内容准确性核验通过（PG RLS / Outbox / 协议与版本准确）
- [x] 静态脚本检查通过
- [x] 真实浏览器 1280px & 375px UI/UX 交互与溢出检查通过
- [x] 已同步 `Ref 08`、`index.html`、`NOTES.md` 并推送 `origin/main`

---

## Task 5: Lesson 0026（双模交付、Hybrid Runner、Air-Gapped 私有化与企业级权限开放平台）+ 交互实验台 + Ref 08 第 05 节

**Description:** 查验并登记一手源（SPIFFE/SPIRE `Apache-2.0`、SeaweedFS `Apache-2.0` vs MinIO `AGPL-3.0`、Garage `AGPL-3.0`、Valkey `BSD-3-Clause` vs Redis `RSALv2/SSPLv1/AGPLv3`、OIDC & SCIM 2.0 RFC 7643/7644、Ed25519 RFC 8032、Webhook HMAC-SHA256 与 SSRF 防护实践、Helm `Apache-2.0`）。编写第 26 课微课与 `assets/dual-mode-deploy-lab.js`（三种部署拓扑切换模拟器 + RBAC/ABAC 与基础设施许可排雷检查台），扩展 Ref 08 第 05 节并同步 `index.html`（`0026` → `ready`、`0027` → `next`）与 `NOTES.md`。

**Acceptance criteria:**
- [x] `lessons/0026-dual-mode-deployment-hybrid-runner-and-rbac-platform.html` 讲清如何用同一套代码与配置抽象兼容公有云 SaaS、Hybrid Runner（源码不出内网，Outbound-only mTLS 回传脱敏 IR）、以及 Air-Gapped 极简私有化（Docker Compose 单机 / K8s Helm + Ed25519 离线商用 License 签发与 Feature Flag 校验）；讲透 RBAC + ABAC 资产范围树、OIDC/SCIM 组织同步、不可篡改审计日志与防 SSRF Webhook 开放契约；并给出基础设施商用许可红线替换表（严避 MinIO `AGPL-3.0` / Redis `SSPL` 等）。
- [x] 不重复 `0009` 的 `bbolt`/SQLite 漏洞包内部构造，聚焦全系统级运行时依赖与双模交付架构。
- [x] 交互实验台、4 题测验与 `Ref 08` 第 05 节全部完成并互链。

**Verification:**
- [x] Content accuracy check: 逐个验证基础设施最新开源许可（MinIO/SeaweedFS/Valkey/Redis/SPIFFE）并登记 `RESOURCES.md`。
- [x] Static check: `node --check assets/*.js` 与 Python Quiz/链接检查通过。
- [x] Browser UI/UX check: 本地 HTTP 服务在 1280px & 375px 实测 `0026`、`Ref 08` 与 `index.html`，通过后 `git commit && git push`。

**Dependencies:** Task 4

**Files likely touched:**
- `RESOURCES.md`
- `assets/dual-mode-deploy-lab.js`
- `lessons/0026-dual-mode-deployment-hybrid-runner-and-rbac-platform.html`
- `reference/ch7-product-arch-and-tech-design-matrix.html`
- `index.html`, `NOTES.md`

**Estimated scope:** Medium (5–6 files)

### Checkpoint 5: Lesson 0026 双门禁核验与发布
- [x] 内容准确性核验通过（全部基础设施开源许可与标准协议经一手核实）
- [x] 静态脚本检查通过
- [x] 真实浏览器 1280px & 375px UI/UX 交互与溢出检查通过
- [x] 已同步 `Ref 08`、`index.html`、`NOTES.md` 并推送 `origin/main`

---

## Task 6: Lesson 0027（SCA 黄金样本回归评测 Benchmark Harness、OTel 剖析与 AI-Friendly Monorepo/Spec 落地）+ 交互实验台 + Ref 08 收官

**Description:** 查验并登记一手源（OpenTelemetry Go & Python SDK `Apache-2.0`、Buf CLI/Schema Registry `Apache-2.0`、OpenAPI 3.1 + `oapi-codegen` `Apache-2.0`、MADR 架构决策记录标准、SCA 黄金样本评测指标规范）。编写第 27 课微课与 `assets/eval-observability-lab.js`（AI 改动后的 Precision/Recall/F1/P95 延迟回归门禁模拟器 + OTel 扫描阶段火焰/耗时剖面器 + 90 天垂直切片导航），完成 Ref 08 第 06 节全章收官，最终更新 `index.html`（`27 / 27 课 · 8 / 8 速查卡 · 4 阶段 7 章节全收官`）与 `NOTES.md`。

**Acceptance criteria:**
- [x] `lessons/0027-sca-benchmark-harness-observability-and-ai-spec-repo.html` 讲透「1 人 + AI Coding Agent」模式下如何防止 AI 在重构解析器/版本匹配器/可达性时引入静默精度回退（黄金样本 Ground-Truth Benchmark Harness + 误报/漏报/P95 延迟门禁）、OpenTelemetry 跨 Go↔Python `traceparent` 全链路扫描耗时剖析、AI 友好的 Go + Python + Protobuf 强契约 Monorepo 目录与 ADR 约定，以及前 90 天可独立交付的垂直切片 Spec 框架。
- [x] `reference/ch7-product-arch-and-tech-design-matrix.html`（Ref 08）完整覆盖 `0023`–`0027` 全部 6 节并标明 CH 07 & 全课程 27 课收官。
- [x] `index.html` 更新为 27 / 27 课、8 / 8 速查卡，`0027` 设为已发布，顶部和底部导航全部指向最新版本且筛选器 `all (27)` / `p4 (5)` / `PROD (5)` 精确匹配。

**Verification:**
- [x] Content accuracy check: 核验 OTel / Buf / OpenAPI / MADR 一手资料并完善 `RESOURCES.md`。
- [x] Static check: 对全仓 CH 07（`0023`–`0027` + `Ref 08` + `index.html`）运行 `node --check` 与 Python 校验脚本，零报错。
- [x] Browser UI/UX check: 本地 HTTP 服务在 1280px & 375px 实测 `0027`、`Ref 08` 与 `index.html`（验证 27/27 计数、`p4 (5)`、`PROD (5)` 筛选及 `0023`↔`0027`↔`Ref 08` 双向跳转），全部通过后执行 `git add -A && git commit && git push`。

**Dependencies:** Task 5

**Files likely touched:**
- `RESOURCES.md`
- `assets/eval-observability-lab.js`
- `lessons/0027-sca-benchmark-harness-observability-and-ai-spec-repo.html`
- `reference/ch7-product-arch-and-tech-design-matrix.html`
- `index.html`, `NOTES.md`

**Estimated scope:** Medium (5–6 files)

### Checkpoint 6: 全章收官总门禁与发布
- [x] 0027 内容准确性核验通过
- [x] 全 CH 07 静态检查（JS 语法 + 5 课测验均衡 + 全量相对链接）零报错
- [x] 真实浏览器 1280px & 375px 全量 UI/UX 与 `index.html` 筛选计数验证通过
- [x] `Ref 08`、`index.html`、`NOTES.md` 全量收官同步并已推送 `origin/main`
