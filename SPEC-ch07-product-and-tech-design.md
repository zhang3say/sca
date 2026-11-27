# Spec: CH 07 产品架构与工程技术设计课程 — V1

Status: approved (V1)

## Objective

在已完成的前 22 课（Ch 01–06，聚焦 SCA 领域内核与商业策略）基础上，新增 **Phase 4 · CH 07「产品架构与工程技术设计」**（5 节高密度交互微课 `0023`–`0027` + 5 个交互实验台 + 1 份可打印速查卡 `Ref 08`）。

**核心目标**：解决“懂了 SCA 算法与标准之后，如何作为 **1 人架构师 + AI Coding Agents** 团队，使用 **Go + Python** 从第一天起就兼容 **SaaS 多租户 / Hybrid Runner / Air-Gapped 极简私有化** 双模交付，打造出一套可实际立项编码、不崩雪崩、不串租户、防 AI 静默回归的企业级 SCA 软件系统”的工程断层。

### 与既有课程的严格防重叠边界

| 既有课程 | 已覆盖内容（CH 07 不重复） | CH 07 聚焦的增量产品与工程设计 |
|---|---|---|
| `0002` Layer 2 IR | PURL 编码、成分与依赖图逻辑模型、CycloneDX/SPDX 双向投影 | 上层产品业务对象域（`Tenant → Workspace → Project → Asset → Snapshot → Finding → Waiver → Remediation`）与 SKU Entitlement |
| `0006` 多触点采集 | Agent MCP/Hook/LSP、PR Diff 入口、Hyades/Kafka 概念流水线 | 控制面与数据面物理部署切分、模块化单体架构、Go↔Python 契约与快慢双路径队列调度 |
| `0009` 离线漏洞库 | `bbolt`/SQLite 漏洞包增量构建与分发格式 | 全系统级双模部署（Hybrid Runner、单机 Compose / K8s Helm、离线 License 签发与基础设施商用许可排雷） |
| `0021` 海量台账 | CAS 图去重、Hot/Warm/Cold 分流、`RoaringBitmap` + PG `CYCLE` 10s 定损 | PostgreSQL `tenant_id` + RLS 多租户隔离、Finding 跨重构指纹与豁免继承、Transactional Outbox 多存储一致性 |
| `0022` 商业总装 | 「一核三阶」SKU 分层、EU CRA/S2C2F、Team Topologies 配比、五大竞品打法 | 面向「1 人 + AI Agent」的黄金样本回归基准（Benchmark Harness）、OTel 全链路剖析与 Go+Python Monorepo/Spec 落地规范 |

### 课程矩阵总览（Phase 4 · CH 07）

| 课号 | 目标文件与交互实验台 | 层级标签 | 时长 | 核心产品与工程决策命题 |
|---|---|---|---|---|
| **0023** | `lessons/0023-product-domain-model-and-persona-workflows.html`<br/>`assets/product-domain-lab.js` | `PROD,SYS,L2` | ~18 min | **产品域模型与五角色端到端闭环**：统一业务对象模型（`Tenant` 到 `Waiver/Remediation`）、五类角色核心旅程与 4 条闭环流、SKU Feature Entitlement 网关、SaaS 与私有化一致体验契约。 |
| **0024** | `lessons/0024-solo-ai-modular-monolith-and-scan-orchestration.html`<br/>`assets/service-orchestration-lab.js` | `PROD,SYS,L1,L4` | ~20 min | **1 人 + AI 模块化单体与任务编排**：Go 控制面/扫描 Worker + Python 专项 Worker + 构建沙箱边界、Go↔Python 强类型契约（Protobuf / ConnectRPC / JSON Schema）、零重型运维队列演进阶梯（PG `SKIP LOCKED` / NATS JetStream → Kafka）、快路径（PR/MCP <15s）vs 慢路径隔离与状态机防雪崩。 |
| **0025** | `lessons/0025-multitenant-storage-finding-lifecycle-and-consistency.html`<br/>`assets/multitenant-consistency-lab.js` | `PROD,SYS,L2,L3` | ~20 min | **多租户隔离、Finding 生命周期与多存储一致性**：PG `tenant_id` + RLS + Go `sqlc` 类型防护（一套 Schema 兼容 SaaS 多租户与私有化单租户）、Finding 跨分支/重构稳定指纹与 VEX/豁免继承、Transactional Outbox 保障 PG ↔ ClickHouse / RoaringBitmap 一致、Python Worker 写入隔离契约。 |
| **0026** | `lessons/0026-dual-mode-deployment-hybrid-runner-and-rbac-platform.html`<br/>`assets/dual-mode-deploy-lab.js` | `PROD,SYS,L4` | ~20 min | **双模交付、Hybrid Runner 与企业级权限开放平台**：一套代码兼容 SaaS / Hybrid Runner（源码不出内网，mTLS 仅传 IR）/ Air-Gapped 极简私有化（Compose/Helm + 离线规则包 + Ed25519 离线商用 License）、RBAC + ABAC 资产范围树 + OIDC/SCIM、OpenAPI + 防 SSRF 签名 Webhook + 审计日志、基础设施许可排雷（严避 MinIO `AGPL-3.0` / Redis `SSPL/AGPL`）。 |
| **0027** | `lessons/0027-sca-benchmark-harness-observability-and-ai-spec-repo.html`<br/>`assets/eval-observability-lab.js` | `PROD,SYS,L1,L3` | ~18 min | **AI 协同研发质量防线与工程落地蓝图**：SCA 黄金样本回归评测基准（Benchmark Harness：Precision / Recall / F1 / P95 延迟门禁防 AI 改坏解析器）、OpenTelemetry 全链路耗时归因、Go + Python 强类型 Monorepo 组织结构、ADR 模板与 90 天 MVP 垂直切片 Spec。 |
| **Ref 08** | `reference/ch7-product-arch-and-tech-design-matrix.html` | `REF` | 速查 | **可打印速查卡**：随 `0023`–`0027` 逐课增量沉淀域模型字段字典、任务队列与 Outbox 契约、双模拓扑与许可替代清单、评测门禁与 Monorepo 结构速查矩阵。 |

### 已规划的工作区基线更新（待 Spec 批准后在后续实施阶段执行）

1. **`MISSION.md` 范围扩展**：将全课程 Mission 从「3 阶段 22 课底座与策略」扩展为包含 Phase 4「产品架构与 1 人 + AI Agent 双模工程技术设计」，并将原本 `Out of scope` 中的平台工程化/部署与权限底座边界移入 CH 07 作用域（前端 React 细节与财务计费网关仍保留在 Out of scope）。
2. **`learning-records/0003-solo-ai-agent-go-python-dual-mode.md`**：记录学习者明确的新现实基线——`0022` 已收官；当前组织形态为「1 人架构师 + AI Coding Agents」；后端主力技术栈收敛为 **Go + Python**；产品需从第一天起原生支持 **SaaS + 私有化双模兼容**，且选择模式 A（纯课程模式）。

---

## Tech Stack

### 课程工作区交付技术栈
- **前端与样式**：纯静态 HTML5、原生 ES6 Vanilla JavaScript（无任何构建工具、无外部 CDN 运行时依赖）、复用 `assets/tufte-course.css` 与 `assets/quiz.js` / `assets/curriculum.js`。
- **托管与发布**：GitHub Pages 静态站点（`https://zhang3say.github.io/sca/`），通过推送 `main` 分支自动触发更新。

### CH 07 教学目标产品技术栈（严格商用闭源合规 · 需在 `RESOURCES.md` 引述一手源）
- **控制面与核心扫描器**：**Go**（API Gateway / 控制面模块化单体 / Single Go Core CLI+MCP+Hook / L1+L3 Worker），`sqlc`（MIT）+ `pgx`（MIT）保证类型安全与租户上下文强制注入。
- **专项分析与 AI 安全 Worker**：**Python**（AI-BOM / 模型解析 / 深度静态特征 Worker），通过 Protobuf / ConnectRPC（Apache-2.0）或严格版本化 JSON Schema 与 Go 控制面通信，受控写入边界。
- **主事务与多租户存储**：**PostgreSQL 16+**（PostgreSQL License），原生 Row-Level Security（RLS）+ `SKIP LOCKED`（Day-1 轻量任务队列）+ Transactional Outbox 表。
- **异步消息、分析与缓存基础设施（全量排查 AGPL/SSPL/BSL 替代）**：
  - 队列演进：Day-1 PostgreSQL `SKIP LOCKED` → 中阶 **NATS JetStream**（Apache-2.0）→ 超大规模 **Apache Kafka**（Apache-2.0）。
  - 在线分析与对象存储：**ClickHouse**（Apache-2.0）；对象存储优先云原生 S3 或 **SeaweedFS**（Apache-2.0）/ **Garage**（AGPL-3.0 需避坑！仅选 Apache-2.0 方案如 SeaweedFS 或标准 S3 接口），严禁捆绑 MinIO（AGPL-3.0 商用传染风险）。
  - 内存缓存与策略鉴权：**Valkey**（BSD-3-Clause，替代 Redis SSPL/RSALv2）、**Open Policy Agent / CEL**（Apache-2.0）。
  - 可观测性与交付编排：**OpenTelemetry**（Apache-2.0）、Docker Compose（单机极简离线）+ Kubernetes Helm Chart（Apache-2.0 声明式模板）。

---

## Commands

每次新增或更新 CH 07 课程与速查卡时，在工作区根目录执行以下完整校验与发布命令：

```bash
# 1. 校验所有 JS 实验台与共享脚本语法正确（含新增 assets/*-lab.js）
for f in assets/*.js; do node --check "$f" || exit 1; done

# 2. 校验所有 HTML 内嵌 quiz JSON 可解析、选项均衡度与相对链接完整性
python3 - <<'PY'
import glob, json, os, re

errors = []
for path in sorted(glob.glob("lessons/002[3-7]*.html") + ["reference/ch7-product-arch-and-tech-design-matrix.html", "index.html"]):
    if not os.path.exists(path):
        continue
    text = open(path, encoding="utf-8").read()
    # Check quiz JSON & option length balance
    for m in re.finditer(r'<script[^>]*class="quiz-data"[^>]*>(.*?)</script>', text, re.S):
        data = json.loads(m.group(1))
        for i, q in enumerate(data.get("questions", [])):
            opts = q.get("options", [])
            lens = [len(o) for o in opts]
            if lens and (max(lens) - min(lens) > 6):
                errors.append(f"{path} Q{i+1}: option lengths unbalanced {lens}")
    # Check local relative links
    base = os.path.dirname(path)
    for attr, target in re.findall(r'(href|src)="([^"]+)"', text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        clean = target.split("#")[0]
        resolved = os.path.normpath(os.path.join(base, clean))
        if not os.path.exists(resolved):
            errors.append(f"{path}: broken {attr} -> {target} ({resolved})")

assert not errors, "\n".join(errors)
print("HTML/Quiz/Links verification passed.")
PY

# 3. 检查 Git 工作区状态并在单课闭环验证通过后提交推送
git status -sb
git add -A && git commit -m "feat(lesson): 完成第 XXXX 课...及 Ref 08 ..." && git push
```

---

## Project Structure

```text
/home/leezi/lll/learn/sca/
├── SPEC-ch07-product-and-tech-design.md          # 本文档（CH 07 V1 规范）
├── MISSION.md                                     # 课程总目标（Spec 批准后扩展 Phase 4）
├── NOTES.md                                       # 教学笔记与总纲目录（随课同步更新）
├── RESOURCES.md                                   # 高可信一手参考源清单（含 CH 07 新增权威源）
├── index.html                                     # 课程总览页（扩至 4 阶段 · 7 章 · 27 课 · 8 速查卡）
├── learning-records/
│   ├── 0001-starting-baseline-and-constraints.md
│   ├── 0002-agentic-shift-left-replaces-lsp-only.md
│   └── 0003-solo-ai-agent-go-python-dual-mode.md # [新增] 记录 1 人 + AI / Go+Python / 双模基线
├── assets/
│   ├── tufte-course.css                           # 新增 .phase-divider.phase-4 等共享样式
│   ├── quiz.js                                    # 复用测验引擎
│   ├── curriculum.js                              # 复用首页筛选控制器
│   ├── product-domain-lab.js                      # [新增] Lesson 0023 交互实验台
│   ├── service-orchestration-lab.js               # [新增] Lesson 0024 交互实验台
│   ├── multitenant-consistency-lab.js             # [新增] Lesson 0025 交互实验台
│   ├── dual-mode-deploy-lab.js                    # [新增] Lesson 0026 交互实验台
│   └── eval-observability-lab.js                  # [新增] Lesson 0027 交互实验台
├── lessons/
│   ├── 0001..0022-*.html                          # 已发布 Phase 1–3 课程（只读不改）
│   ├── 0023-product-domain-model-and-persona-workflows.html
│   ├── 0024-solo-ai-modular-monolith-and-scan-orchestration.html
│   ├── 0025-multitenant-storage-finding-lifecycle-and-consistency.html
│   ├── 0026-dual-mode-deployment-hybrid-runner-and-rbac-platform.html
│   └── 0027-sca-benchmark-harness-observability-and-ai-spec-repo.html
└── reference/
    ├── ...                                        # 已发布 Ref 01–07
    └── ch7-product-arch-and-tech-design-matrix.html # [新增] Ref 08 可打印速查卡
```

---

## Code Style

### 1. 微课 HTML 结构与测验组件约定（延续 `0022` 与 `/teach` 规范）
每课严格包含：顶部共享导航栏（指向 `../index.html`、`Ref 08` 及上下课）→ Tufte `.lesson-header` + `.callout.mission` → 3–4 个结构化工程章节（含边注 `.sidenote` 与宽幅权衡对比表 `.table-wrap.full-width`）→ 1 个专属交互实验台（`<section class="widget-panel full-width">` 挂载独立 `*-lab.js`）→ 1 个 4 题主动回忆测验 → 双栏 Footer（`一手必读原典` + `导师陪跑提问引导`）。

```html
<!-- 主动回忆测验（选项字数严格等长或差值 ≤ 2 字，正确选项 answerIndex 均匀分布 0..3） -->
<section class="widget-panel full-width" data-widget="quiz">
  <script type="application/json" class="quiz-data">
    {
      "title": "Lesson 0023 · 产品域模型与端到端闭环主动回忆测验",
      "intro": "重点检验核心域对象边界、Finding 与 Asset 解耦及双模 Feature Entitlement 设计。",
      "questions": [
        {
          "prompt": "在全场景 SCA 产品域模型中，为何必须把 Finding 归属到 Project+Branch 的逻辑位置，而非直接强绑定在单次 Snapshot 主键上？",
          "options": [
            "因为单次快照无法保存任何组件版本号与许可证元数据字段，必须由漏洞记录单独冗余。",
            "为了跨越每次扫描快照持续继承人工豁免、误报声明与修复状态，避免每次构建重复告警。",
            "为了强制要求公有云多租户版与私有化单租户版分别维护两套完全不同的数据库表结构。",
            "因为这样可以彻底取消内容寻址去重机制，每次流水线运行都能全量重写全部漏洞流水。"
          ],
          "answerIndex": 1,
          "explanation": "Snapshot 是不可变的时间点事实（对应某次 Commit 或镜像 Digest）；而人工审计结论（Waiver / VEX / Assigned Owner）必须随逻辑代码位置与稳定指纹跨 Snapshot 持续生效（B 正确）。"
        }
      ]
    }
  </script>
</section>
```

### 2. `index.html` 课程卡片与阶段筛选器约定

```html
<li class="lesson-row is-available" data-phase="p4" data-layer="PROD,SYS,L2" data-status="ready">
  <div class="lesson-num">0023</div>
  <div>
    <div class="lesson-main-title">
      <a href="./lessons/0023-product-domain-model-and-persona-workflows.html">全场景 SCA 产品域模型、五类角色旅程与核心闭环编排</a>
    </div>
    <p class="lesson-desc">定义从 Tenant 到 Waiver/Remediation 的统一产品业务对象模型……</p>
    <div class="lesson-tags">
      <span class="tag-chip">产品架构</span>
      <span class="tag-chip">Domain Model · Entitlement</span>
    </div>
  </div>
  <div class="lesson-status-col">
    <span class="badge badge-ok">已发布 · 可学习</span>
    <span class="lesson-duration">~18 min</span>
  </div>
</li>
```

### 3. 交互实验台 JS 规范
- 所有 `assets/*-lab.js` 采用零依赖 IIFE `(function () { "use strict"; ... })()`，严格做 DOM 转义防 XSS，禁止引入外部 JS/CSS CDN。
- 卡片与网格布局遵循响应式规则（`minmax(0, 1fr)` 与 `overflow-x: auto` 包裹宽表），杜绝桌面端/窄屏横向溢出。
- 全工作区中文撰稿；在对话与文档中展示工作区路径时遵守 WSL2 UNC 格式（`file://wsl.localhost/Ubuntu/...` 与 `\\wsl.localhost\Ubuntu\...`）；Git 提交统一使用中文描述配 `feat(lesson):` 前缀。

---

## Testing Strategy

1. **内容准确性逐课核验（Content Accuracy Gate · 撰稿前与撰稿后双查）**：
   - 每课涉及的所有工程框架、协议标准、数据库特性、版本语义与基础设施选型，均须通过权威一手源（`search_web` 查验官方文档/仓库 LICENSE）核实，并同步登记至 `RESOURCES.md`；严禁凭参数化记忆编造版本号、接口或开源协议。
   - 任何涉及存储、队列、缓存、网关、评测工具的选型必须标注精确开源协议（Apache-2.0 / MIT / BSD / PostgreSQL vs AGPL / SSPL / BSL），并与 `0001`–`0022` 已讲内容逐条比对防止重复。
2. **脚本与静态链接自动化检查（每课交付必跑）**：
   - 使用 `node --check` 校验所有 `assets/*.js`。
   - 运行 Python 校验脚本：验证全部内嵌 `.quiz-data` JSON 格式合法、`options` 字符长度差值在可控范围内（推荐差值 ≤ 6 字符，无长度提示漏题）、`answerIndex` 分布均匀，且全部相对 `href`/`src` 链接（含新课 ↔ `Ref 08` ↔ `index.html`）文件真实存在。
3. **首页筛选器与统计一致性验证**：
   - 每发布一课同步更新 `index.html` 的 `hero-stats`（最终总课数 27、速查卡 8 份）、`data-phase="p4"`（5 课）及 `PROD`（产品与工程）筛选胶囊计数与 `.lesson-row` 状态。
4. **真实浏览器 UI/UX 渲染与交互核验（每课完成必测，未通过不推进下一课）**：
   - 在工作区根目录启动本地静态 HTTP 服务（`python3 -m http.server`），通过 Chrome DevTools MCP 或 `browser` 子智能体对新课、`Ref 08` 与 `index.html` 在桌面端（`1280px`）与移动端（`375px`）双视口实测：
   - 验证控制台零 JS 报错、页面无横向溢出（`document.documentElement.scrollWidth <= document.documentElement.clientWidth`）、表格包裹正常不破版、交互实验台所有按钮/预设/切换控件均可响应并实时更新、主动回忆测验可作答与计分。

---

## Boundaries

- **Always do（始终遵守）：**
  - 全程使用中文编写课程、速查卡、文档与 Git 提交信息。
  - 先查阅并验证一手官方资料写入 `RESOURCES.md`，在课程中附带权威外链引用。
  - 所有测验选项保持字数与结构高度均衡，随机分布正确答案位置，不留格式线索。
  - 每完成一课即增量更新 `Ref 08`、`index.html`、`NOTES.md`，执行全套校验后提交推送至 `origin/main`。
- **Ask first（修改前先确认）：**
  - 修改任何已发布的 `0001`–`0022` 课程或 `Ref 01`–`07` 内容。
  - 变更本 Spec 约定的课程数量（5 课）、技术栈范围（Go + Python）或新增工作区外部依赖。
  - 从模式 A（纯课程模式）切换为模式 B（生成真实 SCA 产品代码仓库骨架或独立 ADR 目录）。
- **Never do（严禁事项）：**
  - 严禁向闭源商业内核推荐直接静态链接或打包交付 GPL / AGPL / BSL / SSPL 组件（如 MinIO AGPL-3.0、Redis SSPL/AGPL 等）；若提及必须明确标出红线与替代方案。
  - 严禁在多课 HTML 中内联重复的 CSS 样式块或测验逻辑（必须复用 `assets/tufte-course.css` 与 `assets/quiz.js`）。
  - 严禁跳过 Spec 评审或 Plan 评审直接批量生成全部课程；严禁未跑校验脚本就执行 `git commit && git push`。

---

## Success Criteria

CH 07 完整交付时必须满足以下全部可验证条件：

1. **课程与交互实验台完整**：`lessons/0023`–`0027` 共 5 篇微课 HTML 与对应的 5 个 `assets/*-lab.js` 交互实验台全部上线且可独立运行，无控制台语法错误。
2. **速查卡闭环**：`reference/ch7-product-arch-and-tech-design-matrix.html`（Ref 08）完整覆盖 `0023`–`0027` 核心决策矩阵与字段字典，并可正常打印。
3. **零内容重叠与强约束对齐**：5 课严格围绕「1 人 + AI Agent」「Go + Python 双栈」「SaaS + Hybrid + 极简私有化双模兼容」「商用闭源零传染许可」展开，与 `0001`–`0022` 不重复造轮子。
4. **工作区状态全量同步**：`MISSION.md`、`NOTES.md`、`RESOURCES.md`、`learning-records/0003-solo-ai-agent-go-python-dual-mode.md`、`assets/tufte-course.css`（`.phase-4` 样式）与 `index.html`（4 阶段 · 7 章 · 27 课 · 8 份速查卡，筛选计数精确匹配）全部同步更新。
5. **自动化检验 100% 通过**：Commands 章节中的 JS 语法校验、Quiz JSON 与选项长度均衡检查、全量本地链接检查零报错，且已推送 `origin/main`。

---

## Out of Scope (Deferred — V2 Backlog)

以下内容明确排除在 CH 07 V1 之外，留待后续需要时通过独立 Delta Spec 启动：

1. **真实产品可运行代码脚手架与文档仓（模式 B）**：不在本课程仓生成可编译的 Go+Python SCA 服务源码、`proto/` 文件或产品级 `ADR/` 目录。
2. **前端 UI 视觉组件库与交互设计系统**：不展开 React/Vue 页面组件实现、设计稿系统或复杂交互前端工程。
3. **商业支付与 ERP/CRM 计费集成**：不涉及 Stripe/支付宝支付回调、开票系统、SaaS 账单对账等纯商业财务系统设计。
4. **安全大模型微调与训练流水线**：不展开 LLM 预训练/微调数据集工程，AI 能力仍聚焦在既有确定的工程化与安全治理边界。

---

## Resolved Decisions

1. **首页层级筛选标签（Q1 已拍板）**：在 `index.html` 的「架构层级」筛选栏新增独立胶囊 **「产品与工程 (`PROD`)」**，同时保留 `0023`–`0027` 上的 `SYS` 与关联层标签（如 `PROD,SYS,L2`），兼顾按专题直达与跨阶段关联检索。
2. **交付节奏与每课强门禁（Q2 已拍板）**：采用 **连续垂直切片交付** 推进 `0023`–`0027` 与 `Ref 08`，但**每完成一课必须严格执行「内容准确性核验 + 真实浏览器 UI/UX 无误核验」双门禁**，全部通过后再更新 `index.html` / `NOTES.md` 并推送 `origin/main`，确认无误后方可进入下一课。
