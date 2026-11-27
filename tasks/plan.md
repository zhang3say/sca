# Implementation Plan: CH 07 产品架构与工程技术设计课程（Phase 4）

Source spec: `SPEC-ch07-product-and-tech-design.md`

## Overview

在已完成的前 3 阶段 6 章 22 课与 7 份速查卡基础上，将本工作区扩展至 **4 阶段 · 7 章节 · 27 课 · 8 份速查卡**，新增 **Phase 4 · CH 07「产品架构与工程技术设计」**（`0023`–`0027` 共 5 节交互微课 + 5 个原生 JS 交互实验台 + `Ref 08` 可打印速查矩阵）。全部内容严格围绕学习者的真实工程基线设计：**1 人架构师 + AI Coding Agents 协同研发**、**Go + Python 双主力后端栈**、**从第一天起原生支持 SaaS / Hybrid Runner / Air-Gapped 极简私有化双模交付**，以及**严格的商用闭源零传染开源许可红线**。采用垂直切片（Vertical Slice）连续推进，但**每一课交付前必须先后通过「内容准确性核验（一手官方源 + 协议排查）」与「真实浏览器 UI/UX 无误核验（桌面 1280px + 移动端 375px）」双门禁**。

## Architecture Decisions

- **AD-1 · 首页筛选标签双标策略（`PROD` + `SYS`）**：在 `index.html` 的架构层级筛选栏新增独立胶囊 `PROD`（产品与工程），同时为 `0023`–`0027` 保留 `SYS` 及所涉层级标签（如 `PROD,SYS,L2`），支持学习者一键聚焦 CH 07 或按系统架构/L1–L4 联合检索；在 `assets/tufte-course.css` 新增 `.phase-divider.phase-4` 视觉区分。
- **AD-2 · 逐课垂直切片 + 速查卡增量同步**：按依赖顺序逐课交付 `0023` → `0024` → `0025` → `0026` → `0027`。每完成一课即同步补全该课对应的一手权威资料（`RESOURCES.md`）、专属交互实验台（`assets/*-lab.js`）、`Ref 08`（`reference/ch7-product-arch-and-tech-design-matrix.html`）对应章节、`index.html` 状态与计数及 `NOTES.md`，随后提交推送 `origin/main`。
- **AD-3 · 每课强制双门禁核验（Content Accuracy + Live Browser UI/UX）**：
  - **内容准确性门禁**：每课撰稿前通过 `search_web` 核查所涉所有开源项目/标准/数据库特性/协议条款（如 `ConnectRPC`、`River`、`NATS JetStream`、`SeaweedFS` vs `MinIO`、`Valkey` vs `Redis`、`sqlc`/`pgx`、PG RLS、`SPIFFE`、`OpenTelemetry`、`Buf` 等），把核验后的一手来源登记进 `RESOURCES.md`，绝不凭记忆臆测版本号或开源许可。
  - **UI/UX 渲染与交互门禁**：在运行 `node --check` 与 Python Quiz/链接静态校验之后，通过 `python3 -m http.server` 启动本地静态服务，使用 Chrome DevTools MCP 或 `browser` 子智能体在 **桌面端（1280px）** 与 **移动端（375px）** 实测该课、Ref 08 与 `index.html`，确认零控制台 JS 报错、零横向溢出（`scrollWidth <= clientWidth`）、交互实验台控件联动正常、4 题主动回忆测验作答计分正常且无长度漏题。
- **AD-4 · 严格防重叠与零回改红线**：`0001`–`0022` 与 `Ref 01`–`07` 保持只读稳定，CH 07 不复讲 `0002`（L2 IR 编码）、`0006`（触点协议）、`0009`（漏洞包格式）、`0021`（CAS/RoaringBitmap）与 `0022`（商业 SKU/竞品策略）既有内容，仅通过清晰的相对链接向上引申至产品工程落地。

## Dependency Graph

```text
Task 1: 工作区基线升级 (MISSION.md, learning-records/0003, tufte-course.css, index.html, NOTES.md)
   │
   ▼  [Checkpoint 1: 首页筛选与基线同步门禁]
Task 2: Lesson 0023 (产品域模型与五角色闭环) + product-domain-lab.js + Ref 08 启篇 (§01-02)
   │
   ▼  [Checkpoint 2: 0023 内容准确性 + 静态 + 双视口 UI/UX 门禁 + Git 推送]
Task 3: Lesson 0024 (1人+AI模块化单体、Go↔Python契约与快慢调度) + service-orchestration-lab.js + Ref 08 (§03)
   │
   ▼  [Checkpoint 3: 0024 内容准确性 + 静态 + 双视口 UI/UX 门禁 + Git 推送]
Task 4: Lesson 0025 (多租户隔离、Finding指纹状态机与Outbox一致性) + multitenant-consistency-lab.js + Ref 08 (§04)
   │
   ▼  [Checkpoint 4: 0025 内容准确性 + 静态 + 双视口 UI/UX 门禁 + Git 推送]
Task 5: Lesson 0026 (双模交付、Hybrid Runner、RBAC/SCIM与开放平台) + dual-mode-deploy-lab.js + Ref 08 (§05)
   │
   ▼  [Checkpoint 5: 0026 内容准确性 + 静态 + 双视口 UI/UX 门禁 + Git 推送]
Task 6: Lesson 0027 (黄金样本评测Benchmark、OTel剖析与Monorepo/Spec落地) + eval-observability-lab.js + Ref 08 收官 (§06)
   │
   ▼  [Checkpoint 6: 0027 门禁 + CH 07 全章交叉链接/筛选总检 + Git 推送]
```

## Task List

详细可执行任务、验收标准与验证命令均记录于 [`tasks/todo.md`](./todo.md)，按如下有序索引推进：

- **Phase 4.1 · 工作区基线与框架搭建**
  - Task 1：更新 `MISSION.md`、新增 `learning-records/0003-solo-ai-agent-go-python-dual-mode.md`、更新 `assets/tufte-course.css`（`.phase-4`）、更新 `index.html`（4 阶段总纲与 `PROD` 胶囊，预设 `0023` 为下一课 ZPD）、更新 `NOTES.md` → **Checkpoint 1**
- **Phase 4.2 · 逐课垂直切片交付（每课必过双门禁）**
  - Task 2：Lesson `0023` + `product-domain-lab.js` + `Ref 08` 启篇 + `RESOURCES.md` + 索引同步 → **Checkpoint 2**
  - Task 3：Lesson `0024` + `service-orchestration-lab.js` + `Ref 08` §03 + `RESOURCES.md` + 索引同步 → **Checkpoint 3**
  - Task 4：Lesson `0025` + `multitenant-consistency-lab.js` + `Ref 08` §04 + `RESOURCES.md` + 索引同步 → **Checkpoint 4**
  - Task 5：Lesson `0026` + `dual-mode-deploy-lab.js` + `Ref 08` §05 + `RESOURCES.md` + 索引同步 → **Checkpoint 5**
  - Task 6：Lesson `0027` + `eval-observability-lab.js` + `Ref 08` §06 收官 + `RESOURCES.md` + 索引与总览最终同步 → **Checkpoint 6**

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| 开源基础设施许可变动或记忆误差（如 Redis、MinIO、River、Garage、SeaweedFS 等协议细节） | High | 每课动笔前必用 `search_web` 查验官方仓库 `LICENSE` 与最新条款并登记至 `RESOURCES.md`，禁止凭经验引用许可或版本。 |
| 交互实验台复杂网格或宽表在窄屏（375px）或 1280px 发生横向溢出（历史曾出现 `ae2987e` 修复） | High | 遵循 `minmax(0, 1fr)` 与 `.table-wrap` 规范；每课均通过本地 HTTP 服务在真实浏览器 1280px / 375px 视口检测 `scrollWidth <= clientWidth`。 |
| 与 `0002`/`0006`/`0009`/`0021`/`0022` 内容重复导致“换皮重讲” | Medium | 撰稿前先对照 `SPEC-ch07-product-and-tech-design.md` 的防重叠矩阵审查提纲，明确只讲产品域对象、系统服务切分、事务一致性、双模部署与回归评测工程。 |
| 测验选项字数不均或正确答案集中导致“猜题线索” | Medium | 每课执行 Python 校验脚本强制检查 `max(len) - min(len) <= 6` 且 4 道题的 `answerIndex` 均匀覆盖不同位置。 |
| WSL2 本地无原生 `chromium` CLI 导致无法跑无头命令行截图 | Low | 在工作区根目录用 `python3 -m http.server` 启动临时本地站点，通过 Chrome DevTools MCP 或内置 `browser` 子智能体完成真实页面渲染、交互点击与视口检查，检查结束后关闭临时服务。 |

## Open Questions

无（所有待决项已在 `SPEC-ch07-product-and-tech-design.md` 的 `## Resolved Decisions` 中确认拍板）。
