# 新基线确立：1 人架构师 + AI Coding Agents、Go + Python 双栈与 SaaS/私有化双模交付

完成 Phase 1–3 全部 22 课（SCA 领域内核与商业策略蓝图）后，学习者明确后续将进入 **Phase 4 · CH 07「产品架构与工程技术设计」**，并确立了三项直接决定系统工程选型的真实约束：当前研发组织形态为「1 人架构师 + AI Coding Agents」，后端主力技术栈收敛为 **Go + Python**，且产品须从第一天起原生支持 **SaaS 多租户与企业私有化双模兼容**（采用纯课程交付模式 A）。

## Evidence

学习者在启动 CH 07 的规范对齐（Spec Gate）中明确回答：“22 已经上线；A（纯课程模式）；只有我一人但是借助 AI Agent 足够了；后端主力 Go+Python；双模式兼容”。

## Implications

- **低运维复杂度优先**：1 人 + AI Agent 绝不能一上来拆出十几个微服务或引入重型 ZooKeeper/分布式编排群，优先「Go 模块化单体 + Python 独立专项 Worker + PG `SKIP LOCKED`」演进阶梯，以 Protobuf/ConnectRPC/OpenAPI/`sqlc` 强类型契约防止 AI 协同漂移。
- **双模统一抽象**：数据库多租户隔离（PG `tenant_id` + RLS）与对象存储/队列/License 抽象必须用一套代码同时跑通公有云 SaaS、不出域 Hybrid Runner 与单机 Compose/Helm 离线私有化。
- **AI 质量防线**：必须设立 SCA 黄金样本回归评测基准（Benchmark Harness）和基础设施许可排雷红线（严避 MinIO `AGPL-3.0`、Redis `SSPL/AGPL` 等），防止 AI 重构或引入基础设施依赖时造成静默精度回退或法务违约。
