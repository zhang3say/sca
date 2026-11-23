# 架构视角演进：对话式 AI Agent 时代左移防线必须从 LSP-only 升级为三模单核

在探讨第 6 课多触点采集架构时，学习者敏锐指出当前主流研发方式已向对话式 AI Coding Agent 迁移，许多工程师在日常编码中甚至不再打开传统 IDE，导致纯 `IDE LSP` 红色波浪线触点失明。因此平台左移（触点 1）不再只围绕 IDE 语言服务器建模，而应采用「Single Go Core（OSV-SCALIBR + 本地缓存）→ `--mode=mcp` / `--mode=hook` / `--mode=lsp`」三模协议架构，在 Agent 安装依赖前与编辑后 1.5 秒内完成 Slopsquatting 拦截与结构化自愈闭环。

## Evidence
学习者主动质疑第 6 课初版对 IDE LSP 的单一预设（“当前 ai agent 工具盛行，编程变成了对话式，IDE Language Server 甚至都不打开了”），准确识别了 2026+ 真实研发触点的范式转移并要求据此重构第 6 课。

## Implications
- **触点 1 建模标准升级**：后续涉及研发工作流（如 Lesson 0014 自动修复与 PR、Lesson 0015 恶意包/Slopsquatting 防御、Lesson 0019 Agentic AI 治理）时，默认同时考虑面向人类的 IDE/PR 界面与面向 Coding Agent 的 MCP/Hook 结构化反馈闭环。
- **产品差异化定位强化**：将本地 SCA 从“给人类画红线”升级为“驱动 AI Agent 自主改用安全版本的亚秒级守护内核”，直接对齐本产品的现代化第三代 SCA 定位。
