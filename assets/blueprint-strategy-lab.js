/* ==========================================================================
   可复用交互组件：总架构师商业矩阵、研发配比与竞品攻防实验台（Lesson 0022）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：12 个月分阶段研发人力配比与 Team Topologies 仿真器
   模式二：全球商业标杆竞品攻防与大客户 POC 破局推演器
   ========================================================================== */

(function () {
  "use strict";

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function initBlueprintStrategyLab(container) {
    const dataEl = container.querySelector("script.blueprint-strategy-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const RD_PRESETS = [
      {
        id: "phase1-foundation",
        label: "1. Phase 1 底座拍板期 (M1–M3 · 12人)",
        desc: "前 3 个月集中兵力打牢 L1 适配器（借力 OSV-SCALIBR / Syft / cdxgen）、L2 统一 IR 主权与 L3 多源汇聚索引，避免后期推倒重写。",
        headcount: 12,
        useOssBase: true,
        keepIrSovereignty: true,
        dedicateResearch: true,
        weights: { platform: 0.55, moat: 0.15, stream: 0.2, enabling: 0.1 }
      },
      {
        id: "phase2-moat",
        label: "2. Phase 2 壁垒冲刺期 (M4–M9 · 20人)",
        desc: "统一底座稳定后，主力大举转向 L4 静动态可达性、无破坏性修复、投毒 Capability Diff 与 AI-BOM/MCP 护城河，拉出商业溢价。",
        headcount: 20,
        useOssBase: true,
        keepIrSovereignty: true,
        dedicateResearch: true,
        weights: { platform: 0.25, moat: 0.45, stream: 0.15, enabling: 0.15 }
      },
      {
        id: "phase3-scale",
        label: "3. Phase 3 规模领跑期 (M10–M12+ · 30人)",
        desc: "在已有商业护城河上补齐 SLSA v1.2 Private Sigstore、CAS/RoaringBitmap 万级资产台账，并做深 IDE/Agent MCP 与企业生态交付。",
        headcount: 30,
        useOssBase: true,
        keepIrSovereignty: true,
        dedicateResearch: true,
        weights: { platform: 0.25, moat: 0.4, stream: 0.2, enabling: 0.15 }
      },
      {
        id: "anti-handroll",
        label: "4. 反例：手写解析器黑洞 (16人 · 70%耗在L1/L3)",
        desc: "不借力 Apache-2.0 引擎，试图全自研数十种包管理器解析与漏洞抓取，结果一年过去团队仍深陷边缘语法补丁，第三代壁垒寸步未进。",
        headcount: 20,
        useOssBase: false,
        keepIrSovereignty: false,
        dedicateResearch: false,
        weights: { platform: 0.7, moat: 0.1, stream: 0.15, enabling: 0.05 }
      }
    ];

    const COMPETITOR_PRESETS = [
      {
        id: "snyk",
        label: "对战 Snyk（互联网/AI 原生团队）",
        competitor: "snyk",
        sku: "pro",
        deploy: "saas",
        featReachability: true,
        featAiMcp: true,
        featBinarySlsa: false
      },
      {
        id: "endor",
        label: "对战 Endor Labs（金融/高噪音治理）",
        competitor: "endor",
        sku: "pro",
        deploy: "saas",
        featReachability: true,
        featAiMcp: true,
        featBinarySlsa: true
      },
      {
        id: "socket",
        label: "对战 Socket.dev（高频投毒敏感研发）",
        competitor: "socket",
        sku: "pro",
        deploy: "saas",
        featReachability: true,
        featAiMcp: true,
        featBinarySlsa: false
      },
      {
        id: "wiz",
        label: "对战 Wiz Code（多云 CNAPP 协同共存）",
        competitor: "wiz",
        sku: "enterprise",
        deploy: "saas",
        featReachability: true,
        featAiMcp: true,
        featBinarySlsa: true
      },
      {
        id: "blackduck",
        label: "对战 Black Duck（车企/硬件私有化合规）",
        competitor: "blackduck",
        sku: "enterprise",
        deploy: "airgap",
        featReachability: true,
        featAiMcp: false,
        featBinarySlsa: true
      }
    ];

    const COMPETITOR_META = {
      snyk: {
        name: "Snyk",
        entryAngle: "Agent MCP 三模左移 + 真可达性降噪 + 独立数据主权",
        weakness: "传统 SCA 噪音偏高、高阶私有化成本高、AI-BOM/MCP 护城河分散",
        budgetAnchor: "OpenSSF S2C2F + 研发人效提升（降噪 85%+ 省工时）",
        tactics: [
          "用同一批真实业务仓库现场跑对比：展示函数级静动态可达性 + VEX 自动压降 85%+ 无关告警，直接击中开发者修复疲劳。",
          "在 Coding Agent 场景切入 Single Go Core（MCP + Hook + LSP），在依赖写入前阻断 Slopsquatting 并给出 Safe Major 升级方案。",
          "强调全栈 Apache-2.0/MIT 合规内核与零厂商锁定 CycloneDX 1.7 / OpenVEX 双向导出能力。"
        ]
      },
      endor: {
        name: "Endor Labs",
        entryAngle: "全形态矩阵（容器/AI-BOM/MCP/C++二进制）+ 本土私有化",
        weakness: "高度聚焦应用层可达性与依赖生命周期，在 AI 推理层/MCP 治理与国密/离线交付侧较薄",
        budgetAnchor: "EU CRA (2026-09 上报) + NIST SSDF v1.1 全资产台账",
        tactics: [
          "在代码可达性拉平的前提下，亮出统一 L2 IR 同时纳管 OCI 镜像、OS Backport（Debian/RHEL）与 C/C++ 二进制同源扫描。",
          "叠加 EU AI Act Art. 53 模型权重（Safetensors/Pickle）与 MCP Tool Pinning，在 AI 转型客户中形成代差级扩展。",
          "展示 OCI 签名逻辑增量漏洞库与空气隔离 Private Sigstore 能力，拿下金融/政企离线交付大单。"
        ]
      },
      socket: {
        name: "Socket.dev",
        entryAngle: "恶意包行为防线 + CVE 可达性 + 资产台账一站式闭环",
        weakness: "长于行为投毒防线，但在企业级万级 CVE 溯源、运行时容器关联与 C/C++ 合规审计非主战场",
        budgetAnchor: "OpenSSF S2C2F Level 3/4 + 供应链投毒零容忍",
        tactics: [
          "在开源防火墙保留 72h 冷却窗 + Capability Diff + 混淆/抢注拦截的同时，与 L3 OSV/Backport 及 L4 可达性合二为一。",
          "向 CISO 算总账：购买单点防投毒仍需另配 CVE 优先级与合规审计平台，而本底座一套数据模型解决存量 + 增量双风险。",
          "用 CAS + RoaringBitmap 演示 10 秒 0-day 全网爆炸半径与 Backstage Group 自动派单，锁定中心安全团队预算。"
        ]
      },
      wiz: {
        name: "Wiz Code（Google Cloud）",
        entryAngle: "不做云基础设施对抗，以开放标准充当高保真代码/AI 信号源",
        weakness: "核心基因在无代理云运行时图谱（CNAPP），深层源码调用图、语言构建解析与模型序列化扫描偏浅",
        budgetAnchor: "CNAPP 生态互补 + 研发态深度左移（Code-to-Cloud 闭环）",
        tactics: [
          "主动拥抱共生而非硬碰硬：通过标准 CycloneDX 1.7 / OpenVEX / SLSA VSA 接口向 Wiz/CNAPP 推送高可信静态信号。",
          "切分清楚边界：Wiz 看重“云上是否暴露与 IAM 权限”，我方守住“IDE/Agent 写入前防投毒 + 函数级调用路径 + Safe Upgrade PR”。",
          "面向未全量上云或存在混合云/私有化研发网的客户，提供独立完整的软件供应链指挥台。"
        ]
      },
      blackduck: {
        name: "Black Duck",
        entryAngle: "现代云原生/DevSecOps 体验 + 零传染私有化 + C/C++ 同源补齐",
        weakness: "重型架构迭代慢、扫描等待时间长、缺少现代 Agent MCP 入口与轻量级云原生适配",
        budgetAnchor: "EU CRA (2027-12 全量 SBOM) + 车规/嵌入式许可证法务审计",
        tactics: [
          "在保留 Winnowing / CENTRIS 片段同源检测与三层二进制特征金字塔的基础上，把扫描耗时压到分钟级并接入 CI/PR 流水线。",
          "用 Declared/Observed/Concluded 三层真值与三维传染推理（含 Go/Rust 静态链接边界）直击法务与并购尽调痛点。",
          "叠加现代 AI-BOM 与 SLSA v1.2 Provenance 验签，拿下车企智能座舱、工业物联网等“既要 C/C++ 又要 AI”的新增标段。"
        ]
      }
    };

    const state = {
      activeTab: "rd", // "rd" | "compete"
      rdPresetId: "phase1-foundation",
      headcount: 12,
      useOssBase: true,
      keepIrSovereignty: true,
      dedicateResearch: true,
      // 模式二
      competitor: "snyk",
      sku: "pro", // "starter" | "pro" | "enterprise"
      deploy: "saas", // "saas" | "airgap"
      featReachability: true,
      featAiMcp: true,
      featBinarySlsa: false
    };

    function getCurrentRdPreset() {
      return RD_PRESETS.find((p) => p.id === state.rdPresetId) || RD_PRESETS[0];
    }

    function computeAllocation(preset) {
      let { platform, moat, stream, enabling } = Object.assign({}, preset.weights);

      if (!state.useOssBase) {
        platform = 0.68;
        moat = 0.12;
        stream = 0.15;
        enabling = 0.05;
      } else if (!state.keepIrSovereignty) {
        platform = Math.max(0.15, platform - 0.1);
        stream += 0.15;
        moat = Math.max(0.1, moat - 0.05);
      }

      if (!state.dedicateResearch && enabling > 0) {
        const shift = enabling;
        enabling = 0;
        stream += shift;
      }

      const sum = platform + moat + stream + enabling;
      const pCount = Math.max(1, Math.round((state.headcount * platform) / sum));
      const mCount = Math.max(0, Math.round((state.headcount * moat) / sum));
      const eCount = state.dedicateResearch ? Math.max(1, Math.round((state.headcount * enabling) / sum)) : 0;
      const sCount = Math.max(1, state.headcount - pCount - mCount - eCount);

      return {
        pCount,
        mCount,
        sCount,
        eCount,
        pPct: Math.round((pCount / state.headcount) * 100),
        mPct: Math.round((mCount / state.headcount) * 100),
        sPct: Math.round((sCount / state.headcount) * 100),
        ePct: Math.round((eCount / state.headcount) * 100)
      };
    }

    function evaluateRd(preset, alloc) {
      const antiCard = {
        tone: "is-bad",
        verdict: "反模式 · 70% 人力陷在 L1 解析补丁与重复造轮子",
        meta: "手写多语言 Lockfile + 直接耦合外部 CLI 输出充当数据模型",
        desc: "12 个月后仅产出又一个普通 CVE 列表扫描器；面对高价值可达性与 AI-BOM 需求时因缺失统一 IR 被迫推倒重构。"
      };

      let tone = "is-ok";
      let verdict = "健康配比 · 底座稳固且高价值壁垒持续产出";
      let meta = `Platform ${alloc.pCount}人 · 壁垒子系统 ${alloc.mCount}人 · 交付 ${alloc.sCount}人 · 研究 ${alloc.eCount}人`;
      let desc = "通过 Apache-2.0 引擎（OSV-SCALIBR / Syft / cdxgen）压低底层人力消耗，将最稀缺的高阶工程师集中到 L2 IR、可达性、投毒与 AI-BOM。";

      if (!state.useOssBase) {
        tone = "is-bad";
        verdict = "致命黑洞 · 手写解析器吞噬全队产能";
        meta = `Platform 飙升至 ${alloc.pPct}% (${alloc.pCount}人) · 壁垒仅剩 ${alloc.mCount}人`;
        desc = "仅维护 Maven/Gradle/Poetry/uv/OCI/RPM 边缘兼容就会耗尽骨干人力，商业化窗口期彻底丢失。";
      } else if (!state.keepIrSovereignty) {
        tone = "is-warn";
        verdict = "重构预警 · 缺失 Layer 2 IR 主权埋下隐形债务";
        meta = "外部扫描器 JSON 直连前端/策略层";
        desc = "虽短期出活快，但一旦接入 Reachability、VEX 或 HuggingFace AI-BOM 挂载点，下游全链路接口将爆发级联破坏。";
      } else if (!state.dedicateResearch) {
        tone = "is-warn";
        verdict = "情报滞后 · 缺少 Enabling 安全研究护航";
        meta = "恶意包规则与漏洞函数符号库停滞";
        desc = "没有专职安全研究（Enabling）团队提炼 MAL-* 行为信号与修复 Commit 函数符号，L4 壁垒引擎将变成“无米之炊”。";
      }

      const yamlLines = [
        `# Team Topologies 12M 配比快照 (${state.headcount} 人 · ${preset.id})`,
        `platform_team:        ${String(alloc.pCount).padStart(2)} 人 (${alloc.pPct}%)  # L1 适配器 / L2 IR / L3 索引`,
        `complicated_subsys:   ${String(alloc.mCount).padStart(2)} 人 (${alloc.mPct}%)  # L4 可达性 / 投毒 / AI-BOM / SLSA`,
        `stream_aligned:       ${String(alloc.sCount).padStart(2)} 人 (${alloc.sPct}%)  # MCP / PR门禁 / 台账与企业交付`,
        `enabling_research:    ${String(alloc.eCount).padStart(2)} 人 (${alloc.ePct}%)  # L3 符号映射 / MAL-* / 合规校准`,
        `guardrails:`,
        `  oss_foundation: "${state.useOssBase ? "Apache-2.0/MIT 嵌入" : "危险: 自研解析黑洞"}"`,
        `  l2_ir_contract: "${state.keepIrSovereignty ? "100% 自研统一图模型" : "警告: 外部 JSON 透传"}"`
      ];

      return { antiCard, modernCard: { tone, verdict, meta, desc }, yamlLines };
    }

    function renderRdTab() {
      const preset = getCurrentRdPreset();
      const alloc = computeAllocation(preset);
      const res = evaluateRd(preset, alloc);

      return `
        <div class="grl-preset-bar">
          ${RD_PRESETS.map(
            (p) => `
              <button type="button" class="grl-pill ${state.rdPresetId === p.id ? "active" : ""}" data-rdpreset="${p.id}">
                ${escapeHtml(p.label)}
              </button>
            `
          ).join("")}
        </div>

        <p style="font-size:0.84rem;color:var(--ink-secondary);margin:0 0 0.85rem;padding:0.55rem 0.78rem;background:#faf8f2;border-left:3px solid var(--accent-blue);border-radius:0 4px 4px 0;">
          <strong>阶段策略：</strong>${escapeHtml(preset.desc)}
        </p>

        <div class="grl-layout">
          <div class="grl-controls">
            <div class="grl-control-group">
              <span class="grl-control-label">1. 研发团队总规模</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                ${[12, 20, 30]
                  .map(
                    (hc) => `
                      <button type="button" class="grl-pill ${state.headcount === hc ? "active" : ""}" data-hc="${hc}">
                        ${hc} 人梯队
                      </button>
                    `
                  )
                  .join("")}
              </div>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 总架构师资源保护闸门</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="oss" ${state.useOssBase ? "checked" : ""} />
                <span><strong>借力 Apache-2.0 底座</strong>（OSV-SCALIBR / Syft / cdxgen），拒绝手写常规解析器</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="ir" ${state.keepIrSovereignty ? "checked" : ""} />
                <span><strong>死守 L2 统一 IR 主权</strong>，阻断“扫描器 JSON 直连业务”的技术债</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="research" ${state.dedicateResearch ? "checked" : ""} />
                <span>配置 <strong>Enabling 安全研究组</strong>（赋能漏洞函数符号 + MAL-* + 许可矩阵）</span>
              </label>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid is-2col">
              <div class="grl-card ${res.antiCard.tone}">
                <div class="grl-card-kicker">行业常见败局 · 解析器泥潭</div>
                <div class="grl-card-title">${escapeHtml(res.antiCard.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.antiCard.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.antiCard.desc)}</p>
              </div>

              <div class="grl-card ${res.modernCard.tone}">
                <div class="grl-card-kicker">当前配置 · Team Topologies 推演结果</div>
                <div class="grl-card-title">${escapeHtml(res.modernCard.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.modernCard.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.modernCard.desc)}</p>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">Team Topologies 12 个月人力配比切片 (YAML)</span>
                <span class="badge ${res.modernCard.tone === "is-ok" ? "badge-ok" : res.modernCard.tone === "is-warn" ? "badge-warn" : "badge-danger"}">
                  ${escapeHtml(res.modernCard.verdict)}
                </span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(res.yamlLines.join("\n"))}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function evaluateCompete() {
      const meta = COMPETITOR_META[state.competitor] || COMPETITOR_META.snyk;
      let badgeCls = "badge-ok";
      let verdict = `WINNABLE · 对标 ${meta.name} 形成非对称差异化优势`;
      const extraRisks = [];

      if (state.sku === "starter" && (state.competitor === "endor" || state.competitor === "socket")) {
        badgeCls = "badge-warn";
        verdict = "WARN · 仅靠 Starter 底座版会陷入与开源 CLI 的同质化价格战";
        extraRisks.push("警告：Starter 底座版只覆盖 SBOM/CVE 与基础许可，对战 Endor/Socket 必须升级至 Pro 第三代壁垒版才能拉出商业溢价。");
      }

      if (state.deploy === "airgap" && state.sku !== "enterprise") {
        badgeCls = "badge-warn";
        verdict = "WARN · 客户要求空气隔离私有化，建议直接锚定 Enterprise Sovereign 版";
        extraRisks.push("建议：离线分发 OCI 增量库、Private Sigstore Rekor v2 与万级 PG+CAS 台账属于 Enterprise Sovereign 核心高溢价能力。");
      }

      if (state.competitor === "blackduck" && !state.featBinarySlsa) {
        badgeCls = "badge-danger";
        verdict = "GAP · 缺少 C/C++ 同源与二进制 SCA 能力，难以撼动 Black Duck 主力标段";
        extraRisks.push("缺口：面向车企/嵌入式客户必须开启 Winnowing / CENTRIS 代码同源与三层二进制特征金字塔（Lesson 0016）。");
      }

      if ((state.competitor === "snyk" || state.competitor === "endor") && !state.featReachability) {
        badgeCls = "badge-danger";
        verdict = "GAP · 关闭静动态可达性与安全修复后，无法解决客户核心噪音痛点";
        extraRisks.push("缺口：第三代 SCA 的灵魂是“静动态可达性 + VEX + API Diff 安全升级”，失去 L4 降噪将退回传统扫描器。");
      }

      const skuLabel =
        state.sku === "starter"
          ? "Starter 统一底座版（L1–L3 合规与基础 SBOM）"
          : state.sku === "pro"
            ? "Pro 第三代壁垒版（+可达性 / 投毒 / AI-BOM / MCP）"
            : "Enterprise Sovereign 版（+Private SLSA / 万级台账 / 离线）";

      const tactics = extraRisks.length > 0 ? extraRisks.concat(meta.tactics) : meta.tactics;

      return { meta, badgeCls, verdict, skuLabel, tactics };
    }

    function renderCompeteTab() {
      const r = evaluateCompete();

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div class="grl-preset-bar" style="margin-bottom:0.45rem;">
            ${COMPETITOR_PRESETS.map(
              (p) => `
                <button type="button" class="grl-pill ${state.competitor === p.competitor ? "active" : ""}" data-comppreset="${p.id}">
                  ${escapeHtml(p.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">1. 我方主推商业分层（一核三阶）</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.sku === "starter" ? "active" : ""}" data-sku="starter">Starter 底座版</button>
                <button type="button" class="grl-pill ${state.sku === "pro" ? "active" : ""}" data-sku="pro">Pro 三代壁垒版</button>
                <button type="button" class="grl-pill ${state.sku === "enterprise" ? "active" : ""}" data-sku="enterprise">Enterprise 私有化版</button>
              </div>

              <span class="grl-control-label" style="margin-top:0.65rem;display:block;">2. 客户交付环境约束</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.deploy === "saas" ? "active" : ""}" data-deploy="saas">公有云 / 混合云 SaaS</button>
                <button type="button" class="grl-pill ${state.deploy === "airgap" ? "active" : ""}" data-deploy="airgap">离线空气隔离私有化</button>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.42rem;">
              <span class="grl-control-label">3. 本次 POC 投入的护城河武器库</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="reach" ${state.featReachability ? "checked" : ""} />
                <span><strong>静动态可达性 + VEX + API Diff</strong> 安全升级（L4 降噪）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="aimcp" ${state.featAiMcp ? "checked" : ""} />
                <span><strong>恶意包 72h 冷却 + AI-BOM + MCP 治理</strong>（L4/AI 护城河）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="binslsa" ${state.featBinarySlsa ? "checked" : ""} />
                <span><strong>C/C++ 同源二进制 + Private Sigstore SLSA</strong>（企业深水区）</span>
              </label>
            </div>
          </div>
        </div>

        <div class="grl-impact-panel" style="margin-bottom:0.85rem;">
          <div class="grl-impact-head">
            <span>竞品攻防与大客户 POC 裁决（目标：${escapeHtml(r.meta.name)}）</span>
            <span class="badge ${r.badgeCls}">${escapeHtml(r.verdict)}</span>
          </div>
          <div class="grl-impact-list">
            <div class="grl-impact-item ${r.badgeCls === "badge-ok" ? "is-clear" : "is-hit"}">
              <strong>当前主推 SKU：</strong>${escapeHtml(r.skuLabel)} &middot; <strong>部署模式：</strong>${state.deploy === "saas" ? "云端 SaaS + 本地 Agent 网关" : "OCI 增量离线包 + 私有化集群"}
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">核心切入锚点</div>
            <div class="grl-kpi-val is-text">${escapeHtml(r.meta.entryAngle)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">标杆结构性短板</div>
            <div class="grl-kpi-val is-text">${escapeHtml(r.meta.weakness)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">合规 / 预算撬动点</div>
            <div class="grl-kpi-val is-text">${escapeHtml(r.meta.budgetAnchor)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">全栈商用许可状态</div>
            <div class="grl-kpi-val is-text" style="color:var(--ok);">0 GPL · 0 AGPL · 0 BSL 传染风险</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">POC 破局执行打法：</div>
          <ul style="margin:0;padding-left:1.1rem;font-size:0.8rem;line-height:1.58;color:var(--ink-secondary);">
            ${r.tactics.map((t) => `<li>${escapeHtml(t)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：12 个月研发配比与全球标杆竞品攻防推演";
      const intro =
        config.intro ||
        "在模式一中模拟 Phase 1→3 的 Team Topologies 研发人力动态迁移与“手写解析器黑洞”后果；在模式二中针对全球五大商业标杆推演 SKU 定价与 POC 打法。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0022 · Chief Architect Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "rd" ? "active" : ""}" data-tab="rd">
            <span class="grl-tab-num">1</span>
            模式一：12 个月研发配比与 Team Topologies 仿真
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "compete" ? "active" : ""}" data-tab="compete">
            <span class="grl-tab-num">2</span>
            模式二：五大商业标杆攻防与大客户 POC 推演
          </button>
        </div>

        ${state.activeTab === "rd" ? renderRdTab() : renderCompeteTab()}
      `;

      bindEvents();
    }

    function bindEvents() {
      container.querySelectorAll("[data-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTab = btn.dataset.tab;
          render();
        });
      });

      container.querySelectorAll("[data-rdpreset]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = RD_PRESETS.find((p) => p.id === btn.dataset.rdpreset);
          if (!found) return;
          state.rdPresetId = found.id;
          state.headcount = found.headcount;
          state.useOssBase = found.useOssBase;
          state.keepIrSovereignty = found.keepIrSovereignty;
          state.dedicateResearch = found.dedicateResearch;
          render();
        });
      });

      container.querySelectorAll("[data-hc]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.headcount = Number(btn.dataset.hc) || 12;
          render();
        });
      });

      container.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          const t = cb.dataset.toggle;
          if (t === "oss") state.useOssBase = cb.checked;
          if (t === "ir") state.keepIrSovereignty = cb.checked;
          if (t === "research") state.dedicateResearch = cb.checked;
          if (t === "reach") state.featReachability = cb.checked;
          if (t === "aimcp") state.featAiMcp = cb.checked;
          if (t === "binslsa") state.featBinarySlsa = cb.checked;
          render();
        });
      });

      container.querySelectorAll("[data-comppreset]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = COMPETITOR_PRESETS.find((p) => p.id === btn.dataset.comppreset);
          if (!found) return;
          state.competitor = found.competitor;
          state.sku = found.sku;
          state.deploy = found.deploy;
          state.featReachability = found.featReachability;
          state.featAiMcp = found.featAiMcp;
          state.featBinarySlsa = found.featBinarySlsa;
          render();
        });
      });

      container.querySelectorAll("[data-sku]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.sku = btn.dataset.sku;
          render();
        });
      });

      container.querySelectorAll("[data-deploy]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.deploy = btn.dataset.deploy;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="blueprint-strategy-lab"]')
      .forEach(initBlueprintStrategyLab);
  });
})();
