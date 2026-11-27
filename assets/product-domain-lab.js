/* ==========================================================================
   可复用交互组件：产品域对象模型与五角色 Entitlement 路由实验台（Lesson 0023）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
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

  function initProductDomainLab(container) {
    const dataEl = container.querySelector("script.product-domain-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const DOMAIN_SCENARIOS = [
      {
        id: "waiver-persist",
        label: "1. 每次提交触发新 Snapshot，已豁免漏洞是否重复炸群？",
        desc: "研发昨天对某条不构成利用路径的 CVE 登记了 VEX NOT_AFFECTED 豁免；今天仅改了 README 并推送新 Commit，生成了新 Snapshot。",
        snapshotMeta: "Commit #a18f → #b402 · 同一 Project/Branch · 仅文档变更",
        payloadLines: [
          "// 不可变历史快照（只追加，不修改）",
          "Snapshot{id: \"snap_9042\", asset_id: \"ast_checkout_repo\", branch: \"main\", cas_hash: \"sha256:7d1f...\"}",
          "// 逻辑风险台账（按稳定位置绑定，跨 Snapshot 延续）",
          "LogicalFinding{id: \"fnd_331\", asset_id: \"ast_checkout_repo\", branch: \"main\", purl: \"pkg:maven/org.yaml/snakeyaml\", vuln_id: \"CVE-2022-1471\"}",
          "WaiverPolicy{finding_id: \"fnd_331\", vex_state: \"NOT_AFFECTED\", justification: \"CODE_NOT_REACHABLE\", expires_at: \"2027-03-01\"}"
        ],
        naiveOutcome: {
          badge: "坏模型（Finding 强绑定 Snapshot）",
          alerts: "1,240 条/月 重复炸群",
          waiverRate: "0% 自动继承",
          auditTrace: "断裂（每次扫描生成全新 finding_id）",
          notes: [
            "Snapshot ID 变更导致昨天人工标记的 NOT_AFFECTED 全部失效，今天再次在 PR 里报错。",
            "安全团队被迫用 Excel 手工比对昨天与今天的导出表，工具直接失去研发信任。"
          ]
        },
        goodOutcome: {
          badge: "正确域模型（Snapshot × LogicalFinding 分离）",
          alerts: "0 条重复告警（自动静默继承）",
          waiverRate: "100% 跨 Snapshot 继承",
          auditTrace: "完整保留（last_seen_snapshot 滚动刷新）",
          notes: [
            "新 Snapshot 仅刷新 Finding.last_seen_snapshot_id，保留既有 Policy/Waiver 状态与到期提醒。",
            "同时支持按任意历史 Snapshot 回放当时合规快照，满足 EU CRA 审计不可篡改溯源。"
          ]
        }
      },
      {
        id: "monorepo-assets",
        label: "2. Monorepo 多模块：同一仓库里既有 Go 后端、Python AI 又有 Dockerfile",
        desc: "一个 Git 仓库同时包含 `/services/pay-api`(Go)、`/ml/reranker`(Python+ModelPack) 与 2 个生产容器镜像。",
        snapshotMeta: "1 个 Git Repo (Project) → 3 个异构 Asset Target → 各自独立 Branch/Digest 生命周期",
        payloadLines: [
          "Project{id: \"prj_core_commerce\", workspace_id: \"ws_fin\", owner_group: \"team-checkout\"}",
          "  ├─ Asset{id: \"ast_1\", kind: \"SOURCE_MANIFEST\", locator: \"/services/pay-api/go.mod\"}",
          "  ├─ Asset{id: \"ast_2\", kind: \"AI_MODEL_DIR\",    locator: \"/ml/reranker/model.safetensors\"}",
          "  └─ Asset{id: \"ast_3\", kind: \"OCI_IMAGE\",       locator: \"ghcr.io/acme/pay-api:v2.4\"}",
          "// 关键：Policy 与权限挂在 Project/Workspace 树，扫描证据与快照挂在 Asset"
        ],
        naiveOutcome: {
          badge: "坏模型（Repo = 唯一扫描对象）",
          alerts: "组件混杂、Owner 混乱",
          waiverRate: "跨服务误伤或漏管",
          auditTrace: "无法区分源码与上线镜像差异",
          notes: [
            "把 Git 仓库当唯一粒度时，容器镜像里的 OS CVE 与 Go 源码的静态库被揉成一团，法务无法单独导出容器镜像 SBOM。",
            "AI 模型组与后端组无法按各自路径/资产独立接收派单或设置不同阻断阈值。"
          ]
        },
        goodOutcome: {
          badge: "正确域模型（Project 聚合多形态 Asset）",
          alerts: "按 Asset 精确归因与路由",
          waiverRate: "支持按 Asset 或 Project 作用域授权",
          auditTrace: "源码 ↔ 制品 ↔ 线上镜像链路贯通",
          notes: [
            "Project 负责业务归属、Backstage Owner 与 KPI 聚合；Asset 负责承载源码目录、容器仓库或模型制品等异构扫描目标。",
            "每个 Asset 独立生成不可变 Snapshot，天然兼容后续 SLSA Provenance 把源码 Asset 与镜像 Asset 关联。"
          ]
        }
      },
      {
        id: "vuln-reeval",
        label: "3. 夜间零代码变更时爆发 0-day：如何不重扫源码就生成新 Finding？",
        desc: "凌晨 2 点上游 OSV 情报新公布高危漏洞；此时所有代码仓都没有任何新 Git Push。",
        snapshotMeta: "零新增 Snapshot · Layer 3 情报变更事件触发既有资产图谱重算",
        payloadLines: [
          "// 1. 保留既有最新 Snapshot 与其关联的 Layer 2 IR 组件引用 (SnapshotComponentRef)",
          "// 2. 独立定时/事件任务按 PURL 倒排命中受影响 Snapshot 集合",
          "// 3. 批量 Upsert LogicalFinding，自动绑定全局 VulnerabilityMeta(CVE/EPSS/KEV)",
          "Finding{id: \"fnd_889\", origin: \"CONTINUOUS_REEVAL\", first_seen_snapshot: \"snap_9042\", status: \"OPEN\"}",
          "RemediationTask{finding_ids: [\"fnd_889\"], target_channel: \"PR_BOT | SLACK_GROUP\", state: \"QUEUED\"}"
        ],
        naiveOutcome: {
          badge: "坏模型（CI 扫完即存静态报告 JSON）",
          alerts: "0-day 漏报直至下次发版",
          waiverRate: "无独立 Finding 实体可更新",
          auditTrace: "只能人工重跑上千条 CI 流水线",
          notes: [
            "如果只把扫描结果存成报告附件或依赖本地 CI 重跑，夜间爆发 0-day 时线上已经运行半年的服务会完全盲区。",
            "同时因为没有独立 Finding 与 RemediationTask 解耦，同一组件在 5 个版本中只修一次也会发 50 条垃圾工单。"
          ]
        },
        goodOutcome: {
          badge: "正确域模型（Finding 独立于 CI 运行）",
          alerts: "10 秒全网命中并触发重算工单",
          waiverRate: "自动校验是否存在在先全局 VEX",
          auditTrace: "完整记录 first_seen_at 与情报版本",
          notes: [
            "Snapshot 固化资产成分事实，Finding 作为可独立演化的风险实体由 L3 重算任务按最新情报持续刷新。",
            "RemediationTask 按「同一 Project + 同一修复升级动作」聚合多条 Finding，避免给研发刷屏。"
          ]
        }
      },
      {
        id: "audit-freeze",
        label: "4. 客户大版本发版封板：需要锁定 6 个月前的合规证据快照",
        desc: "客户依据 EU CRA 要求留存发版时的准确 SBOM、许可证结论与当时的豁免审批记录。",
        snapshotMeta: "Release Tag v3.2.0 封板归档 · 不可随日后升级或豁免过期被篡改",
        payloadLines: [
          "ReleaseBundle{id: \"rel_3_2_0\", snapshot_id: \"snap_8810\", sealed_at: \"2026-10-15T08:00Z\"}",
          "  ├─ sbom_ref: \"s3://cas/cyclonedx/8810.json.zst\" (含 PURL + SHA256)",
          "  ├─ license_verdict_ref: \"s3://cas/notices/8810.txt\"",
          "  └─ finding_audit_freeze: [ {finding_id, status_at_release, waiver_approver, vex_doc_sha256} ]"
        ],
        naiveOutcome: {
          badge: "坏模型（覆盖写当前状态，无封板切片）",
          alerts: "历史交付状态被后续修复覆盖",
          waiverRate: "过期后丢失当年审批证据",
          auditTrace: "无法通过欧盟 CRA / 车企合规审查",
          notes: [
            "直接把最新状态覆盖进同一行记录而不留封板快照，半年后监管抽查 v3.2.0 时根本说不清当时为何放行。"
          ]
        },
        goodOutcome: {
          badge: "正确域模型（活体 Finding + 不可变 Release 封板）",
          alerts: "日常态实时更新，历史发版态永不漂移",
          waiverRate: "审批人/理由/有效期冻结在 Release 证据包",
          auditTrace: "一键重现任意历史发版 SBOM + VEX 证明",
          notes: [
            "日常开发分支上的 Finding 持续演化关闭，而打 Tag 发版时将 Snapshot + 当时有效 Waiver 列表固化为不可变 Release 证据包。"
          ]
        }
      }
    ];

    const PERSONAS = [
      {
        id: "dev-agent",
        label: "研发工程师 / AI Coding Agent",
        loop: "闭环一：Coding/PR 事前事中极速阻断与无感升级",
        latencyTarget: "< 1.5s (MCP/Hook) · < 15s (PR Gate)",
        primarySurface: "Single Go Core (MCP / Hook / LSP) + PR Check Comment",
        starterCap: "依赖解析 + 已知 CVE 与许可证红线提示（无可达性降噪）",
        proCap: "Slopsquatting/恶意包安装前拦截 + 调用图可达性过滤 + 一键安全升级 Patch",
        sovCap: "私有源包镜像策略 + 内网 MCP 工具签名/Schema Pinning 强制校验",
        saasProvider: "OpenFeature Cloud Provider → 读取租户级实时策略与灰度开关",
        onpremProvider: "OpenFeature Local Ed25519 License Provider → 离线缓存策略零外联"
      },
      {
        id: "appsec",
        label: "AppSec 安全工程师",
        loop: "闭环二：精准研判降噪、VEX 签发与 0-day 爆炸半径处置",
        latencyTarget: "< 10s (全网 0-day 定损检索)",
        primarySurface: "Finding Triage Workbench + Policy / Waiver 审批流",
        starterCap: "基础 CVE 清单筛选、手动标记误报与工单状态流转",
        proCap: "EPSS/KEV/SSVC 自动分级、静态+动态可达性证据链展示、批量签发 OpenVEX",
        sovCap: "C/C++ 二进制同源命中溯源 + 全集团万级资产图谱 0-day 秒级定向派单",
        saasProvider: "按租户 SKU 动态激活可达性 UI 卡片与 VEX 签发按钮",
        onpremProvider: "完全同构的前端/API 开关逻辑，未授权功能优雅降级为升级提示"
      },
      {
        id: "devops",
        label: "DevOps / 平台 SRE",
        loop: "闭环三：CI/CD 流水线准入与 Hybrid Runner / 集群自治",
        latencyTarget: "< 50ms (K8s 准入 VSA/CEL 验签)",
        primarySurface: "CI Plugin / K8s Admission Webhook / Runner 管理台",
        starterCap: "CI 阻断阈值配置（按严重度阻断）与基础制品 SBOM 归档",
        proCap: "Guided Remediation 自动提 PR + Hybrid Runner 出站扫描编排",
        sovCap: "Private Sigstore / SLSA VSA 准入校验 + Air-Gapped 离线包增量同步",
        saasProvider: "SaaS 托管 Runner + 客户自部署 Hybrid Runner 混合调度",
        onpremProvider: "单机 Docker Compose 或 Helm 全量离线运行，零云端依赖"
      },
      {
        id: "legal",
        label: "法务 / 开源合规官 (OSPO)",
        loop: "闭环四：发版前许可证传染性清查与合规清单归档",
        latencyTarget: "异步分钟级（全量文件头扫描 + Notice 打包）",
        primarySurface: "License Compliance Center + Release 封板证据库",
        starterCap: "SPDX 表达式解析、Declared/Observed 冲突告警与 NOTICE 导出",
        proCap: "AI-BOM（模型/数据集 CC-BY-NC / OpenRAIL）门禁 + Curation 覆写审计",
        sovCap: "EU CRA 24h/72h 监管导出包 + C/C++ 代码片段同源法务审查台",
        saasProvider: "云端多法域合规模板热更 + S3 加密归档",
        onpremProvider: "本地离线 SPDX/OSADL 规则库 + 本地合规归档目录"
      },
      {
        id: "ciso",
        label: "CISO / 安全负责人",
        loop: "全局闭环：跨业务线风险水位、MTTR 与合规达标驾驶舱",
        latencyTarget: "分钟级 Warm OLAP 聚合视图",
        primarySurface: "Executive Posture Dashboard + 监管就绪度报告",
        starterCap: "全组织项目盘点、高危漏洞存量趋势与 SLA 达标率",
        proCap: "可达性压缩比统计（噪音削减 85%+）、Agent/AI 资产风险敞口总览",
        sovCap: "EU CRA / NIST SSDF 成熟度对标报表 + 私有化审计日志导出",
        saasProvider: "ClickHouse 多租户隔离 OLAP 大盘视图",
        onpremProvider: "极简私有化模式下复用 PG 物化视图或单节点 ClickHouse（零冗余集群）"
      }
    ];

    const state = {
      activeTab: "domain",
      scenarioId: DOMAIN_SCENARIOS[0].id,
      modelMode: "good", // "good" | "naive"
      personaId: PERSONAS[0].id,
      skuTier: "pro", // "starter" | "pro" | "sov"
      deployMode: "dual" // "saas" | "onprem" | "dual"
    };

    function renderDomainTab() {
      const sc = DOMAIN_SCENARIOS.find((s) => s.id === state.scenarioId) || DOMAIN_SCENARIOS[0];
      const out = state.modelMode === "good" ? sc.goodOutcome : sc.naiveOutcome;
      const isGood = state.modelMode === "good";

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">选择真实产品研发场景（检验域边界是否抗住长期演化）：</span>
          <div class="grl-preset-bar" style="margin-top:0.4rem;">
            ${DOMAIN_SCENARIOS.map(
              (s) => `
                <button type="button" class="grl-pill ${state.scenarioId === s.id ? "active" : ""}" data-sc="${s.id}">
                  ${escapeHtml(s.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="margin-top:0.75rem;display:flex;flex-wrap:wrap;gap:0.75rem;align-items:center;justify-content:space-between;">
            <div>
              <span class="grl-control-label">切换底层数据建模方式：</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${isGood ? "active" : ""}" data-mmode="good">推荐：Immutable Snapshot × Logical Finding 解耦</button>
                <button type="button" class="grl-pill ${!isGood ? "active" : ""}" data-mmode="naive">反例：每次扫描覆盖 / Finding 强绑 Snapshot</button>
              </div>
            </div>
            <div style="font-size:0.78rem;color:var(--ink-muted);font-family:var(--font-mono);">${escapeHtml(sc.snapshotMeta)}</div>
          </div>
        </div>

        <p style="font-size:0.86rem;color:var(--ink-secondary);margin:0 0 0.75rem;"><strong>场景推演：</strong>${escapeHtml(sc.desc)}</p>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">模型健康度判定</div>
            <div class="grl-kpi-val" style="color:${isGood ? "var(--ok)" : "var(--danger)"};">${escapeHtml(out.badge)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">告警噪音 / 触发效果</div>
            <div class="grl-kpi-val" style="color:${isGood ? "var(--ok)" : "var(--danger)"};">${escapeHtml(out.alerts)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Waiver / VEX 继承率</div>
            <div class="grl-kpi-val">${escapeHtml(out.waiverRate)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">合规审计回放能力</div>
            <div class="grl-kpi-val">${escapeHtml(out.auditTrace)}</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">域模型关键结构示例：</div>
            <div class="grl-payload-box" style="margin:0;">${sc.payloadLines.map((l) => escapeHtml(l)).join("<br/>")}</div>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">工程后果拆解：</div>
            <ul style="margin:0;padding-left:1.1rem;font-size:0.81rem;line-height:1.62;color:var(--ink-secondary);">
              ${out.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}
            </ul>
          </div>
        </div>
      `;
    }

    function renderPersonaTab() {
      const p = PERSONAS.find((x) => x.id === state.personaId) || PERSONAS[0];
      const tierMap = {
        starter: { name: "Tier 1 · Starter 合规底座版", cap: p.starterCap, color: "var(--accent-blue)" },
        pro: { name: "Tier 2 · Pro 三代智能与 AI 版", cap: p.proCap, color: "var(--ok)" },
        sov: { name: "Tier 3 · Enterprise Sovereign 离线/全能版", cap: p.sovCap, color: "#6b3fa0" }
      };
      const t = tierMap[state.skuTier] || tierMap.pro;
      const modeDesc =
        state.deployMode === "saas"
          ? p.saasProvider
          : state.deployMode === "onprem"
            ? p.onpremProvider
            : `${p.saasProvider}；同时通过 OpenFeature 接口无缝兼容：${p.onpremProvider}`;

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 选择目标用户角色：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${PERSONAS.map(
              (item) => `
                <button type="button" class="grl-pill ${state.personaId === item.id ? "active" : ""}" data-persona="${item.id}">
                  ${escapeHtml(item.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">2. 切换商业 SKU Entitlement：</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.skuTier === "starter" ? "active" : ""}" data-tier="starter">Tier 1 Starter</button>
                <button type="button" class="grl-pill ${state.skuTier === "pro" ? "active" : ""}" data-tier="pro">Tier 2 Pro</button>
                <button type="button" class="grl-pill ${state.skuTier === "sov" ? "active" : ""}" data-tier="sov">Tier 3 Sovereign</button>
              </div>
            </div>

            <div>
              <span class="grl-control-label">3. 切换交付形态（同一套代码）：</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.deployMode === "dual" ? "active" : ""}" data-dmode="dual">双模抽象对比</button>
                <button type="button" class="grl-pill ${state.deployMode === "saas" ? "active" : ""}" data-dmode="saas">公有云 SaaS</button>
                <button type="button" class="grl-pill ${state.deployMode === "onprem" ? "active" : ""}" data-dmode="onprem">Air-Gapped 离线</button>
              </div>
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">核心闭环流</div>
            <div class="grl-kpi-val">${escapeHtml(p.loop)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">交互与链路 SLA</div>
            <div class="grl-kpi-val" style="color:var(--accent-blue);">${escapeHtml(p.latencyTarget)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">主要触达工作面</div>
            <div class="grl-kpi-val">${escapeHtml(p.primarySurface)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">当前激活版本</div>
            <div class="grl-kpi-val" style="color:${t.color};">${escapeHtml(t.name)}</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">该角色在此 SKU 下的解锁能力：</div>
            <p style="font-size:0.83rem;line-height:1.62;color:var(--ink-secondary);margin:0;">${escapeHtml(t.cap)}</p>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">OpenFeature 统一网关控制实现：</div>
            <p style="font-size:0.83rem;line-height:1.62;color:var(--ink-secondary);margin:0;">${escapeHtml(modeDesc)}</p>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：产品域对象解耦与五角色 Entitlement 路由模拟器";
      const intro =
        config.intro ||
        "在模式一中对比「Snapshot 与 Finding 分离」如何化解重复炸群与审计失真；在模式二中体验同一套 OpenFeature 网关如何在 SaaS 与离线私有化间统一交付五类角色闭环。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0023 · Product Domain Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "domain" ? "active" : ""}" data-tab="domain">
            <span class="grl-tab-num">1</span>
            模式一：不可变 Snapshot × 逻辑 Finding 解耦仿真
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "persona" ? "active" : ""}" data-tab="persona">
            <span class="grl-tab-num">2</span>
            模式二：五类角色闭环 × 一核三阶双模 Entitlement
          </button>
        </div>

        ${state.activeTab === "domain" ? renderDomainTab() : renderPersonaTab()}
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

      container.querySelectorAll("[data-sc]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.scenarioId = btn.dataset.sc;
          render();
        });
      });

      container.querySelectorAll("[data-mmode]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.modelMode = btn.dataset.mmode;
          render();
        });
      });

      container.querySelectorAll("[data-persona]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.personaId = btn.dataset.persona;
          render();
        });
      });

      container.querySelectorAll("[data-tier]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.skuTier = btn.dataset.tier;
          render();
        });
      });

      container.querySelectorAll("[data-dmode]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.deployMode = btn.dataset.dmode;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="product-domain-lab"]').forEach(initProductDomainLab);
  });
})();
