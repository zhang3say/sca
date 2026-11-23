/* ==========================================================================
   Reusable Layer 3 Multi-Source Vulnerability Intel Aggregation & Arbitration Lab
   Zero-dependency vanilla JS shared across Layer 3 intelligence lessons.
   Usage:
     <section class="widget-panel" data-widget="vuln-intel-lab">
       <script type="application/json" class="vuln-intel-lab-data">{ ... }</script>
     </section>
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

  const MODES = [
    { id: "naive", label: "反模式 · 直接混库 / 盲信单源" },
    { id: "industrial", label: "推荐方案 · 许可隔离 + 图关系分离 + 分字段裁决" },
  ];

  const DEFAULT_SCENARIOS = [
    {
      id: "nvd-backlog-vs-ghsa",
      tabLabel: "1. NVD 积压断层与 CPE 误配",
      contextTitle: "NVD 披露滞后窗口模拟 · CVEListV5 (CNA/ADP) + GHSA Reviewed 补位",
      rawRecords: [
        {
          id: "nvd-raw",
          source: "NIST NVD Feed (披露初期窗口模拟)",
          tierBadge: "Status: Awaiting Analysis",
          tierClass: "tier-low",
          identifier: "CVE-2026-22039 (CC0 / Public Domain)",
          note: "模拟新 CVE 披露后滞留 NVD Awaiting Analysis / Not Scheduled 队列：尚无 CPE 节点、无 CVSS 向量，仅有一段摘要。",
        },
        {
          id: "cvelist-v5",
          source: "CVEProgram/cvelistV5 (CNA + CISA-ADP)",
          tierBadge: "CNA Affected + ADP SSVC",
          tierClass: "tier-mid",
          identifier: "CVE-2026-22039 (containers.cna + adp)",
          note: "CNA 容器已声明 <1.15.3 与 >=1.16.0, <1.16.3；CISA-ADP（Vulnrichment）容器已补充 SSVC（Exploitation: poc, Technical Impact: total）。",
        },
        {
          id: "ghsa-reviewed",
          source: "GitHub Advisory DB (Reviewed)",
          tierBadge: "生态原生权威 · conf 0.96",
          tierClass: "tier-high",
          identifier: "GHSA-cvq5-hhx3-f99p (CC-BY-4.0)",
          note: "GitHub 安全团队人工核验：精准锚定 pkg:golang/github.com/kyverno/kyverno 区间并列 aliases: [CVE-2026-22039]。",
        },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：仅接 NVD 或拿摘要字符串硬猜包名",
          verdictTitle: "高危 CVE 在分析滞后期全线漏报，模糊匹配又引爆跨项目误报",
          summary:
            "传统架构只拉取 NVD 同步库且依赖 CPE 字符串匹配：在 NVD 积压未分配 CPE 期间，所有新披露漏洞全部静默漏报；若粗暴用产品名做模糊文本匹配，又会把同名无关组件拖进误报泥潭。",
          itemTags: {
            "nvd-raw": { cls: "ghost", text: "无 CPE · 窗口期漏报" },
            "cvelist-v5": { cls: "dropped", text: "未接 CVEListV5" },
            "ghsa-reviewed": { cls: "dropped", text: "未接生态库" },
          },
          irSnippet: [
            "// 反模式：纯 NVD CPE 驱动管线输出",
            '"cve_id": "CVE-2026-22039",',
            '"nvd_vuln_status": "Awaiting Analysis",',
            '"cpe_configurations": [], // ❌ 匹配规则为空，全公司静默漏报',
            '"fallback_fuzzy_match": "kyverno* -> 误命中 unrelated-kyverno-helper"'
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：GHSA-Reviewed + CVEListV5 (CNA/ADP) 主位，NVD 兜底",
          verdictTitle: "零等待当天完成精确 PURL 区间入库，并保留 CVE/CISA-ADP 富化信号",
          summary:
            "开源语言生态优先采用 GHSA Reviewed 与生态原生库（PyPA/Go/RustSec）提供的精确 PURL 与 [introduced, fixed) 区间；同步直连 cvelistV5 解析 CNA 与 CISA-ADP 容器补全 CVSS/SSVC/CWE；NVD 则退居闭源商业软件/固件 CPE 兜底与历史回补。",
          itemTags: {
            "nvd-raw": { cls: "superseded", text: "DEFERRED (无 CPE)" },
            "cvelist-v5": { cls: "enriched", text: "ENRICHED (CWE/SSVC)" },
            "ghsa-reviewed": { cls: "kept", text: "PRIMARY (PURL+区间)" },
          },
          irSnippet: [
            "// Layer 3 归一化裁决输出 (Canonical Group)",
            '"canonical_group_id": "VGRP-2026-22039",',
            '"aliases": ["CVE-2026-22039", "GHSA-cvq5-hhx3-f99p"],',
            '"range_authority": "ghsa-reviewed (pkg:golang/github.com/kyverno/kyverno)",',
            '"events": [{ "introduced": "1.16.0" }, { "fixed": "1.16.3" }],',
            '"enrichment": { "cvss_v3": 9.9, "ssvc_source": "CISA-ADP" }'
          ].join("\n"),
        },
      },
    },
    {
      id: "aliases-vs-upstream",
      tabLabel: "2. 别名等价 vs Upstream 衍生",
      contextTitle: "OSV v1.7.0 核心分水岭 · 防止 Debian DSA / Ubuntu USN 区间交叉污染",
      rawRecords: [
        {
          id: "ghsa-cve",
          source: "Upstream CVE / GHSA / Go VulnDB",
          tierBadge: "同一上游缺陷 · aliases",
          tierClass: "tier-high",
          identifier: "GHSA-xr7r-f8xq-vfvv <-> CVE-2024-21626 <-> GO-2024-2491",
          note: "指向完全相同的上游 opencontainers/runc 源码缺陷与官方修复版本 fixed: 1.1.12。",
        },
        {
          id: "debian-dsa",
          source: "Debian Security Tracker (DSA)",
          tierBadge: "发行版 Backport · upstream",
          tierClass: "tier-mid",
          identifier: "DSA-5615-1 (affected: pkg:deb/debian/runc)",
          note: "Debian 12 向旧主版本回溯打补丁：fixed: 1.1.5+ds1-1+deb12u1（版本号仍低于 1.1.12！）。",
        },
        {
          id: "ubuntu-usn",
          source: "Ubuntu Security Notice (USN)",
          tierBadge: "发行版 Backport · upstream",
          tierClass: "tier-mid",
          identifier: "USN-6619-1 (affected: pkg:deb/ubuntu/runc)",
          note: "Ubuntu 22.04 独立维护 Backport 补丁 1.1.7-0ubuntu1~22.04.2，在 OSV v1.7.0 中通过 upstream 指向 CVE-2024-21626。",
        },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：把 DSA / USN 全部塞进 aliases 做等价传递闭包",
          verdictTitle: "上游 <1.1.12 未修区间误传染给 Debian 已修补包，引爆大规模误报",
          summary:
            "若忽略 aliases（对称等价）与 upstream（有向衍生）的语义界线，把 DSA-5615-1 与 CVE-2024-21626 合并成同一等价组并共享 affected 区间，会导致已打上 Backport 补丁的 Debian 1.1.5+ds1-1+deb12u1 依然命中上游 <1.1.12 规则！",
          itemTags: {
            "ghsa-cve": { cls: "kept", text: "混入同一等价组" },
            "debian-dsa": { cls: "ghost", text: "误继承 <1.1.12 误报!" },
            "ubuntu-usn": { cls: "ghost", text: "关联告警交叉污染" },
          },
          irSnippet: [
            "// 反模式：DSA 被错误归入 aliases 传递闭包",
            '"bad_alias_group": ["CVE-2024-21626", "GHSA-xr7r-f8xq-vfvv", "DSA-5615-1"],',
            '"merged_affected_rules": [',
            '  { "purl": "pkg:deb/debian/runc", "fixed": "1.1.5+ds1-1+deb12u1" },',
            '  { "purl": "pkg:deb/debian/runc", "fixed": "1.1.12" } // ❌ 污染 Debian 12 匹配!',
            "]"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：严格分离等价边（ALIASES）与衍生边（UPSTREAM_OF）",
          verdictTitle: "报告计数合并降噪，而版本匹配规则按发行版作用域严格隔离",
          summary:
            "遵循 OSV Schema v1.7.0：仅在 GHSA <-> CVE <-> GO 间建立对称 ALIAS_OF 边；对 Debian DSA / Ubuntu USN 建立有向 UPSTREAM_OF -> CVE-2024-21626 边。Layer 3 匹配时发行版组件只认发行版作用域区间，展示层则沿 UPSTREAM_OF 折叠进同一张漏洞工单。",
          itemTags: {
            "ghsa-cve": { cls: "kept", text: "ALIAS_OF (对称等价)" },
            "debian-dsa": { cls: "coexist", text: "UPSTREAM_OF · 独立匹配" },
            "ubuntu-usn": { cls: "coexist", text: "UPSTREAM_OF · 独立匹配" },
          },
          irSnippet: [
            "// Layer 3 关系图边模型 (advisory_edges) + 作用域匹配隔离",
            '"edges": [',
            '  { "src": "GHSA-xr7r-f8xq-vfvv", "type": "ALIAS_OF", "dst": "CVE-2024-21626" },',
            '  { "src": "GO-2024-2491",        "type": "ALIAS_OF", "dst": "CVE-2024-21626" },',
            '  { "src": "DSA-5615-1",          "type": "UPSTREAM_OF", "dst": "CVE-2024-21626" }',
            "],",
            '"match_eval(deb/debian/runc@1.1.5+ds1-1+deb12u1?distro=debian-12)": "NOT_AFFECTED"'
          ].join("\n"),
        },
      },
    },
    {
      id: "arbiter-and-withdrawn",
      tabLabel: "3. 冲突裁决与 Withdrawn 撤销",
      contextTitle: "教学模拟场景 · Unreviewed 噪音 vs Reviewed 精校 + 虚假 CVE 撤销墓碑事件",
      rawRecords: [
        {
          id: "ghsa-unrev",
          source: "GitHub Advisory (Unreviewed)",
          tierBadge: "自动导入 · conf 0.40",
          tierClass: "tier-low",
          identifier: "GHSA-xxxx-unrev-demo (CVE-2026-XXXXX 模拟)",
          note: "早期自动脚本从刚申请的 CVE 抓取：把受影响范围错误写成全版本 <99.0.0。",
        },
        {
          id: "pypa-withdrawn",
          source: "PyPA Advisory DB (Canonical)",
          tierBadge: "官方审查 · withdrawn",
          tierClass: "tier-high",
          identifier: "PYSEC-2026-XXXX (withdrawn: 2026-05-26T00:00Z)",
          note: "Python 包维护者联合 PyPA 确认该报告为恶意刷 CVE 误报，正式打上 withdrawn 墓碑时间戳撤销！",
        },
        {
          id: "nvd-rejected",
          source: "NVD / CVEListV5",
          tierBadge: "状态同步中 · 滞后",
          tierClass: "tier-mid",
          identifier: "CVE-2026-XXXXX (State: PUBLISHED -> REJECTED)",
          note: "MITRE/NVD 尚未完成 REJECTED 同步，NVD Feed 在未来 48 小时内仍显示为有效漏洞。",
        },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：无差别保留全部多源记录，或忽略 withdrawn 墓碑",
          verdictTitle: "已被官方撤销的虚假 CVE 依然卡死全公司 CI/PR 门禁 48 小时+",
          summary:
            "若采集器只做 INSERT ON CONFLICT DO NOTHING 而不处理 withdrawn 时间戳，或由于 NVD 延迟未同步 REJECT 状态而继续触发告警，全公司数千个项目将为一个根本不存在的虚假漏洞停工救火。",
          itemTags: {
            "ghsa-unrev": { cls: "ghost", text: "错误区间残留生效" },
            "pypa-withdrawn": { cls: "dropped", text: "忽略 withdrawn 字段" },
            "nvd-rejected": { cls: "ghost", text: "滞后 NVD 仍报错" },
          },
          irSnippet: [
            "// 反模式：缺少墓碑状态传播与权威等级覆盖",
            '"match_rules_active": true, // ❌ NVD 尚未同步 REJECT，继续匹配',
            '"ghsa_unreviewed_range": "< 99.0.0",',
            '"ci_gate_impact": "BLOCKED 1,420 pipelines on bogus CVE"'
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：领域权威矩阵裁决 + 墓碑冻结 + 持续重算收敛",
          verdictTitle: "保留审计记录但立即停用匹配规则，触发 Hyades 自动消警",
          summary:
            "Arbitrator 发现原生生态权威（PyPA / GHSA-Reviewed）已标记 withdrawn，立即把规范组状态置为 WITHDRAWN（不物理删除以留审计线索），冻结全部下游别名规则（包含滞后的 NVD 与 Unreviewed），并向 Kafka 发送 intel.advisory.updated 事件通知各项目自动收敛状态。",
          itemTags: {
            "ghsa-unrev": { cls: "superseded", text: "OVERRIDDEN BY WITHDRAWN" },
            "pypa-withdrawn": { cls: "kept", text: "TOMBSTONE 权威生效" },
            "nvd-rejected": { cls: "superseded", text: "SUPPRESSED (等待同步)" },
          },
          irSnippet: [
            "// Layer 3 裁决状态机 + Lesson 0006 事件联动",
            '"canonical_group_id": "VGRP-2026-XXXXX",',
            '"lifecycle_state": "WITHDRAWN", "withdrawn_at": "2026-05-26T00:00:00Z",',
            '"matcher_rule_enabled": false,',
            '"kafka_event_emitted": "intel.advisory.updated -> auto-resolve active findings"'
          ].join("\n"),
        },
      },
    },
    {
      id: "osv-license-gate",
      tabLabel: "4. 商用闭源数据许可隔离",
      contextTitle: "MISSION.md 红线 · OSV.dev 并非单一开源许可，混合打包触法风险",
      rawRecords: [
        {
          id: "rustsec-cc0",
          source: "RustSec / NVD / CVEListV5",
          tierBadge: "CC0-1.0 / Public Domain",
          tierClass: "tier-high",
          identifier: "RUSTSEC-2025-XXXX (CC0-1.0 示例)",
          note: "公有领域或等效免署名许可，可自由纳入商业闭源产品与离线私有化分发包。",
        },
        {
          id: "ghsa-ccby",
          source: "GHSA / PyPA / Go VulnDB / OSS-Fuzz",
          tierBadge: "CC-BY-4.0 (须署名)",
          tierClass: "tier-mid",
          identifier: "GHSA-xxxx-xxxx-xxxx (CC-BY-4.0 示例)",
          note: "允许商业闭源使用与分发，但必须在产品界面、API 文档或离线包 NOTICE 中明确履行署名与变更声明。",
        },
        {
          id: "ubuntu-ccbysa",
          source: "OSV.dev Ubuntu / Alpine 转换库",
          tierBadge: "CC-BY-SA-4.0 (ShareAlike)",
          tierClass: "tier-low",
          identifier: "UBUNTU-CVE-2024-xxxx (CC-BY-SA-4.0)",
          note: "基于 OSV.dev 公布的源数据表标注为 CC-BY-SA-4.0：若直接将整库合并改造为商业闭源衍生数据库对外打包分发，存在相同方式共享传染争议。",
        },
        {
          id: "wolfi-nc",
          source: "OSV.dev Chainguard / Wolfi Feed",
          tierBadge: "CC-BY-NC-ND / 商业扫描器受限",
          tierClass: "tier-low",
          identifier: "CGA-xxxx-xxxx (Commercial Scanner Restricted)",
          note: "明确限制商业扫描器直接再分发或用于竞品商业服务！绝不可随闭源 SCA 离线包打包售卖。",
        },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：直接 wget gs://osv-vulnerabilities/all.zip 打包卖给客户",
          verdictTitle: "触发 CC-BY-NC-ND 商业违约与 CC-BY-SA 衍生库合规雷区",
          summary:
            "许多团队误以为 OSV 工具代码是 Apache-2.0 就代表 all.zip 数据也能随便打包进闭源商业版售卖。实际上 OSV.dev 数据按上游继承不同许可，直接整包混卖会同时违反非商业禁售条款、ShareAlike 隔离与 CC-BY 署名义务。",
          itemTags: {
            "rustsec-cc0": { cls: "kept", text: "混入大包" },
            "ghsa-ccby": { cls: "ghost", text: "漏掉 NOTICE 署名" },
            "ubuntu-ccbysa": { cls: "ghost", text: "SA 衍生边界风险!" },
            "wolfi-nc": { cls: "dropped", text: "NC-ND 商用违约!" },
          },
          irSnippet: [
            "// 反模式：无差别全量拉取 OSV all.zip 编译进商业离线 SQLite",
            '"bundle_sources": ["ghsa", "rustsec", "ubuntu-osv", "chainguard-wolfi"],',
            '"attribution_notice_generated": false, // ❌ 违反 CC-BY-4.0',
            '"commercial_license_audit": "FAILED (CC-BY-NC-ND + ShareAlike mixed)"'
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：采集闸门强校验 License + 分发包隔离 + 自动 NOTICE",
          verdictTitle: "商业离线内核仅装配绿灯源，自动生成 CC-BY 署名账本",
          summary:
            "在 Layer 3 采集入口设立 License Policy Gate：默认阻断 NC/ND 受限源（如 Chainguard 商业限制 feed）；对 CC-BY-SA 数据保持独立转换/隔离或直接采纳官方客观安全通告事实与商业授权源；所有 CC-BY-4.0 源自动注册入 ATTRIBUTION_NOTICE 并随离线包一并下发。",
          itemTags: {
            "rustsec-cc0": { cls: "kept", text: "ALLOWED (CC0)" },
            "ghsa-ccby": { cls: "enriched", text: "ALLOWED + NOTICE 署名" },
            "ubuntu-ccbysa": { cls: "superseded", text: "QUARANTINED (隔离/直采)" },
            "wolfi-nc": { cls: "dropped", text: "BLOCKED BY GATE" },
          },
          irSnippet: [
            "// Layer 3 商业闭源合规分发策略清单 (intel_feed_policy.yaml)",
            '"commercial_offline_bundle": {',
            '  "allowed_feeds": ["nvd", "cvelistv5", "rustsec", "ghsa-reviewed", "go", "pypa", "redhat-ccby"],',
            '  "quarantined_or_isolated": ["ubuntu-ccbysa (direct-tracker-only)"],',
            '  "hard_blocked": ["chainguard-nc-nd"],',
            '  "auto_generated_notices": "THIRD_PARTY_DATA_NOTICES.md (CC-BY-4.0)"',
            "}"
          ].join("\n"),
        },
      },
    },
  ];

  function initVulnIntelLab(container) {
    const dataEl = container.querySelector("script.vuln-intel-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        container.innerHTML = "<p>漏洞情报实验台数据解析失败。</p>";
        return;
      }
    }

    const scenarios = config.scenarios || DEFAULT_SCENARIOS;
    const state = {
      scenarioIdx: 0,
      modeId: "naive",
    };

    function render() {
      const sc = scenarios[state.scenarioIdx] || scenarios[0];
      const out = sc.modes[state.modeId] || sc.modes.industrial;

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "多源漏洞情报汇聚与裁决实验台")}</h3>
          <div class="widget-status">${escapeHtml(sc.tabLabel)}</div>
        </div>
      `;

      if (config.intro) {
        html += `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(config.intro)}</p>`;
      }

      html += `<div class="dep-lab-tabs">`;
      scenarios.forEach((item, idx) => {
        html += `
          <button type="button" class="dep-tab-btn ${idx === state.scenarioIdx ? "active" : ""}" data-sc="${idx}">
            ${escapeHtml(item.tabLabel)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="dep-lab-controls">`;
      html += `<span class="dep-lab-ctrl-label">切换 Layer 3 汇聚策略</span>`;
      MODES.forEach((m) => {
        html += `
          <button type="button" class="dep-toggle-btn ${m.id === state.modeId ? "active" : ""}" data-mode="${m.id}">
            ${escapeHtml(m.label)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="fusion-grid">`;

      html += `<div>`;
      html += `<div class="fusion-col-head">多源上游原始情报输入（${escapeHtml(sc.contextTitle)}）</div>`;
      html += `<div class="fusion-raw-list">`;
      sc.rawRecords.forEach((rec) => {
        const tag = out.itemTags && out.itemTags[rec.id];
        html += `
          <div class="fusion-item ${escapeHtml(rec.tierClass)}">
            <div class="fusion-item-top">
              <span class="fusion-source">${escapeHtml(rec.source)}</span>
              <div class="fusion-badge-row">
                <span class="fusion-tag">${escapeHtml(rec.tierBadge)}</span>
                ${tag ? `<span class="fusion-tag ${escapeHtml(tag.cls)}">${escapeHtml(tag.text)}</span>` : ""}
              </div>
            </div>
            <div class="fusion-purl">${escapeHtml(rec.identifier)}</div>
            <p class="fusion-item-note">${escapeHtml(rec.note)}</p>
          </div>
        `;
      });
      html += `</div></div>`;

      html += `
        <div class="fusion-result-box">
          <div class="fusion-col-head">Layer 3 规范化裁决与下游载荷</div>
          <div class="dep-verdict-box ${escapeHtml(out.status)}">
            <div class="dep-verdict-label">${escapeHtml(out.verdictLabel)}</div>
            <div class="dep-verdict-main">${escapeHtml(out.verdictTitle)}</div>
            <p class="dep-verdict-note">${escapeHtml(out.summary)}</p>
          </div>
          <div class="dep-graph-box">
            <div class="dep-graph-head">
              <span>汇聚后规范输出（Layer 3 IR / 策略）</span>
              <span>策略：${escapeHtml(MODES.find((m) => m.id === state.modeId)?.label || state.modeId)}</span>
            </div>
            <pre class="fusion-json">${escapeHtml(out.irSnippet)}</pre>
          </div>
        </div>
      `;

      html += `</div>`;

      container.innerHTML = html;

      container.querySelectorAll(".dep-tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.scenarioIdx = Number(btn.dataset.sc);
          render();
        });
      });

      container.querySelectorAll(".dep-toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.modeId = btn.dataset.mode;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="vuln-intel-lab"]').forEach(initVulnIntelLab);
  });
})();
