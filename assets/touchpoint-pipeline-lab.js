/* ==========================================================================
   Reusable Multi-Touchpoint Ingestion & Continuous Re-evaluation Lab
   Zero-dependency vanilla JS shared across ingestion & platform pipeline lessons.
   Usage:
     <section class="widget-panel" data-widget="touchpoint-lab">
       <script type="application/json" class="touchpoint-lab-data">{ ... }</script>
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
    { id: "naive", label: "反模式 · 单一模式硬套全场景" },
    { id: "industrial", label: "推荐方案 · 触点分级与事件驱动解耦" },
  ];

  const DEFAULT_SCENARIOS = [
    {
      id: "ide-lsp",
      tabLabel: "1. IDE 本地反馈（LSP）",
      contextTitle: "延迟预算 <= 1.5s · 开发者编辑 package.json / go.mod",
      inspectTitle: "IDE 编辑器实时交互轨迹",
      inspectTag: "VS Code / JetBrains -> sca-ls",
      inspectTree: [
        "[编辑器事件流]",
        "  t=0.00s  didOpen(package.json)        -> 首次入库扫描",
        "  t=0.40s  didChange(键入 '\"ax')         -> 编辑中（未合法 JSON）",
        "  t=0.80s  didChange(键入 'ios\": \"0.21') -> 编辑中",
        "  t=1.90s  didSave(package-lock.json)   -> 文件落盘 SHA 变更!",
        "",
        "[本地状态与缓存]",
        "  ├── 已缓存 PURL: pkg:npm/express@4.19.2 (TTL 命中, 0ms)",
        "  └── 增量变更 PURL: pkg:npm/axios@0.21.1 (待匹配)"
      ].join("\n"),
      badges: [
        { cls: "add", text: "didOpen / didSave 触发" },
        { cls: "opq", text: "OSV-SCALIBR 本地静态提取" },
        { cls: "del", text: "禁每次按键拉起 mvn/npm 构建" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：didChange 实时同步构建 + 在 VS Code/IDEA 各写一套逻辑",
          verdictTitle: "编辑器卡死 18 秒 + 每分钟打爆后端匹配接口配额",
          summary:
            "在每次按键（didChange）就触发完整依赖解析甚至拉起 npm/mvn 子进程，会导致半成品 JSON 报错、CPU 飙升卡死 IDE 线程；为多个编辑器各自维护原生插件逻辑，也会导致告警规则与 CI 严重漂移。",
          irSnippet: [
            "// 反模式：每次敲键盘发一次全量请求，无本地缓存与防抖",
            "event=didChange -> spawn('mvn dependency:tree')  // ❌ 耗时 18,400ms",
            "POST /api/v1/scan/full  payload={ 248 packages }  // ❌ 重复全量查询",
            "UI 状态: 卡顿阻塞 · 28 次无效请求 · 规则与 CI 门禁不一致"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：snyk-ls 模式（Go 独立 LSP + 防抖 + 差量缓存）",
          verdictTitle: "180ms 内精准标红 pkg:npm/axios@0.21.1，仅查询 1 个增量 PURL",
          summary:
            "IDE 插件只做薄 UI，统一通过 stdio JSON-RPC 对接 Go 编写的 sca-ls 后台进程。仅在 didOpen/didSave（带 Manifest 文件哈希校验）异步执行泳道 A 本地静态提取，命中本地 PURL LRU 缓存直接渲染，仅把新增/变更 PURL 打包批量查询后端。",
          irSnippet: [
            "// 推荐输出：LSP 后台异步执行 + PURL 差量查询",
            "trigger: didSave(sha256 changed) -> local OSV-SCALIBR (62ms)",
            "cache_hit: 247/248 PURLs -> delta_query: [\"pkg:npm/axios@0.21.1\"] (95ms)",
            "publishDiagnostics: {",
            "  \"range\": \"line 14\", \"severity\": \"High\",",
            "  \"codeAction\": \"Upgrade axios -> 1.7.4 (CVE-2021-3749)\"",
            "}"
          ].join("\n"),
        },
      },
    },
    {
      id: "pr-diff",
      tabLabel: "2. PR 门禁增量 Diff",
      contextTitle: "延迟预算 5–30s · 存在历史债务与 Base 快照缺失边界",
      inspectTitle: "Pull Request 分支快照对比视图",
      inspectTag: "PR #418 (feat/pay -> main)",
      inspectTree: [
        "[Base 分支 (main @ merge-base 7a9f2c)]",
        "  ├── 历史存量旧债: 42 个 CVE (含 legacy-xml@1.0.2 High)",
        "  └── CI 状态: ⚠️ 主干最后一次完整快照落后或缺失!",
        "",
        "[Head 分支 (feat/pay @ e3c10b)]",
        "  ├── 保留全部 42 个历史旧债 (本 PR 未触碰)",
        "  ├── 新增直接依赖: pkg:npm/lodash@4.17.15 (scope=runtime, CVE-2021-23337)",
        "  └── 作用域变更: pkg:npm/junit-helper (test -> runtime, 含旧 High CVE)"
      ].join("\n"),
      badges: [
        { cls: "add", text: "Net-New = Risk(Head) - Risk(Base)" },
        { cls: "opq", text: "Base 缺失时 Tier 1 兜底基线" },
        { cls: "del", text: "严禁因 42 个老债阻断当前 PR" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：全量告警阻断 或 Base 缺失时直接 Fail-Open 放行",
          verdictTitle: "要么被 42 个老漏洞卡死全部 PR，要么漏放新增高危漏洞",
          summary:
            "若 PR 门禁直接拿 Head 扫描全量结果做阻断，业务团队改一行无关代码也会被 42 个历史遗留漏洞卡死，最终被迫关掉门禁；而若因 Base 快照未命中就跳过检查（Fail-Open），新引入的 lodash@4.17.15 将长驱直入主干。",
          irSnippet: [
            "// 反模式：拿全量存量清单做门禁判断",
            '"pr_gate_decision": "BLOCKED",',
            '"blocking_count": 43, // ❌ 把 42 个与本 PR 无关的老洞算在开发者头上',
            '"if_base_missing": "PASS_WITH_SKIP" // ❌ 基线缺失时直接放行高危新包'
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：基于 Layer 2 IR 的增量图差 + 同步静态基线兜底",
          verdictTitle: "精确拦截 2 项净新增风险（新包 + test->runtime 提权），8.2s 放行说明",
          summary:
            "当 merge-base 的权威快照缺失时，门禁 Worker 同步抽取 merge-base 的清单文件在内存跑 Tier 1 静态解析生成 G_base_fallback（耗时 ~2s）。随后按 (vuln_id, canonical_purl, scope_class, subpath) 计算集合差，精准识别新增组件及由 test 提升为 runtime 的生产暴露风险。",
          irSnippet: [
            "// 推荐输出：Net-New Delta Report (PR Check 8.2s 完成)",
            '"base_resolution": "tier1_static_fallback (merge_base=7a9f2c)",',
            '"legacy_debt_ignored": 42,',
            '"net_new_blockers": [',
            '  { "type": "NEW_PKG", "purl": "pkg:npm/lodash@4.17.15", "cve": "CVE-2021-23337" },',
            '  { "type": "SCOPE_ESCALATION", "purl": "pkg:npm/junit-helper@2.1", "from": "test", "to": "runtime" }',
            "]"
          ].join("\n"),
        },
      },
    },
    {
      id: "ci-cas",
      tabLabel: "3. Monorepo CI 与 CAS 去重",
      contextTitle: "延迟预算 1–5m · 120 个微服务共用一个巨型仓库",
      inspectTitle: "CI 触发时各服务清单指纹对比",
      inspectTag: "Commit 91d4e8 (仅修改 docs/ + svc-auth)",
      inspectTree: [
        "[Monorepo 目录树: 120 个子服务]",
        "  ├── services/billing/go.mod+go.sum  -> sha256:aaa111 (与上次一致)",
        "  ├── services/order/pom.xml          -> sha256:bbb222 (与上次一致)",
        "  ├── ... (其余 117 个服务依赖树均未修改)",
        "  └── services/auth/package-lock.json -> sha256:ccc999 (依赖已变更!)",
        "",
        "[CAS 缓存键构造]",
        "  cas_key = sha256(normalized_manifests + env_fingerprint + extractor_ver)"
      ].join("\n"),
      badges: [
        { cls: "add", text: "CAS 命中跳过 L1 解析" },
        { cls: "opq", text: "Zero-Copy Pointer Rebind" },
        { cls: "del", text: "禁无脑重跑 120 次 ORT/Maven" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：每次 Commit 对全仓 120 个模块重新执行 Tier 3 构建解析",
          verdictTitle: "CI 排队 28 分钟，重复向服务端上传 120 份一模一样的 15MB BOM",
          summary:
            "只改了 README 或 1 个微服务的依赖，却在 CI 里盲目调用 ORT/cdxgen 重跑全仓构建并重复灌入 120 份完整依赖图，不仅把 CI Runner 和数据库 I/O 拖垮，还造成大量内容完全相同的冗余图谱存储爆炸。",
          irSnippet: [
            "// 反模式：120 个服务全量重跑构建与全量写库",
            "ort_runs_triggered: 120,   // ❌ 119 个服务浪费 25 分钟构建算力",
            "sbom_payloads_uploaded: 120 * 14MB = 1.68 GB,",
            "postgres_graph_writes: 480,000 duplicate edges"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：CAS 内容寻址跳过重算 + 提交指针轻量重绑定",
          verdictTitle: "119 个未变模块 15ms 完成指针绑定，仅 1 个变更模块跑构建解析",
          summary:
            "CI 插件先为每个模块计算归一化依赖输入哈希与构建环境指纹，通过 /v1/snapshots/probe 探测服务端 CAS 索引。命中历史快照的服务零提取直接生成一条 commit_sha -> snapshot_id 绑定记录；未命中的 services/auth 才执行 Tier 3 构建并上传增量快照。",
          irSnippet: [
            "// 推荐输出：CAS Skip-Scan + 完整 Commit 审计溯源",
            '"cas_probe_summary": { "total_modules": 120, "cas_hit": 119, "re_extracted": 1 },',
            '"pointer_rebinds": "119 commits -> existing snapshot_ids (15ms, 0 bytes BOM)",',
            '"new_snapshot_uploaded": {',
            '  "module": "services/auth", "commit": "91d4e8",',
            '  "cas_key": "sha256:ccc999...", "tier": "Tier 3 (cdxgen/ORT)"',
            "}"
          ].join("\n"),
        },
      },
    },
    {
      id: "hyades-reeval",
      tabLabel: "4. 0-day 异步持续重算",
      contextTitle: "Hyades (Dependency-Track v5) · 30,000 仓库 0-day 应急响应",
      inspectTitle: "凌晨 02:14 情报更新事件流",
      inspectTag: "CVE-2026-XXXX (log4j-core)",
      inspectTree: [
        "[Layer 3 漏洞情报流到达]",
        "  Event: intel.advisory.updated",
        "  PURL Range: pkg:maven/org.apache.logging.log4j/log4j-core [<2.24.0]",
        "",
        "[PostgreSQL 倒排索引状态 (30,000 个项目快照)]",
        "  ├── 命中该 PURL 的总快照数: 18,400 份",
        "  │     ├── 历史废弃 Feature 分支 / 已关闭 PR 快照: 16,200 份 (TTL 归档)",
        "  │     └── 活跃主干 / 生产在跑容器镜像快照:     2,200 份 (Active Scope!)",
        "  └── 源码 Git 仓库: 无需重新 clone（Layer 2 IR 已完整持久化）"
      ].join("\n"),
      badges: [
        { cls: "add", text: "一次采集 · 持续重算" },
        { cls: "opq", text: "Kafka 分区异步流控" },
        { cls: "del", text: "活跃窗口过滤（豁免僵尸快照）" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：定时轮询重拉源码仓库 或 单体内存队列全量重算 18,400 份快照",
          verdictTitle: "要么 24 小时后才发现中招，要么 OOM 打死 API 网关并锁死数据库",
          summary:
            "初代架构要么靠夜间定时 Cron 重新克隆仓库扫一遍（0-day 暴露窗口长达数小时且 GitLab 崩溃），要么像早期单体队列那样把包含 16,200 份已关闭 PR 的全量快照全部塞进 API 进程内存并发重算，瞬间 OOM 并阻塞白天正常 CI 上报。",
          irSnippet: [
            "// 反模式：定时重克隆或单体无差别重算全库",
            "cron_reclone_30k_repos: \"ETA 6h 40m (GitLab 503)\",",
            "in_memory_queue_depth: 18400, // ❌ 88% 算力浪费在半年前废弃 PR 上",
            "apiserver_status: \"OOMKilled (Exit 137)\""
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：Hyades 事件驱动微批重算 + 活跃分支剪枝 + 泳道隔离",
          verdictTitle: "零源码拉取，42 秒内完成 2,200 个活跃生产项目定位与告警推送",
          summary:
            "借鉴 Dependency-Track v5 (Hyades) 架构：情报入库后发送事件到低优先级 Bulk Kafka Topic（绝不阻塞白天的 PR 交互通道），vuln-analyzer 通过 PURL 倒排索引仅捞出 2,200 份活跃主干与生产镜像快照分批重算，并由 notification-publisher 推送精准负责人。",
          irSnippet: [
            "// 推荐输出：事件驱动双触发持续重算流水线",
            "trigger: \"intel.advisory.updated\" -> reverse_purl_lookup (180ms)",
            "active_window_filter: \"18,400 matched -> pruned to 2,200 active prod/main\"",
            "kafka_topic: \"sca.reeval.bulk\" (48 partitions, isolated from PR lane)",
            "elapsed: \"42.6s -> 2,200 snapshots evaluated, 318 impacted services alerted\""
          ].join("\n"),
        },
      },
    },
  ];

  function initTouchpointLab(container) {
    const dataEl = container.querySelector("script.touchpoint-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        container.innerHTML = "<p>多触点实验台数据解析失败。</p>";
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
          <h3 class="widget-title">${escapeHtml(config.title || "多触点采集与持续重算交互实验台")}</h3>
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
      html += `<span class="dep-lab-ctrl-label">切换架构策略对比</span>`;
      MODES.forEach((m) => {
        html += `
          <button type="button" class="dep-toggle-btn ${m.id === state.modeId ? "active" : ""}" data-mode="${m.id}">
            ${escapeHtml(m.label)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="oci-lab-grid">`;

      html += `<div>`;
      html += `<div class="oci-lab-col-head">${escapeHtml(sc.inspectTitle)}</div>`;
      html += `
        <div class="oci-lab-inspect">
          <div class="oci-lab-inspect-head">
            <span>输入事件与现场状态</span>
            <span>${escapeHtml(sc.inspectTag)}</span>
          </div>
          <pre class="oci-lab-tree">${escapeHtml(sc.inspectTree)}</pre>
        </div>
      `;
      if (sc.badges && sc.badges.length) {
        html += `<div class="oci-lab-badges">`;
        sc.badges.forEach((b) => {
          html += `<span class="wh-pill ${escapeHtml(b.cls)}">${escapeHtml(b.text)}</span>`;
        });
        html += `</div>`;
      }
      html += `</div>`;

      html += `
        <div class="oci-lab-result">
          <div class="oci-lab-col-head">工程裁决与运行时流转 · ${escapeHtml(sc.contextTitle)}</div>
          <div class="dep-verdict-box ${escapeHtml(out.status)}">
            <div class="dep-verdict-label">${escapeHtml(out.verdictLabel)}</div>
            <div class="dep-verdict-main">${escapeHtml(out.verdictTitle)}</div>
            <p class="dep-verdict-note">${escapeHtml(out.summary)}</p>
          </div>
          <div class="dep-graph-box">
            <div class="dep-graph-head">
              <span>运行时指令 / 状态载荷</span>
              <span>模式：${escapeHtml(MODES.find((m) => m.id === state.modeId)?.label || state.modeId)}</span>
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
    document.querySelectorAll('[data-widget="touchpoint-lab"]').forEach(initTouchpointLab);
  });
})();
