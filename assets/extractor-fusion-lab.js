/* ==========================================================================
   Reusable Multi-Extractor Confidence Fusion & Disambiguation Lab
   Zero-dependency vanilla JS shared across Layer 1 / Layer 2 lessons.
   Usage:
     <section class="widget-panel" data-widget="fusion-lab">
       <script type="application/json" class="fusion-lab-data">{ ... }</script>
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

  const STRATEGIES = [
    { id: "union", label: "策略 A · 简单并集（Naive Union）" },
    { id: "intersect", label: "策略 B · 简单交集（Naive Intersection）" },
    { id: "tiered", label: "策略 C · 分级置信度融合 + ACL（推荐底座）" },
  ];

  const DEFAULT_SCENARIOS = [
    {
      id: "maven-fatjar",
      tabLabel: "1. Java 多模块 + Fat-JAR",
      contextTitle: "单版本生态多引擎冲突：静态 pom.xml vs deps.dev vs 交付 Fat-JAR",
      rawEvidences: [
        {
          id: "scalibr-static",
          source: "OSV-SCALIBR (pomxml 静态无网)",
          tierBadge: "Tier 0 · conf 0.45",
          tierClass: "tier-low",
          purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
          note: "仅解析子模块声明与未展开属性/旧路径深度，误判带 Log4Shell (CVE-2021-44228) 版本。",
        },
        {
          id: "scalibr-net",
          source: "OSV-SCALIBR (transitivedependency/pomxml)",
          tierBadge: "Tier 2 · conf 0.82",
          tierClass: "tier-mid",
          purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
          note: "联网拉取 parent POM 与 platform-bom 展开 dependencyManagement，算得实际生效版本 2.17.1。",
        },
        {
          id: "syft-jar",
          source: "Syft (java-archive-cataloger 扫 target/app.jar)",
          tierBadge: "Tier 4 · conf 0.98",
          tierClass: "tier-high",
          purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
          note: "直接读取最终构建产出的 META-INF/maven/pom.properties 与 MANIFEST，交付实锤为 2.17.1。",
        },
      ],
      outcomes: {
        union: {
          status: "danger",
          verdictLabel: "灾难：爆发致命 Ghost CVE 误报",
          verdictTitle: "同时写入 2.14.1 与 2.17.1 两份组件记录",
          summary:
            "在 Java 单一 Classpath 语义下直接取多引擎并集，导致已失效的静态猜测 2.14.1 与真实产物 2.17.1 同时进入资产表，平台立刻触发不存在的 Log4Shell P0 阻断告警。",
          itemTags: {
            "scalibr-static": { cls: "ghost", text: "GHOST 误报入库" },
            "scalibr-net": { cls: "kept", text: "重复并存" },
            "syft-jar": { cls: "kept", text: "重复并存" },
          },
          irSnippet: [
            "// 错误：同一 Classpath 下并存两个冲突版本",
            '"snapshot_nodes": [',
            '  { "node_ref": "mvn:log4j-core@2.14.1", "confidence": 0.45 }, // ❌ 触发虚假 P0 CVE',
            '  { "node_ref": "mvn:log4j-core@2.17.1", "confidence": 0.98 }',
            "]",
          ].join("\n"),
        },
        intersect: {
          status: "danger",
          verdictLabel: "灾难：版本号冲突导致核心组件漏报消失",
          verdictTitle: "三方精确版本交集为空 → 0 条写入",
          summary:
            "因为静态提取器报了 2.14.1 而构建/制品引擎报了 2.17.1，三者按 (PURL, Version) 取交集直接得到空集！核心安全组件直接从资产台账蒸发，造成致命漏报。",
          itemTags: {
            "scalibr-static": { cls: "dropped", text: "冲突丢弃" },
            "scalibr-net": { cls: "dropped", text: "交集为空被杀" },
            "syft-jar": { cls: "dropped", text: "交集为空被杀" },
          },
          irSnippet: [
            "// 错误：交集过滤清除了真实交付组件",
            '"snapshot_nodes": [], // ❌ log4j-core 彻底漏报',
            '"dropped_reason": "version mismatch across 3 extractors"',
          ].join("\n"),
        },
        tiered: {
          status: "ok",
          verdictLabel: "推荐策略：单版本生态高阶覆写 + citations 留痕",
          verdictTitle: "唯一入库 log4j-core@2.17.1（Tier 4 覆写 Tier 0）",
          summary:
            "ACL 识别出三者归属同一 Maven 单版本作用域：按 Tier 4 (0.98) > Tier 2 (0.82) > Tier 0 (0.45) 规则，2.17.1 正式落库并覆写（Supersede）2.14.1，同时把被覆写原因写入 CycloneDX 1.7 citations[] 留作审计追踪。",
          itemTags: {
            "scalibr-static": { cls: "superseded", text: "SUPERSEDED (0.45)" },
            "scalibr-net": { cls: "enriched", text: "ENRICHED 佐证 (0.82)" },
            "syft-jar": { cls: "kept", text: "KEPT 主真值 (0.98)" },
          },
          irSnippet: [
            "// Layer 2 IR (ext_metadata.fusion_citations) + CycloneDX 1.7 导出投影",
            '"canonical_key": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",',
            '"confidence": 0.98, "tier": "tier4_artifact",',
            '"ext_metadata": { "fusion_citations": [',
            '  { "tool": "syft-java-archive", "status": "accepted" },',
            '  { "tool": "scalibr-pomxmlnet", "status": "corroborated" },',
            '  { "tool": "scalibr-pomxml-static", "status": "superseded_lower_tier", "claimed": "2.14.1" }',
            "]},",
            '// 导出 CycloneDX 1.7 citations[]: { "pointers": ["/components/0/version"], "attributedTo": "syft" }'
          ].join("\n"),
        },
      },
    },
    {
      id: "node-monorepo",
      tabLabel: "2. Node Monorepo · 多版本与安全模式",
      contextTitle: "多版本合法共存生态：OSV-SCALIBR pnpm 锁文件 + cdxgen pre-build 工作区边",
      rawEvidences: [
        {
          id: "scalibr-pnpm",
          source: "OSV-SCALIBR (pnpm-lock.yaml)",
          tierBadge: "Tier 1 · conf 0.92",
          tierClass: "tier-high",
          purl: "pkg:npm/lodash@4.17.21 (root) & @4.17.15 (packages/legacy)",
          note: "Go 进程内毫秒级解析 snapshots 与 importers，精准识别两处共存实例及 dev 标记。",
        },
        {
          id: "cdxgen-pre",
          source: "cdxgen (--lifecycle pre-build --no-install-deps)",
          tierBadge: "Tier 1 · conf 0.90",
          tierClass: "tier-mid",
          purl: "internal:workspaceRef → packages/legacy dependsOn lodash@4.17.15",
          note: "零代码执行安全模式下补全 Monorepo 工作区拓扑属性，规避 build 模式 postinstall RCE (CVE-2024-50611)。",
        },
      ],
      outcomes: {
        union: {
          status: "warn",
          verdictLabel: "隐患：若按 pkg name 合并则漏报，不合并则节点爆炸",
          verdictTitle: "缺乏 install_subpath 维度的粗糙并集失真",
          summary:
            "粗糙并集若只按 base_purl 去重会把 4.17.15 丢掉或覆盖；若直接把两个工具的节点原样堆叠，则同一个 root lodash@4.17.21 会出现两条冗余告警并丢失 workspace 边归属。",
          itemTags: {
            "scalibr-pnpm": { cls: "ghost", text: "未按路径对齐重复" },
            "cdxgen-pre": { cls: "ghost", text: "边与节点脱节" },
          },
          irSnippet: [
            "// 问题：重复节点或路径丢失",
            '"nodes": ["lodash@4.17.21 (scalibr)", "lodash@4.17.21 (cdxgen)"],',
            '"warning": "missing unified (purl, subpath) dedup key"',
          ].join("\n"),
        },
        intersect: {
          status: "danger",
          verdictLabel: "灾难：交集剪掉了工作区边与局部作用域",
          verdictTitle: "丢失 internal:workspaceRef 与 dev 精准标记",
          summary:
            "两个引擎各自提取了对方缺少的图属性（一个强在 pnpm snapshots，一个强在工作区边属性），取交集会导致 Monorepo 子包拓扑断裂。",
          itemTags: {
            "scalibr-pnpm": { cls: "dropped", text: "dev/路径元数据丢弃" },
            "cdxgen-pre": { cls: "dropped", text: "workspaceRef 丢弃" },
          },
          irSnippet: [
            "// 错误：丢失高价值边与作用域信息",
            '"snapshot_edges": [], // ❌ 无法定位是哪个子模块引入脆弱包',
          ].join("\n"),
        },
        tiered: {
          status: "ok",
          verdictLabel: "推荐策略：按 (purl, subpath) 分治 + 图边叠加",
          verdictTitle: "双实例合法共存 + 工作区有向边与 citations 合并",
          summary:
            "针对 npm/pnpm 多版本共存生态，融合器按 (canonical_purl, install_subpath) 精确对齐：root 的 4.17.21 合并双工具证据，packages/legacy 的 4.17.15 保持独立 bom-ref，同时叠加 cdxgen 的 workspaceRef 边与 zero-RCE 标识。",
          itemTags: {
            "scalibr-pnpm": { cls: "coexist", text: "COEXIST 节点基准 (0.92)" },
            "cdxgen-pre": { cls: "enriched", text: "ENRICHED 叠加拓扑边 (0.90)" },
          },
          irSnippet: [
            '"snapshot_nodes": [',
            '  { "node_ref": "npm:root:lodash@4.17.21", "scope": "required" },',
            '  { "node_ref": "npm:legacy:lodash@4.17.15", "subpath": "packages/legacy" }',
            "],",
            '"snapshot_edges": [{ "src": "pkg:legacy", "dst": "npm:legacy:lodash@4.17.15" }]',
          ].join("\n"),
        },
      },
    },
    {
      id: "oci-hybrid",
      tabLabel: "3. OCI 镜像（OS + PyPI + 历史层）",
      contextTitle: "异构资产域协同与镜像 Whiteout 语义：Syft vs OSV-SCALIBR",
      rawEvidences: [
        {
          id: "syft-squashed",
          source: "Syft (dpkg-db-cataloger · SquashedScope)",
          tierBadge: "Tier 4 · conf 0.96",
          tierClass: "tier-high",
          purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",
          note: "扫描镜像最终挂载文件系统，保留完整 distro=debian-12 限定符供 L3 Backport 消误报。",
        },
        {
          id: "syft-deleted",
          source: "Syft (AllLayersScope · 历史构建层)",
          tierBadge: "Audit Only · 已删除",
          tierClass: "tier-low",
          purl: "pkg:deb/debian/curl@7.88.1?arch=amd64&distro=debian-12",
          note: "该包在 Dockerfile 第 3 层安装，但第 4 层已 apt purge 删除（存在 Whiteout 标记）。",
        },
        {
          id: "scalibr-uv",
          source: "OSV-SCALIBR (uv.lock + Linux Py3.12 Marker)",
          tierBadge: "Tier 1 · conf 0.92",
          tierClass: "tier-high",
          purl: "pkg:pypi/requests@2.32.3",
          note: "在容器内应用目录解析锁文件并按目标 Linux/Py3.12 剪枝 Environment Markers。",
        },
      ],
      outcomes: {
        union: {
          status: "danger",
          verdictLabel: "灾难：AllLayers 幽灵包污染生产漏洞单",
          verdictTitle: "把已卸载的 curl@7.88.1 算入运行时脆弱资产",
          summary:
            "无脑取所有扫描输出并集时，构建中间层已被清理的 curl 混入运行态资产表，引发客户质疑“我镜像里根本没有 curl 这个命令/包为何报错”。",
          itemTags: {
            "syft-squashed": { cls: "kept", text: "正常入库" },
            "syft-deleted": { cls: "ghost", text: "幽灵层包污染" },
            "scalibr-uv": { cls: "kept", text: "正常入库" },
          },
          irSnippet: [
            "// 错误：未区分 Squashed 运行态与历史审计态",
            '"runtime_components": [',
            '  "openssl@3.0.11-1~deb12u2", "requests@2.32.3",',
            '  "curl@7.88.1" // ❌ 容器最终层已不存在！',
            "]",
          ].join("\n"),
        },
        intersect: {
          status: "danger",
          verdictLabel: "灾难：异构提取器交集为空 → 全盘归零",
          verdictTitle: "OS 包与 PyPI 包没有交集 → 0 个组件输出",
          summary:
            "Syft 擅长 dpkg/rpm OS 数据库，OSV-SCALIBR 擅长 uv.lock 语言生态；对异构域强行取交集会导致全部 OS 包和全部 Python 包一起被清空！",
          itemTags: {
            "syft-squashed": { cls: "dropped", text: "异构无交集丢弃" },
            "syft-deleted": { cls: "dropped", text: "丢弃" },
            "scalibr-uv": { cls: "dropped", text: "异构无交集丢弃" },
          },
          irSnippet: [
            "// 错误：对互补生态取交集导致 100% 漏报",
            '"snapshot_nodes": []',
          ].join("\n"),
        },
        tiered: {
          status: "ok",
          verdictLabel: "推荐策略：异构互补并集 + Whiteout 状态隔离",
          verdictTitle: "Squashed OS + PyPI 融合入库；历史层标记隔离",
          summary:
            "遵循规则 3「异构资产域互补并集」：Syft 的 SquashedScope deb 包与 OSV-SCALIBR 的 PyPI 包完美互补落库（各自携带 oci_layer 与 distro 限定符）；历史删除层包写入审计字段 deleted_in_layer，默认不触发运行时 CVE 阻断。",
          itemTags: {
            "syft-squashed": { cls: "kept", text: "KEPT OS 运行域 (0.96)" },
            "syft-deleted": { cls: "superseded", text: "ISOLATED 已卸载审计态" },
            "scalibr-uv": { cls: "kept", text: "KEPT PyPI 运行域 (0.92)" },
          },
          irSnippet: [
            '"active_nodes": [',
            '  "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",',
            '  "pkg:pypi/requests@2.32.3"',
            "],",
            '"audit_only_deleted_layers": ["pkg:deb/debian/curl@7.88.1 (whiteout @ layer4)"]',
          ].join("\n"),
        },
      },
    },
    {
      id: "airgapped-ort",
      tabLabel: "4. 断网私有化 + Gradle 合规",
      contextTitle: "能力感知路由与 Scope 精准隔离：OSV-SCALIBR (Offline) + ORT Analyzer",
      rawEvidences: [
        {
          id: "scalibr-offline",
          source: "OSV-SCALIBR (NetworkOffline Capabilities)",
          tierBadge: "Tier 1 · 零外网毫秒",
          tierClass: "tier-high",
          purl: "锁文件提取完成；deps.dev Enricher 已由 FilterByCapabilities 自动摘除",
          note: "面对政企纯内网环境，Capabilities 过滤器自动跳过依赖公网的在线 Enricher，避免挂起超时。",
        },
        {
          id: "ort-dynamic",
          source: "ORT Analyzer (无锁 Gradle · allowDynamicVersions=false)",
          tierBadge: "Gate · 显式告警",
          tierClass: "tier-low",
          purl: "发现 guava:31.+ 动态范围且无 gradle.lockfile",
          note: "ORT 默认拒绝猜测动态范围，向路由器发出需要 Tier 3 内网 CI Hook 构建的信号。",
        },
        {
          id: "ort-ci-hook",
          source: "ORT Analyzer (客户内网 CI Hook · GradleInspector)",
          tierBadge: "Tier 3 · conf 0.96",
          tierClass: "tier-high",
          purl: "guava@31.1-jre (runtimeClasspath) + junit-jupiter@5.10.2 (testCompileClasspath)",
          note: "在内网私有 Nexus 环境下跑完原生解析，产出全局去重 DependencyGraph 与精准 Scope 边界。",
        },
      ],
      outcomes: {
        union: {
          status: "warn",
          verdictLabel: "隐患：测试期 GPL/脆弱依赖混入生产阻塞",
          verdictTitle: "丢失 Scope 边界且暴露未过滤的动态警告噪音",
          summary:
            "若忽略 ORT 精细的 runtimeClasspath vs testCompileClasspath 区分并取并集，仅在单元测试运行的组件会被报成生产环境 P0 阻塞与传染性协议违规。",
          itemTags: {
            "scalibr-offline": { cls: "kept", text: "基础清单" },
            "ort-dynamic": { cls: "ghost", text: "告警未消解" },
            "ort-ci-hook": { cls: "ghost", text: "Scope 被拍平" },
          },
          irSnippet: [
            "// 问题：test 依赖被标成 required 或丢失 scope",
            '"junit-jupiter@5.10.2": { "scope": "required" } // ❌ 实际仅 testCompileClasspath',
          ].join("\n"),
        },
        intersect: {
          status: "danger",
          verdictLabel: "灾难：离线静态扫描无 Gradle 图导致大面积漏报",
          verdictTitle: "只剩极少两方共通锁文件项，丢光 Gradle 传递树",
          summary:
            "离线模式下 OSV-SCALIBR 对无锁 build.gradle 几乎无传递边输出，与 ORT 构建有效图取交集等于直接丢弃全部 Gradle 传递依赖。",
          itemTags: {
            "scalibr-offline": { cls: "dropped", text: "无 Gradle 图" },
            "ort-dynamic": { cls: "dropped", text: "丢弃" },
            "ort-ci-hook": { cls: "dropped", text: "传递依赖被交集抹除" },
          },
          irSnippet: [
            "// 错误：交集抹杀了 ORT CI Hook 的真实传递依赖",
            '"gradle_transitive_edges": 0',
          ].join("\n"),
        },
        tiered: {
          status: "ok",
          verdictLabel: "推荐策略：离线能力裁剪 + ORT CI 有效图接管",
          verdictTitle: "零外网超时 + runtime/test 精确 Scope 写入 L2 IR",
          summary:
            "Capability Router 在断网环境自动启用 OSV-SCALIBR NetworkOffline 套件并接纳内网 CI Hook 回传的 ORT OrtResult：由 ORT 权威边接管无锁 Gradle 传递图，ACL 将 testCompileClasspath 映射为 scope='excluded'/edge_scope='test'，合规与漏洞准确率拉满。",
          itemTags: {
            "scalibr-offline": { cls: "kept", text: "KEPT 离线高速底座" },
            "ort-dynamic": { cls: "superseded", text: "RESOLVED 由 CI 构建消解" },
            "ort-ci-hook": { cls: "enriched", text: "KEPT 有效图+Scope (0.96)" },
          },
          irSnippet: [
            '"snapshot_nodes": [',
            '  { "node_ref": "jvm:guava@31.1-jre", "scope": "required" },',
            '  { "node_ref": "jvm:junit@5.10.2", "scope": "excluded", "edge_scope": "test" }',
            "],",
            '"offline_capabilities": { "network": "offline", "external_timeouts": 0 }'
          ].join("\n"),
        },
      },
    },
  ];

  function initFusionLab(container) {
    const dataEl = container.querySelector("script.fusion-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        container.innerHTML = "<p>多引擎融合实验室数据解析失败。</p>";
        return;
      }
    }

    const scenarios = config.scenarios || DEFAULT_SCENARIOS;
    const state = {
      scenarioIdx: 0,
      strategyId: "union",
    };

    function render() {
      const sc = scenarios[state.scenarioIdx] || scenarios[0];
      const out = sc.outcomes[state.strategyId] || sc.outcomes.tiered;

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "多提取器置信度融合与消歧实验台")}</h3>
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
      html += `<span class="dep-lab-ctrl-label">切换融合引擎策略</span>`;
      STRATEGIES.forEach((st) => {
        html += `
          <button type="button" class="dep-toggle-btn ${st.id === state.strategyId ? "active" : ""}" data-st="${st.id}">
            ${escapeHtml(st.label)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="fusion-grid">`;

      // Left column: Raw evidence items
      html += `<div>`;
      html += `<div class="fusion-col-head">原始提取器输入流（经 ACL 翻译为 RawExtractionEnvelope）</div>`;
      html += `<div class="fusion-raw-list">`;
      sc.rawEvidences.forEach((ev) => {
        const tag = out.itemTags[ev.id] || { cls: "", text: "" };
        html += `
          <div class="fusion-item ${escapeHtml(ev.tierClass)}">
            <div class="fusion-item-top">
              <span class="fusion-source">${escapeHtml(ev.source)}</span>
              <div class="fusion-badge-row">
                <span class="fusion-tag">${escapeHtml(ev.tierBadge)}</span>
                ${tag.text ? `<span class="fusion-tag ${escapeHtml(tag.cls)}">${escapeHtml(tag.text)}</span>` : ""}
              </div>
            </div>
            <div class="fusion-purl">${escapeHtml(ev.purl)}</div>
            <p class="fusion-item-note">${escapeHtml(ev.note)}</p>
          </div>
        `;
      });
      html += `</div></div>`;

      // Right column: Verdict + IR snippet
      html += `
        <div class="fusion-result-box">
          <div class="fusion-col-head">融合裁决结果与 Layer 2 IR 落地投影 · ${escapeHtml(sc.contextTitle)}</div>
          <div class="dep-verdict-box ${escapeHtml(out.status)}">
            <div class="dep-verdict-label">${escapeHtml(out.verdictLabel)}</div>
            <div class="dep-verdict-main">${escapeHtml(out.verdictTitle)}</div>
            <p class="dep-verdict-note">${escapeHtml(out.summary)}</p>
          </div>
          <div class="dep-graph-box">
            <div class="dep-graph-head">
              <span>写入 Layer 2 IR / CycloneDX 1.7 citations 投影</span>
              <span>策略：${escapeHtml(STRATEGIES.find((s) => s.id === state.strategyId)?.label || state.strategyId)}</span>
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
          state.strategyId = btn.dataset.st;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="fusion-lab"]').forEach(initFusionLab);
  });
})();
