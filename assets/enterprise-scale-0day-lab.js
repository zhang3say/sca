/* ==========================================================================
   可复用交互组件：企业级海量资产台账与 0-day 秒级应急实验台（Lesson 0021+）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：海量资产 0-day 爆炸半径秒级检索仿真器
   模式二：策略引擎热更新（CEL vs OPA）与 0-day 门禁灰度模拟器
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

  function initEnterpriseScale0DayLab(container) {
    const dataEl = container.querySelector("script.enterprise-scale-0day-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const PRESETS = [
      {
        id: "log4shell-blast",
        label: "1. Log4Shell 级 0-day (1 万应用 / 1.2 亿边传递追杀)",
        desc: "某基础组件突发高危 0-day，需要 10 秒内定位所有直接与传递依赖该组件的生产在线应用、锁定精确版本号，并把爆炸半径路由给对应研发团队。",
        scaleMeta: "10,000 项目 · 1.2 亿依赖边 · 仅查 Hot 生产活跃快照",
        queryVector: "PURL: pkg:maven/org.apache.logging.log4j/log4j-core@[2.0-beta9, 2.15.0) & Env: PROD & Reachable: TRUE",
        payloadLines: [
          "// 1. 内存中对 3 个 RoaringBitmap 执行极速按位交集（耗时 < 2ms）",
          "hitProjects := roaring.And(roaring.And(idxPurlVer, idxProdEnv), idxReachable)",
          "// 2. 命中 312 个项目后，仅对命中集执行 PG 14+ WITH RECURSIVE ... CYCLE 还原最短依赖路径",
          "WITH RECURSIVE dep_path AS ( ... ) CYCLE child_id SET is_cycle USING path",
          "// 3. 按 Backstage catalog-info.yaml spec.owner (Group) 聚合派单: 312 应用 -> 18 个团队群组（零孤儿告警）"
        ],
        apply: { useCasTiering: true, useBitmapAndCycle: true, useGroupOwnership: true }
      },
      {
        id: "malware-sha-sweep",
        label: "2. 恶意包全网应急熔断 (PURL + SHA256 双模扫盘)",
        desc: "上游情报确认某 npm 包最新补丁版已被投毒（Lesson 0015 MAL-*），且攻击者可能改名混入私有镜像；要求在 5 秒内按 PURL 与二进制/Tarball SHA256 横扫全公司活跃仓与运行镜像。",
        scaleMeta: "8,500 代码仓 + 2,400 运行镜像 · 毫秒级摘要倒排命中",
        queryVector: "PURL: pkg:npm/postmark-mcp@1.0.16..1.0.18 OR ArtifactDigest: sha256:9f82...4c1e",
        payloadLines: [
          "// 1. 通过 CAS 规范化组件摘要字典直查（避免扫 90 天冷备份历史冗余）",
          "SELECT DISTINCT project_id, env_tier, artifact_digest FROM hot_component_bindings",
          "WHERE purl_id = ANY($1) OR sha256 = $2;",
          "// 2. 策略引擎通过 atomic.Pointer 热更新推送 CEL 阻断规则到 CI 与 K8s 1.30 VAP",
          "artifact.digest in params.blockedMalwareDigests || artifact.purl in params.blockedPurls"
        ],
        apply: { useCasTiering: true, useBitmapAndCycle: true, useGroupOwnership: true }
      },
      {
        id: "cyclic-graph-trap",
        label: "3. 深层循环依赖图谱 (npm/Maven 环路防爆栈)",
        desc: "在多模块 Monorepo 与历史遗留 Java/JS 项目中存在 A -> B -> C -> A 循环依赖边；传统递归查询或未设防的图遍历极易导致数据库 CPU 100% 死循环超时。",
        scaleMeta: "平均深度 14 层 · 存在 1,400+ 历史循环引用子图",
        queryVector: "WITH RECURSIVE ... CYCLE child_id SET is_cycle USING path WHERE NOT is_cycle",
        payloadLines: [
          "WITH RECURSIVE graph_traverse AS (",
          "  SELECT parent_id, child_id, 1 AS depth FROM cas_edges WHERE subgraph_hash = $1 AND child_id = $target",
          "  UNION ALL",
          "  SELECT e.parent_id, e.child_id, gt.depth + 1 FROM graph_traverse gt JOIN cas_edges e ON gt.parent_id = e.child_id WHERE gt.depth < 32",
          ") CYCLE parent_id SET is_cycle USING path",
          "SELECT DISTINCT path FROM graph_traverse WHERE NOT is_cycle;"
        ],
        apply: { useCasTiering: true, useBitmapAndCycle: true, useGroupOwnership: true }
      },
      {
        id: "ci-storm-cas",
        label: "4. 每日 3 万次 CI 推送风暴 (CAS 内容寻址图去重)",
        desc: "研发团队每天触发 30,000 次 PR/Main 构建，其中 96% 的构建并未修改 lockfile 依赖子图；若每次全量落库 SBOM JSON 与 4,000 条重复边，三个月内 PG 磁盘与索引将彻底崩盘。",
        scaleMeta: "日均 30,000 次 SBOM 接入 · 子图重复率 96.2%",
        queryVector: "dep_tree_hash = SHA256(canonical_sorted_nodes_and_edges)",
        payloadLines: [
          "// 入库前先算规范化依赖子图内容哈希（Content-Addressable Storage）",
          "if casStore.Exists(depTreeHash) {",
          "    // 仅写入 1 行几十字节的 snapshot_refs(project_id, commit_sha, dep_tree_hash, scanned_at)",
          "    return repo.LinkSnapshotRef(ctx, projectID, commitSHA, depTreeHash)",
          "}",
          "// 实测效果：1.2 亿逻辑边物理压缩至 ~450 万唯一 CAS 边，写入 IOPS 下降 95%+"
        ],
        apply: { useCasTiering: true, useBitmapAndCycle: true, useGroupOwnership: true }
      }
    ];

    const POLICY_EXAMPLES = [
      {
        label: "紧急 0-day 热路径阻断 (CEL + K8s 1.30 VAP)",
        engineMode: "cel-inproc",
        rolloutStage: "shadow-first",
        hotReload: "atomic-ptr",
        bypassReady: true
      },
      {
        label: "跨系统合规与 VEX 豁免矩阵 (OPA Rego Bundle)",
        engineMode: "hybrid-dual",
        rolloutStage: "shadow-first",
        hotReload: "atomic-ptr",
        bypassReady: true
      },
      {
        label: "反例：未灰度直接全网 Enforce 阻断救火热修",
        engineMode: "opa-webhook",
        rolloutStage: "direct-enforce",
        hotReload: "restart-pod",
        bypassReady: false
      }
    ];

    const state = {
      activeTab: "blast", // "blast" | "policy"
      presetId: "log4shell-blast",
      useCasTiering: true,
      useBitmapAndCycle: true,
      useGroupOwnership: true,
      // 模式二
      engineMode: "hybrid-dual", // "cel-inproc" | "opa-webhook" | "hybrid-dual"
      rolloutStage: "shadow-first", // "shadow-first" | "direct-enforce"
      hotReload: "atomic-ptr", // "atomic-ptr" | "restart-pod"
      bypassReady: true
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function evaluateBlast(preset) {
      const antiCard = {
        tone: "is-bad",
        verdict:
          preset.id === "ci-storm-cas"
            ? "存储雪崩 · 3 个月膨胀 50x 磁盘与 WAL 打满"
            : preset.id === "cyclic-graph-trap"
              ? "死循环超时 · 数据库连接池打满引发雪崩"
              : "响应瘫痪 · JSONB 全表扫耗时 12 分钟+ 且千条孤儿告警",
        meta: "全量存原始 SBOM JSON + 无位图索引 + 按个人邮箱告警",
        desc:
          preset.id === "ci-storm-cas"
            ? "每次 CI 都把完整 CycloneDX JSON 与数千条冗余边写进主库，历史归档未分离进 ClickHouse/S3，索引膨胀导致读写全线抖动。"
            : preset.id === "cyclic-graph-trap"
              ? "递归查询未启用 PG 14+ CYCLE 检测且未限制深度，遇到历史循环依赖直接陷入无限扩展直至 statement_timeout。"
              : "应急爆发时只能对千万行 JSONB 跑 LIKE/GIN 扫描，耗时数十分钟；且因离职员工或个人邮箱失效，80% 告警无人认领。"
      };

      let modernTone = "is-ok";
      let modernVerdict = "1.8 秒完成全网检索 + 精准群组派单";
      let modernMeta = "CAS 压缩 95% + RoaringBitmap 交集 + PG14 CYCLE + Group 路由";
      let modernDesc =
        "内存 RoaringBitmap 2 毫秒交集锁定受影响项目集，PG 14+ CYCLE 仅对命中集安全还原最短依赖路径，再经 Backstage Group 聚合成团队工单。";

      if (!state.useCasTiering && !state.useBitmapAndCycle) {
        modernTone = "is-bad";
        modernVerdict = "架构退化 · 退回全表扫与历史膨胀泥潭";
        modernMeta = "已关闭 CAS 分层与位图防环索引";
        modernDesc =
          "缺少 CAS 去重与 RoaringBitmap 内存索引，万级项目下 0-day 查询被迫退化为磁盘全表扫描，无法满足 10 秒 SLA。";
      } else if (!state.useBitmapAndCycle) {
        modernTone = "is-warn";
        modernVerdict = "磁盘可控 · 但 0-day 检索延迟飙升且存在环路风险";
        modernMeta = "缺 RoaringBitmap 交集与 PG 14+ CYCLE 保护";
        modernDesc =
          "CAS 保住了存储成本，但缺乏内存多维位图交集（PURL × 环境 × 可达性）和 CYCLE 防环子句，大并发应急依然可能拖慢主库。";
      } else if (!state.useCasTiering) {
        modernTone = "is-warn";
        modernVerdict = "查询够快 · 但每日 CI 重复推送撑爆内存与主库";
        modernMeta = "未启用 CAS 去重与冷热温三层分流";
        modernDesc =
          "全量保留 90 天以上高频重复构建图谱会导致内存位图和热表基数无序扩张，冷/温数据必须卸载至 ClickHouse 与 S3 Parquet。";
      } else if (!state.useGroupOwnership) {
        modernTone = "is-warn";
        modernVerdict = "检索 < 2s · 但爆发大量“无主孤儿告警”";
        modernMeta = "缺 Backstage spec.owner (Group) 映射";
        modernDesc =
          "虽然 2 秒算出了 312 个受影响应用，但未绑定 Group 级责任人与服务目录，一旦开发离职或跨组接管，0-day 通知直接石沉大海。";
      }

      return { antiCard, modernCard: { tone: modernTone, verdict: modernVerdict, meta: modernMeta, desc: modernDesc } };
    }

    function renderBlastTab() {
      const preset = getCurrentPreset();
      const res = evaluateBlast(preset);

      return `
        <div class="grl-preset-bar">
          ${PRESETS.map(
            (p) => `
              <button type="button" class="grl-pill ${state.presetId === p.id ? "active" : ""}" data-preset="${p.id}">
                ${escapeHtml(p.label)}
              </button>
            `
          ).join("")}
        </div>

        <p style="font-size:0.84rem;color:var(--ink-secondary);margin:0 0 0.85rem;padding:0.55rem 0.78rem;background:#faf8f2;border-left:3px solid var(--accent-blue);border-radius:0 4px 4px 0;">
          <strong>规模化痛点：</strong>${escapeHtml(preset.desc)}
        </p>

        <div class="grl-layout">
          <div class="grl-controls">
            <div class="grl-control-group">
              <span class="grl-control-label">1. 海量台账与 10 秒应急核心机制</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="cas" ${state.useCasTiering ? "checked" : ""} />
                <span>启用 <strong>CAS 子图去重</strong> + <strong>Hot(PG) / Warm(ClickHouse) / Cold(S3)</strong> 三层分流</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="bitmap" ${state.useBitmapAndCycle ? "checked" : ""} />
                <span>启用 <strong>RoaringBitmap 内存倒排交集</strong> + <strong>PG 14+ CYCLE</strong> 防环路径还原</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="owner" ${state.useGroupOwnership ? "checked" : ""} />
                <span>启用 <strong>Backstage <code>spec.owner</code> (Group)</strong> + CODEOWNERS 团队聚合派单</span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 目标台账规模与查询向量</span>
              <div style="font-size:0.77rem;line-height:1.58;color:var(--ink-secondary);">
                <div>&bull; <strong>资产规模：</strong><code>${escapeHtml(preset.scaleMeta)}</code></div>
                <div>&bull; <strong>检索向量：</strong><code>${escapeHtml(preset.queryVector)}</code></div>
                <div>&bull; <strong>存储合规：</strong>PG + Apache AGE + ClickHouse + RoaringBitmap（<strong>0 GPL / 0 BSL</strong>）</div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">
              <div class="grl-card ${res.antiCard.tone}">
                <div class="grl-card-kicker">反例 · 单表原始 JSONB + 无环路/归属防线</div>
                <div class="grl-card-title">${escapeHtml(res.antiCard.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.antiCard.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.antiCard.desc)}</p>
              </div>

              <div class="grl-card ${res.modernCard.tone}">
                <div class="grl-card-kicker">推荐 · CAS + RoaringBitmap + PG 14+ 应急引擎</div>
                <div class="grl-card-title">${escapeHtml(res.modernCard.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.modernCard.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.modernCard.desc)}</p>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">Go Bitmap 交集 · PG 14+ CYCLE · CAS 执行流水线切片</span>
                <span class="badge ${res.modernCard.tone === "is-ok" ? "badge-ok" : res.modernCard.tone === "is-warn" ? "badge-warn" : "badge-danger"}">
                  ${escapeHtml(res.modernCard.verdict)}
                </span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(preset.payloadLines.join("\n"))}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function evaluatePolicy() {
      let latency =
        state.engineMode === "cel-inproc"
          ? "< 0.5 ms (进程内 CEL / K8s 1.30 VAP)"
          : state.engineMode === "hybrid-dual"
            ? "< 1 ms 热路径 (CEL) · ~12 ms 合规编排 (OPA)"
            : "15–60 ms (外部 Webhook + JSON 序列化)";

      let termination =
        state.engineMode === "opa-webhook"
          ? "图灵完备 Rego（需防递归超时与 Webhook 故障）"
          : "非图灵完备 CEL（数学保证有界终止，零死循环）";

      let reloadStatus =
        state.hotReload === "atomic-ptr"
          ? "atomic.Pointer 秒级无锁热切换"
          : "需滚动重启 Pod（慢于 10 秒 SLA!）";

      let badgeCls = "badge-ok";
      let verdict = "READY · 兼顾微秒热路径、秒级热更与零误伤灰度";
      const actions = [];

      if (state.engineMode === "cel-inproc") {
        actions.push("热路径采用 google/cel-go（Apache-2.0），非图灵完备保证有界终止，且可直接下沉至 Kubernetes 1.30+ 原生 ValidatingAdmissionPolicy 消除 Webhook 网络跳数。");
      } else if (state.engineMode === "hybrid-dual") {
        actions.push("采用「CEL 热路径（0-day 阻断 / K8s 1.30 VAP）+ OPA 治理面（跨仓合规矩阵 / 复杂豁免关联）」双引擎分工，各取所长且全栈 Apache-2.0。");
      } else {
        badgeCls = "badge-warn";
        verdict = "WARN · 全流量走外部 OPA Webhook 存在延迟与可用性放大风险";
        actions.push("高并发准入和紧急 0-day 热路径不建议全量走外部 OPA Webhook，应将高频单对象校验下沉至进程内 CEL / K8s ValidatingAdmissionPolicy。");
      }

      if (state.rolloutStage === "direct-enforce") {
        badgeCls = "badge-danger";
        verdict = "BLOCK · 未经 Shadow Dry-Run 直接全网 Enforce 极易引发业务停摆!";
        actions.push("红线警示：紧急 0-day 规则必须先跑 Shadow / Dry-Run 统计爆炸半径并核验可达性（Lesson 0011），再分批切 Enforce；否则一条误判规则会直接掐断全公司发布通道。");
      } else {
        actions.push("已开启 Shadow Dry-Run 先行预演：1 秒内基于 RoaringBitmap 预览受影响 CI 与生产 Pod 数量，确认无大面积误杀后再一键升格 Enforce。");
      }

      if (state.hotReload === "restart-pod") {
        if (badgeCls === "badge-ok") {
          badgeCls = "badge-warn";
          verdict = "WARN · 策略变更依赖重启服务，无法满足 0-day 实时热更新";
        }
        actions.push("请使用 Go atomic.Pointer 原子切换已编译的 cel.Program 或 OPA PreparedEvalQuery 快照，彻底消除配置下发时的锁竞争与容器重启等待。");
      } else {
        actions.push("策略编译器后台完成校验与预编译后，通过 atomic.Pointer 原子指针交换实现亚秒级全节点零抖动热生效。");
      }

      if (!state.bypassReady) {
        if (badgeCls !== "badge-danger") {
          badgeCls = "badge-warn";
          verdict = "WARN · 缺少紧急热修与 VEX 旁路机制，可能锁死 0-day 救火发版";
        }
        actions.push("必须为 0-day 门禁保留带审计与双人授权的 Break-glass 紧急旁路及 VEX not_affected 自动豁免，避免门禁本身阻断修复补丁上线。");
      } else {
        actions.push("已集成 VEX（Lesson 0013）自动放行不可达组件 + 带完整审计留痕的 Break-glass 紧急热修旁路，保证救火发版畅通。");
      }

      return { latency, termination, reloadStatus, badgeCls, verdict, actions };
    }

    function renderPolicyOutput() {
      const r = evaluatePolicy();
      return `
        <div class="grl-impact-panel" style="margin-bottom:0.85rem;">
          <div class="grl-impact-head">
            <span>策略引擎热更新与 0-day 门禁灰度裁决</span>
            <span class="badge ${r.badgeCls}">${escapeHtml(r.verdict)}</span>
          </div>
          <div class="grl-impact-list">
            <div class="grl-impact-item ${r.badgeCls === "badge-ok" ? "is-clear" : "is-hit"}">
              <strong>求值延迟基线：</strong>${escapeHtml(r.latency)}
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">门禁热路径延迟</div>
            <div class="grl-kpi-val">${escapeHtml(r.latency)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">计算安全边界</div>
            <div class="grl-kpi-val">${escapeHtml(r.termination)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">规则热更新方式</div>
            <div class="grl-kpi-val" style="color:${state.hotReload === "atomic-ptr" ? "var(--ok)" : "var(--warn)"};">${escapeHtml(r.reloadStatus)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">商业开源许可</div>
            <div class="grl-kpi-val" style="color:var(--ok);">CEL &amp; OPA 均 Apache-2.0</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">策略网关架构建议：</div>
          <ul style="margin:0;padding-left:1.1rem;font-size:0.8rem;line-height:1.58;color:var(--ink-secondary);">
            ${r.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    function renderPolicyTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div class="grl-preset-bar" style="margin-bottom:0.45rem;">
            ${POLICY_EXAMPLES.map(
              (ex, idx) => `
                <button type="button" class="grl-pill" data-policyex="${idx}">
                  载入方案：${escapeHtml(ex.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">策略执行引擎选型</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.engineMode === "cel-inproc" ? "active" : ""}" data-emode="cel-inproc">CEL 进程内 (K8s VAP)</button>
                <button type="button" class="grl-pill ${state.engineMode === "hybrid-dual" ? "active" : ""}" data-emode="hybrid-dual">CEL 热路径 + OPA 治理</button>
                <button type="button" class="grl-pill ${state.engineMode === "opa-webhook" ? "active" : ""}" data-emode="opa-webhook">全量 OPA Webhook</button>
              </div>

              <span class="grl-control-label" style="margin-top:0.65rem;display:block;">0-day 规则发布阶段</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.rolloutStage === "shadow-first" ? "active" : ""}" data-rstage="shadow-first">Shadow Dry-Run 先预览</button>
                <button type="button" class="grl-pill ${state.rolloutStage === "direct-enforce" ? "active" : ""}" data-rstage="direct-enforce">直接全网 Enforce 阻断</button>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.42rem;">
              <span class="grl-control-label">热加载与救火逃生机制</span>
              <div class="grl-pill-group" style="margin-bottom:0.2rem;">
                <button type="button" class="grl-pill ${state.hotReload === "atomic-ptr" ? "active" : ""}" data-reload="atomic-ptr">atomic.Pointer 热切换</button>
                <button type="button" class="grl-pill ${state.hotReload === "restart-pod" ? "active" : ""}" data-reload="restart-pod">滚动重启生效</button>
              </div>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="bypass" ${state.bypassReady ? "checked" : ""} />
                <span>保留 <strong>VEX 豁免联动 + 带审计 Break-glass 紧急热修旁路</strong></span>
              </label>
            </div>
          </div>
        </div>

        <div class="grl-esl-policy-out">${renderPolicyOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：海量资产 0-day 秒级检索与策略热更新模拟器";
      const intro =
        config.intro ||
        "在模式一中切入 4 大规模化瓶颈验证 CAS、RoaringBitmap 与 PG 14+ CYCLE 的提速效果；在模式二中比较 CEL 与 OPA 的延迟边界及灰度保护。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0021 · Enterprise Scale Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "blast" ? "active" : ""}" data-tab="blast">
            <span class="grl-tab-num">1</span>
            模式一：万级项目 CAS 去重、RoaringBitmap 与 PG 14+ CYCLE 检索
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "policy" ? "active" : ""}" data-tab="policy">
            <span class="grl-tab-num">2</span>
            模式二：CEL vs OPA 策略引擎、热更新与 Shadow Dry-Run 灰度
          </button>
        </div>

        ${state.activeTab === "blast" ? renderBlastTab() : renderPolicyTab()}
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

      container.querySelectorAll("[data-preset]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = PRESETS.find((p) => p.id === btn.dataset.preset);
          if (!found) return;
          state.presetId = found.id;
          Object.assign(state, found.apply);
          render();
        });
      });

      container.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          const t = cb.dataset.toggle;
          if (t === "cas") state.useCasTiering = cb.checked;
          if (t === "bitmap") state.useBitmapAndCycle = cb.checked;
          if (t === "owner") state.useGroupOwnership = cb.checked;
          if (t === "bypass") state.bypassReady = cb.checked;
          render();
        });
      });

      container.querySelectorAll("[data-policyex]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ex = POLICY_EXAMPLES[Number(btn.dataset.policyex)];
          if (!ex) return;
          state.engineMode = ex.engineMode;
          state.rolloutStage = ex.rolloutStage;
          state.hotReload = ex.hotReload;
          state.bypassReady = ex.bypassReady;
          render();
        });
      });

      container.querySelectorAll("[data-emode]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.engineMode = btn.dataset.emode;
          render();
        });
      });

      container.querySelectorAll("[data-rstage]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.rolloutStage = btn.dataset.rstage;
          render();
        });
      });

      container.querySelectorAll("[data-reload]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.hotReload = btn.dataset.reload;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="enterprise-scale-0day-lab"]')
      .forEach(initEnterpriseScale0DayLab);
  });
})();
