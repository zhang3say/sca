/* ==========================================================================
   Reusable Interactive Component: Offline Vuln DB & High-Concurrency Index Lab
   Zero-dependency vanilla JS for Lesson 0009+.
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

  const DB_ARCH_BASELINES = [
    {
      id: "trivy-bbolt",
      name: "Trivy DB (OCI + bbolt)",
      storage: "go.etcd.io/bbolt (单文件 B+Tree mmap)",
      transport: "OCI Artifact (db.tar.gz, ~90–125 MB) + Cosign",
      uncompressed: "~300–500+ MB",
      deltaSupport: "无原生逻辑增量（全层重拉 ~100 MB/6h）",
      airgapNote: "内网可直接复用 Harbor/ECR OCI 仓库；离线 Cosign 需先 cosign initialize 导出 ~/.sigstore TUF 根缓存。",
      licenseVerdict: "工具 Apache-2.0；但禁止直接搬运官方 ghcr.io/aquasecurity/trivy-db 作为商业 SaaS 数据底座（混有 CC-BY-SA 数据源及 CDN 限流）。",
      badgeClass: "badge-warn",
      badgeText: "CLI 优秀 · 商用须自建",
    },
    {
      id: "grype-v6",
      name: "Grype DB v6 (SQLite Handle + Blob)",
      storage: "SQLite3（Handle 搜索索引表 + 去重 JSON Blobs）",
      transport: "latest.json + .tar.zst (~65 MB, 较 v5 缩减 ~70%)",
      uncompressed: "~1.6 GB（含 KEV / EPSS / withdrawn）",
      deltaSupport: "v6 为完整 zstd 快照；需经 grype db import 重建本地索引",
      airgapNote: "若内网仅镜像 HTTP 文件，须随 latest.json 校验 sha256 并运行 import 生成 import.json，不可裸解压覆盖。",
      licenseVerdict: "Vunnel + Grype-DB 工具链 Apache-2.0；自建洁净数据流可严格遵循 Handle+Blob 模式并叠加 License Gate。",
      badgeClass: "badge-ok",
      badgeText: "嵌入式存储范式标杆",
    },
    {
      id: "dual-plane",
      name: "自研商业双模底座 (Edge SQLite + Cloud Snapshot)",
      storage: "Edge: 只读 SQLite Handle+Blob ｜ Cloud: 内存不可变快照",
      transport: "OCI Artifact (Base .tar.zst + Ed25519 签名逻辑增量链)",
      uncompressed: "Edge 约 250–600 MB（按洁净源裁剪）｜ Cloud 内存索引 ~180 MB",
      deltaSupport: "日均逻辑增量 ~350 KB（压缩 >99% 带宽），断链自动回退全量",
      airgapNote: "Base 快照 + 哈希链式逻辑增量包全部封装为 OCI Artifact 推入客户内网 Harbor，离线 Ed25519/TUF 硬验签后原子切换。",
      licenseVerdict: "100% Apache-2.0/MIT 代码 + Lesson 0007 License Gate 洁净源（CC0/CC-BY + 商业授权源）。",
      badgeClass: "badge-ok",
      badgeText: "推荐商业总架构方案",
    },
  ];

  const AIRGAP_SCENARIOS = [
    {
      id: "valid-chain",
      label: "1. 正常签名逻辑增量链 (v100 → v101 → v102)",
      localVersion: "v100 (sha256: 9a4f...c100)",
      incomingMeta: "delta_v100_v101.pb.zst (340 KB) + delta_v101_v102.pb.zst (290 KB)",
      payloadSummary: "含 42 条新增/修订规则 + 3 条 withdrawn 墓碑；总传输仅 630 KB（全量快照 65 MB 的 0.97%）",
      outcome: "ok",
      verdictTitle: "原子提交成功：本地库无停机平滑升至 v102",
      steps: [
        {
          cls: "ok",
          title: "Step 1 · 离线验签（Offline Ed25519 / Cached TUF Root）",
          detail: "使用本地预置企业公钥 & 离线 Sigstore TUF Root 校验 OCI Manifest 与 delta 包签名：签名合法，发布者身份匹配。",
        },
        {
          cls: "ok",
          title: "Step 2 · 哈希链连续性校验（prev_state_sha256 == local_state_sha256）",
          detail: "delta_v101 声明前置逻辑状态哈希 9a4f...c100 与本地一致，且序列号 100→101→102 严格连续。",
        },
        {
          cls: "ok",
          title: "Step 3 · Staging 库事务重放（BEGIN IMMEDIATE）",
          detail: "在临时 staging.db 上按序执行 upserts 与 tombstones（逻辑置 is_enabled=false），不阻塞线上正在扫描的只读句柄。",
        },
        {
          cls: "ok",
          title: "Step 4 · 目标摘要核验与原子切换（Atomic Rename / atomic.Pointer）",
          detail: "重算规范化规则逻辑摘要精确等于 target_state_sha256（e81d...f102），原子替换版本指针；旧连接耗尽后回收。",
        },
      ],
    },
    {
      id: "broken-chain",
      label: "2. 断链缺块 (本地 v100，直接收到 v101→v102)",
      localVersion: "v100 (sha256: 9a4f...c100)",
      incomingMeta: "delta_v101_v102.pb.zst (290 KB) — 缺失 v100→v101",
      payloadSummary: "运维摆渡 U 盘时漏拷了昨天的 delta_v100_v101 包",
      outcome: "warn",
      verdictTitle: "安全拒绝增量重放：自动触发全量 Base 快照兜底恢复",
      steps: [
        {
          cls: "ok",
          title: "Step 1 · 离线验签通过",
          detail: "delta_v101_v102 签名本身真实有效，确实由官方情报源签发。",
        },
        {
          cls: "bad",
          title: "Step 2 · 哈希链连续性校验失败（Chain Break！）",
          detail: "delta 声明 prev_state_sha256 = 7b2c...d101，但本地库当前逻辑摘要为 9a4f...c100！强行写入会丢失 v101 的新增 CVE 与撤回记录，造成静默漏报。",
        },
        {
          cls: "warn",
          title: "Step 3 · 熔断增量应用，保留 v100 继续提供服务",
          detail: "拒绝污染现有本地库，向上层控制面抛出 DELTA_CHAIN_GAP(expected=v101, actual=v100) 告警。",
        },
        {
          cls: "ok",
          title: "Step 4 · 自愈兜底：拉取最近签名全量快照 base_v102.db.zst",
          detail: "自动从内网 Harbor 拉取最新 Base Snapshot（65 MB）或提示摆渡最新全量 OCI Tag，验签后一次重建恢复连续链。",
        },
      ],
    },
    {
      id: "tampered-payload",
      label: "3. 载荷篡改 / 伪造删除高危 CVE",
      localVersion: "v100 (sha256: 9a4f...c100)",
      incomingMeta: "delta_v100_v101_modified.pb.zst",
      payloadSummary: "内网传输路径中某条高危漏洞（如 Log4j/OpenSSH）被恶意删改以逃避门禁",
      outcome: "bad",
      verdictTitle: "密码学硬阻断：零容忍丢弃篡改包并触发安全审计告警",
      steps: [
        {
          cls: "bad",
          title: "Step 1 · 离线签名与 Manifest Digest 校验失败",
          detail: "载荷字节改动导致 SHA-256 摘要不匹配，Ed25519/Cosign 验签直接报错 ERR_INVALID_SIGNATURE。",
        },
        {
          cls: "bad",
          title: "Step 2 · 绝不解包、绝不进 Staging 事务",
          detail: "未通过签名校验的压缩包甚至不允许进入 zstd 解压流程，同步防范压缩炸弹（Zip/Zstd Bomb）DoS。",
        },
        {
          cls: "ok",
          title: "Step 3 · 线上服务保持 v100 完整可用",
          detail: "原本地数据库与内存快照丝毫不受影响，同步向 SIEM/审计日志推送高危完整性告警。",
        },
      ],
    },
    {
      id: "withdrawn-tombstone",
      label: "4. withdrawn 撤回墓碑同步（防假 CVE 复活）",
      localVersion: "v101 (含 CVE-2025-99999 有效规则)",
      incomingMeta: "delta_v101_v102.pb.zst (含 1 条 withdrawn 墓碑)",
      payloadSummary: "上游 OSV 对 CVE-2025-99999 标记 withdrawn（误报/重复撤回），但内网 NVD 镜像仍残留旧记录",
      outcome: "ok",
      verdictTitle: "墓碑持久化：关闭匹配规则同时封死滞后源复活通道",
      steps: [
        {
          cls: "ok",
          title: "Step 1 · 逻辑墓碑写入（is_enabled=false, withdrawn_at=RFC3339）",
          detail: "delta 中的 tombstones[] 不执行物理 DELETE FROM rules，而是将规则标记为逻辑撤销态。",
        },
        {
          cls: "ok",
          title: "Step 2 · 阻断旧版本/旧源反向污染",
          detail: "即使后续内网某滞后镜像重新推送同一 CVE ID 的旧版 JSON，因 withdrawn_at 权威更高，引擎拒绝重新激活。",
        },
        {
          cls: "ok",
          title: "Step 3 · 触发存量工单消警（呼应 Lesson 0006/0007）",
          detail: "同步推送 intel.advisory.withdrawn 事件，自动将受影响的存量告警状态收敛为 RESOLVED_WITHDRAWN。",
        },
      ],
    },
  ];

  function initVulnIndexLab(container) {
    let config = {};
    const dataEl = container.querySelector("script.vuln-index-lab-data");
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const state = {
      activeTab: "airgap",
      baselineId: "dual-plane",
      scenarioId: "valid-chain",
      sbomComponents: 5000,
      vulnRatioPct: 10,
      hotPkgCount: 2,
      fleetProjects: 50000,
    };

    function computeProfile() {
      const N = state.sbomComponents;
      const hitRate = state.vulnRatioPct / 100;
      const hitPkgs = Math.max(1, Math.round(N * hitRate));
      const cleanPkgs = N - hitPkgs;
      const hotExtraRules = state.hotPkgCount * 420; // e.g. openssl / kernel / ffmpeg with hundreds of CVEs

      // 1. Naive SQLite per-component query (no batching, regex parse per rule)
      // ~0.08ms SQLite index probe + JSON decode + runtime version string parse
      const sqliteSingleMs = N * 0.095 + hitPkgs * 0.35 + hotExtraRules * 0.018;

      // 2. bbolt mmap B+Tree bucket lookup + JSON unmarshal per hit
      // ~0.012ms mmap miss, ~0.14ms JSON unmarshal on hit
      const bboltMs = cleanPkgs * 0.012 + hitPkgs * 0.14 + hotExtraRules * 0.012;

      // 3. In-memory immutable snapshot (atomic.Pointer) + pre-parsed intervals
      // ~0.00004ms (40ns) hash miss, ~0.0025ms pre-parsed interval eval on hit
      const memMs = cleanPkgs * 0.00004 + hitPkgs * 0.0028 + hotExtraRules * 0.0006;

      // 4. 0-day Continuous Re-evaluation across fleet
      // Full rescan vs Reverse Index (RoaringBitmap hits ~0.3% of fleet)
      const affectedProjects = Math.max(1, Math.round(state.fleetProjects * 0.003));
      const fullRescanSec = (state.fleetProjects * 1200 * 0.00004) / 1000 + state.fleetProjects * 0.0008; // DB read + match
      const reverseIndexMs = 0.4 + affectedProjects * 0.015; // bitmap lookup + pre-parsed version check

      return {
        N,
        hitPkgs,
        cleanPkgs,
        sqliteSingleMs,
        bboltMs,
        memMs,
        affectedProjects,
        fullRescanSec,
        reverseIndexMs,
      };
    }

    function renderAirgapTab() {
      const baseline = DB_ARCH_BASELINES.find((b) => b.id === state.baselineId) || DB_ARCH_BASELINES[2];
      const scenario = AIRGAP_SCENARIOS.find((s) => s.id === state.scenarioId) || AIRGAP_SCENARIOS[0];

      return `
        <div class="idx-grid-2">
          <div>
            <div class="oci-lab-col-head">A. 三大离线库工程路线对标（点击切换）</div>
            <div class="preset-bar" style="margin-bottom:0.75rem;">
              ${DB_ARCH_BASELINES.map(
                (b) => `<button type="button" class="preset-btn ${b.id === state.baselineId ? "active" : ""}" data-action="pick-baseline" data-id="${escapeHtml(b.id)}">${escapeHtml(b.name)}</button>`
              ).join("")}
            </div>
            <div class="idx-card">
              <div class="idx-card-head">
                <span>${escapeHtml(baseline.name)}</span>
                <span class="badge ${escapeHtml(baseline.badgeClass)}">${escapeHtml(baseline.badgeText)}</span>
              </div>
              <div class="idx-metric-row"><span>存储内核</span><span class="idx-metric-val">${escapeHtml(baseline.storage)}</span></div>
              <div class="idx-metric-row"><span>分发协议与体积</span><span class="idx-metric-val">${escapeHtml(baseline.transport)}</span></div>
              <div class="idx-metric-row"><span>解压后本地占地</span><span class="idx-metric-val">${escapeHtml(baseline.uncompressed)}</span></div>
              <div class="idx-metric-row"><span>增量更新能力</span><span class="idx-metric-val">${escapeHtml(baseline.deltaSupport)}</span></div>
              <p style="margin:0.6rem 0 0.35rem;font-size:0.81rem;color:var(--ink-secondary);line-height:1.5;">
                <strong>断网部署细节：</strong>${escapeHtml(baseline.airgapNote)}
              </p>
              <p style="margin:0;font-size:0.81rem;color:var(--ink-secondary);line-height:1.5;">
                <strong>商业合规红线：</strong>${escapeHtml(baseline.licenseVerdict)}
              </p>
            </div>
          </div>

          <div>
            <div class="oci-lab-col-head">B. 断网增量链验签与原子切换模拟</div>
            <div class="preset-bar" style="margin-bottom:0.75rem;">
              ${AIRGAP_SCENARIOS.map(
                (s) => `<button type="button" class="preset-btn ${s.id === state.scenarioId ? "active" : ""}" data-action="pick-scenario" data-id="${escapeHtml(s.id)}">${escapeHtml(s.label)}</button>`
              ).join("")}
            </div>
            <div class="idx-card">
              <div class="idx-card-head">
                <span>输入状态：${escapeHtml(scenario.localVersion)}</span>
                <span class="badge ${scenario.outcome === "ok" ? "badge-ok" : scenario.outcome === "warn" ? "badge-warn" : "badge-danger"}">
                  ${scenario.outcome === "ok" ? "安全升版" : scenario.outcome === "warn" ? "熔断自愈" : "验签阻断"}
                </span>
              </div>
              <div style="font-family:var(--font-mono);font-size:0.74rem;color:var(--ink-muted);margin-bottom:0.35rem;">
                收到摆渡包：${escapeHtml(scenario.incomingMeta)}
              </div>
              <div style="font-size:0.81rem;color:var(--ink-secondary);margin-bottom:0.45rem;">
                ${escapeHtml(scenario.payloadSummary)}
              </div>
              <div style="font-size:0.84rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">
                最终裁决：${escapeHtml(scenario.verdictTitle)}
              </div>
              <ul class="idx-step-list">
                ${scenario.steps
                  .map(
                    (st) => `
                  <li class="idx-step-item ${escapeHtml(st.cls)}">
                    <strong>${escapeHtml(st.title)}：</strong>${escapeHtml(st.detail)}
                  </li>`
                  )
                  .join("")}
              </ul>
            </div>
          </div>
        </div>
      `;
    }

    function renderProfilerTab() {
      const p = computeProfile();
      const maxBar = Math.max(p.sqliteSingleMs, 1);
      const pct = (ms) => Math.max(2, Math.min(100, Math.round((ms / maxBar) * 100)));

      return `
        <div class="idx-grid-4">
          <div class="ver-field">
            <label for="idx-sbom-size">单次 SBOM 组件数</label>
            <select id="idx-sbom-size" class="ver-select" data-field="sbomComponents">
              <option value="500" ${state.sbomComponents === 500 ? "selected" : ""}>500 组件 (微服务)</option>
              <option value="5000" ${state.sbomComponents === 5000 ? "selected" : ""}>5,000 组件 (大型容器)</option>
              <option value="20000" ${state.sbomComponents === 20000 ? "selected" : ""}>20,000 组件 (Monorepo)</option>
            </select>
          </div>
          <div class="ver-field">
            <label for="idx-vuln-ratio">有历史漏洞包占比</label>
            <select id="idx-vuln-ratio" class="ver-select" data-field="vulnRatioPct">
              <option value="5" ${state.vulnRatioPct === 5 ? "selected" : ""}>5% (95% 洁净组件)</option>
              <option value="10" ${state.vulnRatioPct === 10 ? "selected" : ""}>10% (典型企业基线)</option>
              <option value="30" ${state.vulnRatioPct === 30 ? "selected" : ""}>30% (老旧遗产镜像)</option>
            </select>
          </div>
          <div class="ver-field">
            <label for="idx-hot-pkgs">高密度热点包 (openssl/kernel)</label>
            <select id="idx-hot-pkgs" class="ver-select" data-field="hotPkgCount">
              <option value="0" ${state.hotPkgCount === 0 ? "selected" : ""}>0 个热点包</option>
              <option value="2" ${state.hotPkgCount === 2 ? "selected" : ""}>2 个 (~840 条区间)</option>
              <option value="6" ${state.hotPkgCount === 6 ? "selected" : ""}>6 个 (~2,520 条区间)</option>
            </select>
          </div>
          <div class="ver-field">
            <label for="idx-fleet-size">平台存量资产规模 (0-day 重算)</label>
            <select id="idx-fleet-size" class="ver-select" data-field="fleetProjects">
              <option value="10000" ${state.fleetProjects === 10000 ? "selected" : ""}>10,000 资产版本</option>
              <option value="50000" ${state.fleetProjects === 50000 ? "selected" : ""}>50,000 资产版本</option>
              <option value="200000" ${state.fleetProjects === 200000 ? "selected" : ""}>200,000 资产版本</option>
            </select>
          </div>
        </div>

        <div class="idx-grid-3">
          <div class="idx-card">
            <div class="idx-card-head">
              <span>方案 1 · 逐组件查 SQLite + 现场解析版本</span>
              <span class="badge badge-danger">${p.sqliteSingleMs.toFixed(1)} ms</span>
            </div>
            <div class="idx-bar-track"><div class="idx-bar-fill is-slow" style="width:${pct(p.sqliteSingleMs)}%"></div></div>
            <p style="font-size:0.8rem;color:var(--ink-secondary);margin:0.6rem 0 0;line-height:1.5;">
              执行 <strong>${p.N.toLocaleString()} 次 SQLite 事务探测</strong>，即使 90%+ 组件零漏洞也要穿行 B-Tree + 运行时反复解析版本号字符串，高并发 Worker 极易触发连接池与 CPU 抖动。
            </p>
          </div>

          <div class="idx-card">
            <div class="idx-card-head">
              <span>方案 2 · bbolt mmap 桶读取（Edge 优秀）</span>
              <span class="badge badge-warn">${p.bboltMs.toFixed(1)} ms</span>
            </div>
            <div class="idx-bar-track"><div class="idx-bar-fill is-mid" style="width:${pct(p.bboltMs)}%"></div></div>
            <p style="font-size:0.8rem;color:var(--ink-secondary);margin:0.6rem 0 0;line-height:1.5;">
              利用只读 mmap 页快速跳过 <strong>${p.cleanPkgs.toLocaleString()}</strong> 个洁净包；命中 <strong>${p.hitPkgs.toLocaleString()}</strong> 个候选包后仍需 JSON 反序列化，适合单机 CLI / MCP 工具链冷启动。
            </p>
          </div>

          <div class="idx-card">
            <div class="idx-card-head">
              <span>方案 3 · atomic.Pointer 内存索引 + 预解析</span>
              <span class="badge badge-ok">${p.memMs.toFixed(2)} ms</span>
            </div>
            <div class="idx-bar-track"><div class="idx-bar-fill is-fast" style="width:${pct(p.memMs)}%"></div></div>
            <p style="font-size:0.8rem;color:var(--ink-secondary);margin:0.6rem 0 0;line-height:1.5;">
              洁净包 <strong>~40 ns</strong> SwissTable 哈希空返；热点包区间已在构建期预编译为原生数字结构，匹配零锁无 GC 抖动，比逐次查 SQLite 快 <strong>${Math.round(p.sqliteSingleMs / Math.max(0.05, p.memMs))}x</strong>！
            </p>
          </div>
        </div>

        <div class="idx-card" style="margin-top:0.9rem;">
          <div class="idx-card-head">
            <span>突发 0-day（如新增 1 条 CVE）全平台应急重算对比（${state.fleetProjects.toLocaleString()} 存量资产）</span>
            <span class="badge badge-ok">倒排裁剪：仅命中 ${p.affectedProjects.toLocaleString()} 个资产</span>
          </div>
          <div class="idx-grid-2">
            <div class="idx-step-item bad" style="margin:0;">
              <strong>无倒排索引 · 全库重扫所有资产：</strong>需从数据库拖出全部 ${state.fleetProjects.toLocaleString()} 份 SBOM 重跑匹配，预估耗时 <strong>${p.fullRescanSec.toFixed(1)} 秒</strong>（单核 CPU），易打爆 PostgreSQL IO。
            </div>
            <div class="idx-step-item ok" style="margin:0;">
              <strong>PURL 资产倒排索引 + RoaringBitmap：</strong>通过 <code>PkgKey → Bitmap</code> 直接筛出持有该包的 <strong>${p.affectedProjects.toLocaleString()}</strong> 个版本，纯内存区间求值仅需 <strong>${p.reverseIndexMs.toFixed(1)} ms</strong>！
            </div>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：离线分发安全链与万级组件匹配性能沙盘";
      const intro =
        config.intro ||
        "在两个工作台间切换：先验证内网断网环境的签名增量链与自愈逻辑，再调节 SBOM 与存量资产规模测算索引吞吐量差异。";

      const html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">${state.activeTab === "airgap" ? "模式一：离线分发与验签增量链" : "模式二：高并发匹配与倒排索引剖析"}</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>
        <div class="idx-tab-bar">
          <button type="button" class="idx-tab-btn ${state.activeTab === "airgap" ? "active" : ""}" data-tab="airgap">1. 离线包对比与断网增量链验证</button>
          <button type="button" class="idx-tab-btn ${state.activeTab === "profiler" ? "active" : ""}" data-tab="profiler">2. 万级组件毫秒级匹配 &amp; 0-day 重算压测</button>
        </div>
        ${state.activeTab === "airgap" ? renderAirgapTab() : renderProfilerTab()}
      `;

      container.innerHTML = html;

      container.querySelectorAll("[data-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTab = btn.dataset.tab;
          render();
        });
      });

      container.querySelectorAll('[data-action="pick-baseline"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.baselineId = btn.dataset.id;
          render();
        });
      });

      container.querySelectorAll('[data-action="pick-scenario"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.scenarioId = btn.dataset.id;
          render();
        });
      });

      container.querySelectorAll("[data-field]").forEach((sel) => {
        sel.addEventListener("change", () => {
          const field = sel.dataset.field;
          state[field] = Number(sel.value);
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="vuln-index-lab"]').forEach(initVulnIndexLab);
  });
})();
