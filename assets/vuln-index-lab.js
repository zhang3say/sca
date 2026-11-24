/* ==========================================================================
   Reusable Visual-First Interactive Lab:
   Offline Vuln DB Security Chain, Log-Scale Latency Breakdown & Arch Matrix
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

  /* ------------------------------------------------------------------------
     1. Verified Reference Baselines & Bandwidth Comparison Data
     ------------------------------------------------------------------------ */
  const DB_ARCH_BASELINES = [
    {
      id: "trivy-bbolt",
      name: "Trivy DB (OCI + bbolt)",
      recommended: false,
      badgeClass: "badge-warn",
      badgeText: "CLI 优秀 · 商用须自建",
      dailySyncMb: 140,
      dailySyncLabel: "~140 MB / 次（无逻辑增量，每 6h 整层重拉）",
      storage: "go.etcd.io/bbolt（单文件 B+Tree mmap）",
      transport: "OCI Artifact（db.tar.gz ~100–145 MB；默认 NextUpdate 24h，官方未默认附 Cosign 签名）",
      uncompressed: "数百 MB（构建期 advisory-detail 临时桶清理后落盘）",
      deltaSupport: "无原生逻辑增量（全层重拉 ~140 MB）",
      airgapNote: "内网可直接复用 Harbor/ECR OCI 仓库；若自建商业库叠加离线 Cosign 验签，须先 cosign initialize 导出 ~/.sigstore TUF 根缓存并配合离线 Bundle。",
      licenseVerdict: "工具 Apache-2.0；但禁止直接搬运官方 ghcr.io/aquasecurity/trivy-db 作为商业 SaaS 数据底座（内置 Wolfi/Chainguard CC-BY-NC-ND 与 CC-BY-SA 源及公共仓库限流）。",
    },
    {
      id: "grype-v6",
      name: "Grype DB v6 (SQLite Handle+Blob)",
      recommended: false,
      badgeClass: "badge-blue",
      badgeText: "嵌入式存储范式标杆",
      dailySyncMb: 65,
      dailySyncMaxMb: 200,
      dailySyncLabel: "v6.0 首发 ~65 MB → v6.1+ 含富化 ~200 MB（整包 .tar.zst）",
      storage: "SQLite3（Handle 搜索索引表 + 去重 JSON Blobs）",
      transport: "v6/latest.json（path + checksum）+ .tar.zst（较 v5 的 ~210 MB 首发降 ~69%）",
      uncompressed: "v6.0 首发 ~900 MB（较 v5 的 1.6 GB 降 ~44%）；v6.1+ 含 KEV / EPSS / SSVC 后持续增长",
      deltaSupport: "完整 zstd 快照分发；导入须走 grype db import 生成 import.json 与本地索引",
      airgapNote: "若内网仅镜像 HTTP 文件，须随 latest.json 校验 sha256 并运行 grype db import，不可裸解压覆盖。",
      licenseVerdict: "Vunnel + Grype-DB 工具链 Apache-2.0；自建洁净数据流可严格遵循 Handle+Blob 模式并叠加 License Gate。",
    },
    {
      id: "dual-plane",
      name: "自研商业双模底座 (Edge + Cloud)",
      recommended: true,
      badgeClass: "badge-ok",
      badgeText: "推荐商业总架构方案",
      dailySyncMb: 0.35,
      dailySyncLabel: "~0.35 MB（350 KB/天，逻辑增量压缩 >99% 带宽）",
      storage: "Edge: 只读 SQLite Handle+Blob ｜ Cloud: atomic.Pointer 内存快照",
      transport: "OCI Artifact（Weekly Base .tar.zst + Daily Ed25519 签名逻辑增量链）",
      uncompressed: "Edge 约 250–600 MB（洁净源裁剪）｜ Cloud 内存索引 ~180 MB",
      deltaSupport: "日均逻辑增量 ~200–500 KB（防 B+Tree 页分裂膨胀），断链自动熔断回退 Base",
      airgapNote: "Base 快照 + 哈希链逻辑增量全部封装为 OCI Artifact 推入客户内网 Harbor，离线 Ed25519/TUF 硬验签后原子切换。",
      licenseVerdict: "100% Apache-2.0/MIT 代码 + Lesson 0007 License Gate 洁净源（CC0/CC-BY + 商业授权源）。",
    },
  ];

  const BANDWIDTH_BARS = [
    {
      id: "logic-delta",
      name: "自研签名逻辑增量（Daily Signed Delta）",
      mb: 0.35,
      sizeLabel: "0.35 MB (350 KB/天)",
      cls: "is-fast",
      note: "仅传变更 upserts[] + withdrawn tombstones[]，彻底规避 B+Tree 页分裂",
    },
    {
      id: "bsdiff-antipattern",
      name: "反模式：SQLite 文件跑 bsdiff 二进制补丁",
      mb: 45,
      sizeLabel: "~45 MB / 天（膨胀 >120×）",
      cls: "is-slow",
      note: "插入 50 条 CVE 触发数千个 4 KB B+Tree 页分裂重排，补丁体积骤增且无原子边界",
    },
    {
      id: "grype-zst",
      name: "Grype DB v6 整包压缩快照（.tar.zst）",
      mb: 65,
      extMb: 200,
      sizeLabel: "v6.0 首发 ~65 MB → v6.1+ 约 ~200 MB",
      cls: "is-mid",
      note: "虚线为合入 EPSS / KEV / Unaffected / SSVC 后的实测体积增长区间",
    },
    {
      id: "trivy-oci",
      name: "Trivy DB 全层 OCI 拉取（db.tar.gz）",
      mb: 140,
      sizeLabel: "~100–145 MB / 次",
      cls: "is-mid",
      note: "每 6 小时全量重建整层推送，无跨版本逻辑增量机制",
    },
  ];

  /* ------------------------------------------------------------------------
     2. Tab 1: Visual Hash-Chain & 4-Gate State Machine Scenarios
     ------------------------------------------------------------------------ */
  const AIRGAP_SCENARIOS = [
    {
      id: "valid-chain",
      label: "1. 正常增量链 (v100 → v102)",
      outcome: "ok",
      badgeText: "安全升版 · 0 停机",
      verdictTitle: "四级闸门全绿通行：本地库平滑原子切换至 v102（仅传输 630 KB）",
      chainNodes: [
        {
          cls: "is-base",
          kicker: "Local Active",
          title: "Base v100",
          meta: "300,000 条有效规则",
          hash: "state: 9a4f...c100",
        },
        {
          arrow: true,
          cls: "is-ok",
          label: "prev 匹配 ✓",
          symbol: "→",
        },
        {
          cls: "is-ok",
          kicker: "Delta #1 (340 KB)",
          title: "delta_v100_v101",
          meta: "+25 upserts · 1 tombstone",
          hash: "target: 7b2c...d101",
        },
        {
          arrow: true,
          cls: "is-ok",
          label: "prev 匹配 ✓",
          symbol: "→",
        },
        {
          cls: "is-ok",
          kicker: "Delta #2 (290 KB)",
          title: "delta_v101_v102",
          meta: "+17 upserts · 2 tombstones",
          hash: "target: e81d...f102",
        },
      ],
      chainNote: {
        cls: "is-ok",
        text: "连续性闭环：delta_v100_v101 与 delta_v101_v102 均经 Ed25519/离线 TUF 验签通过，且哈希双锚定严格首尾相接，在 staging.db 事务重放完毕后原子切换指针。",
      },
      gates: [
        { cls: "is-ok", tag: "PASS", title: "Gate 1 · 离线验签", detail: "预置 Ed25519 公钥与离线 ~/.sigstore TUF 根校验通过。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 2 · 哈希链连续", detail: "prev_state_sha256 == 9a4f...c100，序列 100→101→102 连续。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 3 · Staging 重放", detail: "在独立 staging.db 执行 BEGIN IMMEDIATE 事务，线上读锁零阻塞。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 4 · 核验与切换", detail: "规范化逻辑摘要精确匹配 e81d...f102，原子替换生效。" },
      ],
      diff: [
        { label: "本地状态版本", val: "v100 → v102", sub: "逻辑哈希 9a4f...c100 → e81d...f102" },
        { label: "累计规则变动", val: "+42 新增 / 3 墓碑", sub: "仅重放逻辑变更集，无全表重建" },
        { label: "内网摆渡带宽", val: "630 KB / 65 MB", sub: "节省 99.03% 跨光闸传输体积" },
      ],
    },
    {
      id: "broken-chain",
      label: "2. 断链缺块 (漏传 v101)",
      outcome: "warn",
      badgeText: "熔断自愈 · 回退 Base",
      verdictTitle: "Gate 2 熔断拦截：拒绝半残重放，保留 v100 在线并回退 Harbor 全量 Base",
      chainNodes: [
        {
          cls: "is-base",
          kicker: "Local Active",
          title: "Base v100",
          meta: "当前生产读句柄保持运行",
          hash: "state: 9a4f...c100",
        },
        {
          arrow: true,
          cls: "is-broken",
          label: "缺失 ✕",
          symbol: "↛",
        },
        {
          cls: "is-missing",
          kicker: "Missing Gap",
          title: "v100 → v101 漏拷",
          meta: "U 盘摆渡遗漏昨日增量",
          hash: "expected: 7b2c...d101",
        },
        {
          arrow: true,
          cls: "is-broken",
          label: "哈希断链 ✕",
          symbol: "↛",
        },
        {
          cls: "is-warn",
          kicker: "Incoming (290 KB)",
          title: "delta_v101_v102",
          meta: "签名合法但前置状态不匹配",
          hash: "prev: 7b2c...d101 ≠ 9a4f",
        },
      ],
      chainNote: {
        cls: "is-warn",
        text: "自愈兜底路径：触发 DELTA_CHAIN_GAP(expected=v101, actual=v100) 告警并终止增量应用；客户端自动从内网 Harbor 拉取已签名的最近全量快照 base_v102.db.zst 一次重建，杜绝漏掉 v101 新 CVE。",
      },
      gates: [
        { cls: "is-ok", tag: "PASS", title: "Gate 1 · 离线验签", detail: "delta_v101_v102 签名本身真实有效，确由官方情报源签发。" },
        { cls: "is-bad", tag: "BLOCK", title: "Gate 2 · 哈希链连续", detail: "prev_state_sha256=7b2c...d101 与本地 9a4f...c100 不一致，熔断！" },
        { cls: "is-skip", tag: "SKIPPED", title: "Gate 3 · Staging 重放", detail: "禁止带缺口重放（防半残库静默漏报），已跳过事务写入。" },
        { cls: "is-warn", tag: "FALLBACK", title: "Gate 4 · Base 自愈", detail: "v100 持续在线服务，异步拉取 base_v102.db.zst 兜底重建。" },
      ],
      diff: [
        { label: "本地状态版本", val: "保持 v100 → 自愈 v102", sub: "绝不陷入缺少 v101 规则的残缺态" },
        { label: "触发告警事件", val: "DELTA_CHAIN_GAP", sub: "通知运维补全摆渡或自动切 Base" },
        { label: "线上可用性", val: "100% 零中断", sub: "只读查询句柄与内存快照未受污染" },
      ],
    },
    {
      id: "tampered-payload",
      label: "3. 载荷篡改 (恶意删 CVE)",
      outcome: "bad",
      badgeText: "密码学硬阻断",
      verdictTitle: "Gate 1 零容忍拒绝：未过验签甚至禁止进入 zstd 解压流程（防压缩炸弹）",
      chainNodes: [
        {
          cls: "is-base",
          kicker: "Local Active",
          title: "Base v100",
          meta: "完整保留所有高危规则",
          hash: "state: 9a4f...c100",
        },
        {
          arrow: true,
          cls: "is-broken",
          label: "验签失败 ✕",
          symbol: "✕",
        },
        {
          cls: "is-bad",
          kicker: "Tampered Payload",
          title: "delta_v100_v101_mod",
          meta: "中间人试图删掉高危 CVE 逃避门禁",
          hash: "ERR_INVALID_SIGNATURE",
        },
        {
          arrow: true,
          cls: "is-broken",
          label: "隔离丢弃",
          symbol: "⊘",
        },
        {
          cls: "is-shield",
          kicker: "SIEM Audit",
          title: "安全事件上报告警",
          meta: "阻止解压与任何磁盘写入",
          hash: "v100 纹丝不动",
        },
      ],
      chainNote: {
        cls: "is-bad",
        text: "纵深防御要点：先校验 OCI Manifest Digest 与 Ed25519/Cosign 离线签名再解压；任何篡改字节或构造恶意 Zstd 压缩炸弹（Zip/Zstd Bomb）都会在 Gate 1 被当场丢弃。",
      },
      gates: [
        { cls: "is-bad", tag: "BLOCK", title: "Gate 1 · 离线验签", detail: "载荷 SHA-256 变更导致 Ed25519 验签抛出 ERR_INVALID_SIGNATURE。" },
        { cls: "is-skip", tag: "SKIPPED", title: "Gate 2 · 哈希链连续", detail: "未通过身份与完整性认证的载荷不予解析包头。" },
        { cls: "is-skip", tag: "SKIPPED", title: "Gate 3 · Staging 重放", detail: "禁止进入 zstd 解压及 SQLite staging.db，防压缩炸弹 DoS。" },
        { cls: "is-ok", tag: "PROTECTED", title: "Gate 4 · 原库保护", detail: "线上 v100 完整可用，同步向 SIEM 推送高危完整性审计告警。" },
      ],
      diff: [
        { label: "本地状态版本", val: "锁定 v100（未受影响）", sub: "恶意删改未接触本地数据库与内存快照" },
        { label: "安全防护动作", val: "拒绝解压 + 丢弃载荷", sub: "防 CVE 静默抹除与 Zstd Bomb 攻击" },
        { label: "审计日志级别", val: "CRITICAL · 完整性告警", sub: "记录制品 Digest 与验签失败上下文" },
      ],
    },
    {
      id: "withdrawn-tombstone",
      label: "4. withdrawn 墓碑 (防假洞复活)",
      outcome: "ok",
      badgeText: "墓碑锁死 · 闭环消警",
      verdictTitle: "逻辑置废绝不 DELETE：永久封死内网滞后 NVD 镜像造成的假 CVE 复活",
      chainNodes: [
        {
          cls: "is-base",
          kicker: "Local v101",
          title: "CVE-2025-99999 (活跃)",
          meta: "is_enabled = true",
          hash: "state: 7b2c...d101",
        },
        {
          arrow: true,
          cls: "is-ok",
          label: "tombstones[]",
          symbol: "→",
        },
        {
          cls: "is-ok",
          kicker: "Delta (含撤回墓碑)",
          title: "delta_v101_v102",
          meta: "置 is_enabled=false + withdrawn_at",
          hash: "禁止 DELETE FROM rules",
        },
        {
          arrow: true,
          cls: "is-broken",
          label: "拦截滞后污染",
          symbol: "⊘",
        },
        {
          cls: "is-shield",
          kicker: "Stale NVD Mirror",
          title: "滞后旧源试图重推",
          meta: "withdrawn_at 权威更高 → 拒激活",
          hash: "RESOLVED_WITHDRAWN",
        },
      ],
      chainNote: {
        cls: "is-ok",
        text: "联动 Lesson 0006/0007：墓碑落库后同步推送 intel.advisory.updated（lifecycle_state=WITHDRAWN）事件，自动将受影响项目的存量告警收敛为 RESOLVED_WITHDRAWN，无需安全团队手工清表。",
      },
      gates: [
        { cls: "is-ok", tag: "PASS", title: "Gate 1 · 离线验签", detail: "delta_v101_v102 验签通过，确认撤回指令来自官方权威。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 2 · 哈希链连续", detail: "前置状态哈希匹配，按序进入墓碑逻辑事务。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 3 · 写逻辑墓碑", detail: "置 is_enabled=false 与 withdrawn_at，保留历史行阻断滞后源复活。" },
        { cls: "is-ok", tag: "PASS", title: "Gate 4 · 消警闭环", detail: "发布 intel.advisory.updated(WITHDRAWN)，自动消警存量工单。" },
      ],
      diff: [
        { label: "规则行生命周期", val: "ACTIVE → WITHDRAWN", sub: "保留墓碑行（is_enabled=false），绝不物理删行" },
        { label: "滞后 NVD 防御", val: "100% 免疫复活", sub: "旧时间戳记录无法覆盖更高权威撤回态" },
        { label: "下游工单联动", val: "自动 RESOLVED_WITHDRAWN", sub: "对齐 Lesson 0006 Hyades 持续重算事件流" },
      ],
    },
  ];

  /* ------------------------------------------------------------------------
     3. Pure Quantitative Profiler Functions (Log-Scale & Additive Breakdown)
     ------------------------------------------------------------------------ */
  const PROFILER_PRESETS = [
    { id: "micro", label: "微服务 (500 组件 · 5% 命中 · 0 热点)", sbomComponents: 500, vulnRatioPct: 5, hotPkgCount: 0, fleetProjects: 10000 },
    { id: "container", label: "大型容器 (5,000 组件 · 10% 命中 · 2 热点)", sbomComponents: 5000, vulnRatioPct: 10, hotPkgCount: 2, fleetProjects: 50000 },
    { id: "monorepo", label: "企业 Monorepo (20,000 组件 · 30% 命中 · 6 热点)", sbomComponents: 20000, vulnRatioPct: 30, hotPkgCount: 6, fleetProjects: 200000 },
  ];

  function computeProfile({ sbomComponents, vulnRatioPct, hotPkgCount, fleetProjects }) {
    const N = sbomComponents;
    const hitPkgs = Math.max(1, Math.round(N * (vulnRatioPct / 100)));
    const cleanPkgs = N - hitPkgs;
    const hotExtraRules = hotPkgCount * 420;

    // Engine 1: Per-component SQLite query + runtime regex/version string parsing
    const sqlite = {
      cleanMs: cleanPkgs * 0.095,
      hitMs: hitPkgs * (0.095 + 0.35),
      hotMs: hotExtraRules * 0.018,
    };
    sqlite.totalMs = sqlite.cleanMs + sqlite.hitMs + sqlite.hotMs;

    // Engine 2: bbolt mmap B+Tree lookup + JSON unmarshal on hit
    const bbolt = {
      cleanMs: cleanPkgs * 0.012,
      hitMs: hitPkgs * 0.14,
      hotMs: hotExtraRules * 0.012,
    };
    bbolt.totalMs = bbolt.cleanMs + bbolt.hitMs + bbolt.hotMs;

    // Engine 3: In-memory immutable snapshot (atomic.Pointer) + pre-parsed intervals
    const memory = {
      cleanMs: cleanPkgs * 0.00004,
      hitMs: hitPkgs * 0.0028,
      hotMs: hotExtraRules * 0.0006,
    };
    memory.totalMs = memory.cleanMs + memory.hitMs + memory.hotMs;

    const speedup = Math.round(sqlite.totalMs / Math.max(0.05, memory.totalMs));
    const throughputPerSec = Math.round(1000 / Math.max(0.1, memory.totalMs));
    const cleanPct = ((cleanPkgs / N) * 100).toFixed(1);

    // 0-day Continuous Re-evaluation across fleet
    const affectedProjects = Math.max(1, Math.round(fleetProjects * 0.003));
    const prunedPct = (((fleetProjects - affectedProjects) / fleetProjects) * 100).toFixed(1);
    const fullRescanSec = (fleetProjects * 1200 * 0.00004) / 1000 + fleetProjects * 0.0008;
    const reverseIndexMs = 0.4 + affectedProjects * 0.015;
    const zeroDaySpeedup = Math.round((fullRescanSec * 1000) / Math.max(0.1, reverseIndexMs));

    return {
      N,
      hitPkgs,
      cleanPkgs,
      cleanPct,
      hotExtraRules,
      sqlite,
      bbolt,
      memory,
      speedup,
      throughputPerSec,
      fleetProjects,
      affectedProjects,
      prunedPct,
      fullRescanSec,
      reverseIndexMs,
      zeroDaySpeedup,
    };
  }

  // Maps [0.1 ms .. 10000 ms] across 5 decades onto [0% .. 100%]
  function logBarPct(ms) {
    const clamped = Math.max(0.1, Math.min(10000, ms));
    return ((Math.log10(clamped) + 1) / 5) * 100;
  }

  // Maps [0.1 MB .. 300 MB] onto [8% .. 100%]
  function bwLogPct(mb) {
    const minLog = Math.log10(0.1);
    const maxLog = Math.log10(300);
    const clamped = Math.max(0.1, Math.min(300, mb));
    return 8 + ((Math.log10(clamped) - minLog) / (maxLog - minLog)) * 92;
  }

  function formatMs(ms) {
    if (ms < 1) return `${ms.toFixed(2)} ms`;
    if (ms < 100) return `${ms.toFixed(1)} ms`;
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
  }

  /* ------------------------------------------------------------------------
     4. Widget Rendering & Smooth In-Place Event Binding
     ------------------------------------------------------------------------ */
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
      activeTab: "chain",
      scenarioId: "valid-chain",
      presetId: "container",
      sbomComponents: 5000,
      vulnRatioPct: 10,
      hotPkgCount: 2,
      fleetProjects: 50000,
    };

    const tabMeta = {
      chain: "工作台 1：断网哈希链拓扑与四级闸门",
      profiler: "工作台 2：万级组件耗时拆解与 0-day 漏斗",
      compare: "工作台 3：三大离线路线带宽与合规对标",
    };

    function renderChainTab() {
      const sc = AIRGAP_SCENARIOS.find((s) => s.id === state.scenarioId) || AIRGAP_SCENARIOS[0];
      const bannerCls = sc.outcome === "ok" ? "is-ok" : sc.outcome === "warn" ? "is-warn" : "is-bad";
      const badgeCls = sc.outcome === "ok" ? "badge-ok" : sc.outcome === "warn" ? "badge-warn" : "badge-danger";

      return `
        <div class="vlab-controls-bar">
          <div>
            <div class="vlab-section-label">选择断网同步故障 / 正常场景（点击观察链路与闸门流转）</div>
            <div class="purl-presets" style="margin-bottom:0;">
              ${AIRGAP_SCENARIOS.map(
                (s) =>
                  `<button type="button" class="purl-preset-btn ${s.id === state.scenarioId ? "active" : ""}" data-action="pick-scenario" data-id="${escapeHtml(s.id)}">${escapeHtml(s.label)}</button>`
              ).join("")}
            </div>
          </div>
        </div>

        <div class="vlab-verdict-banner ${bannerCls}">
          <div><strong>裁决：</strong>${escapeHtml(sc.verdictTitle)}</div>
          <span class="badge ${badgeCls}">${escapeHtml(sc.badgeText)}</span>
        </div>

        <div class="vlab-chain-stage">
          <div class="vlab-section-label">OCI 哈希链同步拓扑（Base Snapshot → Signed Logical Delta）</div>
          <div class="vlab-chain-row">
            ${sc.chainNodes
              .map((n) => {
                if (n.arrow) {
                  return `
                    <div class="vlab-arrow ${escapeHtml(n.cls)}">
                      <span>${escapeHtml(n.symbol)}</span>
                      <span style="font-size:0.66rem;font-weight:600;">${escapeHtml(n.label)}</span>
                    </div>
                  `;
                }
                return `
                  <div class="vlab-node ${escapeHtml(n.cls)}">
                    <div class="vlab-node-kicker">${escapeHtml(n.kicker)}</div>
                    <div class="vlab-node-title">${escapeHtml(n.title)}</div>
                    <div class="vlab-node-meta">${escapeHtml(n.meta)}</div>
                    <div class="vlab-node-hash">${escapeHtml(n.hash)}</div>
                  </div>
                `;
              })
              .join("")}
          </div>
          <div class="vlab-chain-note ${escapeHtml(sc.chainNote.cls)}">${escapeHtml(sc.chainNote.text)}</div>
        </div>

        <div class="vlab-section-label">四级安全闸门执行状态（Gate 1 → Gate 4）</div>
        <div class="vlab-gates">
          ${sc.gates
            .map((g) => {
              const tagBadge =
                g.tag === "PASS" || g.tag === "PROTECTED"
                  ? "badge-ok"
                  : g.tag === "BLOCK"
                  ? "badge-danger"
                  : g.tag === "FALLBACK"
                  ? "badge-warn"
                  : "badge-blue";
              return `
                <div class="vlab-gate ${escapeHtml(g.cls)}">
                  <div class="vlab-gate-head">
                    <span>${escapeHtml(g.title.split("·")[0].trim())}</span>
                    <span class="badge ${tagBadge}">${escapeHtml(g.tag)}</span>
                  </div>
                  <div class="vlab-gate-title">${escapeHtml(g.title)}</div>
                  <div class="vlab-gate-desc">${escapeHtml(g.detail)}</div>
                </div>
              `;
            })
            .join("")}
        </div>

        <div class="vlab-section-label">本地漏洞库状态变迁（Before → After）</div>
        <div class="vlab-diff-grid">
          ${sc.diff
            .map(
              (d) => `
                <div class="vlab-diff-card">
                  <div class="vlab-diff-label">${escapeHtml(d.label)}</div>
                  <div class="vlab-diff-val">${escapeHtml(d.val)}</div>
                  <div class="vlab-diff-sub">${escapeHtml(d.sub)}</div>
                </div>
              `
            )
            .join("")}
        </div>
      `;
    }

    function renderProfilerOutput() {
      const p = computeProfile(state);
      const engines = [
        {
          name: "方案 1 · 逐组件查 SQLite + 现场正则解析",
          badgeCls: "badge-danger",
          badgeText: "高并发抖动瓶颈",
          barCls: "is-slow",
          winner: false,
          stats: p.sqlite,
          desc: `执行 ${p.N.toLocaleString()} 次 SQLite 事务探测，即使 ${p.cleanPct}% 洁净包也须走完 B-Tree 与反序列化`,
        },
        {
          name: "方案 2 · bbolt mmap 桶读取（Edge 单机优秀）",
          badgeCls: "badge-warn",
          badgeText: "适合 CLI / MCP 冷启动",
          barCls: "is-mid",
          winner: false,
          stats: p.bbolt,
          desc: `mmap 页跳过 ${p.cleanPkgs.toLocaleString()} 个洁净包；命中 ${p.hitPkgs.toLocaleString()} 个包仍需 JSON 反序列化`,
        },
        {
          name: "方案 3 · atomic.Pointer 内存索引 + 构建期预解析",
          badgeCls: "badge-ok",
          badgeText: "SaaS Cloud 推荐架构",
          barCls: "is-fast",
          winner: true,
          stats: p.memory,
          desc: `SwissTable ~40 ns 空返跳过 ${p.cleanPkgs.toLocaleString()} 个洁净包，热路径零 I/O 零锁竞争`,
        },
      ];

      return `
        <div class="vlab-kpi-strip">
          <div class="vlab-kpi is-ok">
            <div class="vlab-kpi-label">内存索引加速比</div>
            <div class="vlab-kpi-num">${p.speedup.toLocaleString()}× 更快</div>
            <div class="vlab-kpi-sub">单份 SBOM：${formatMs(p.memory.totalMs)} vs SQLite ${formatMs(p.sqlite.totalMs)}</div>
          </div>
          <div class="vlab-kpi is-blue">
            <div class="vlab-kpi-label">单核理论吞吐 &amp; 快路径跳过率</div>
            <div class="vlab-kpi-num">${p.throughputPerSec.toLocaleString()} 份/秒</div>
            <div class="vlab-kpi-sub">${p.cleanPct}%（${p.cleanPkgs.toLocaleString()} 个洁净包）~40 ns 直接空返</div>
          </div>
          <div class="vlab-kpi is-warn">
            <div class="vlab-kpi-label">突发 0-day 全平台应急收敛</div>
            <div class="vlab-kpi-num">${p.reverseIndexMs.toFixed(1)} ms</div>
            <div class="vlab-kpi-sub">RoaringBitmap 裁剪 ${p.prunedPct}% 资产（快 ${p.zeroDaySpeedup.toLocaleString()}×）</div>
          </div>
        </div>

        <div class="vlab-chart-box">
          <div class="vlab-chart-head">
            <div>
              <div class="vlab-section-label" style="margin-bottom:0.1rem;">总耗时对数标尺对比（0.1 ms → 10 s，跨越 5 个数量级）+ 三段耗时构成</div>
              <div style="font-size:0.75rem;color:var(--ink-muted);">上方粗条为对数尺度总耗时（直观比较数量级差距）；下方细条为 100% 耗时构成拆解</div>
            </div>
            <div class="vlab-legend">
              <span class="vlab-legend-item"><span class="vlab-swatch seg-clean"></span>洁净包探针</span>
              <span class="vlab-legend-item"><span class="vlab-swatch seg-hit"></span>命中解析与求值</span>
              <span class="vlab-legend-item"><span class="vlab-swatch seg-hot"></span>热点包规则解析</span>
            </div>
          </div>

          <div class="vlab-ruler">
            <span class="vlab-ruler-tick" style="left:0%;">0.1 ms</span>
            <span class="vlab-ruler-tick" style="left:20%;">1 ms</span>
            <span class="vlab-ruler-tick" style="left:40%;">10 ms</span>
            <span class="vlab-ruler-tick" style="left:60%;">100 ms</span>
            <span class="vlab-ruler-tick" style="left:80%;">1 s</span>
            <span class="vlab-ruler-tick" style="left:100%;">10 s</span>
          </div>

          <div class="vlab-engine-list">
            ${engines
              .map((eng) => {
                const total = Math.max(0.0001, eng.stats.totalMs);
                const logWidth = Math.max(2, Math.min(100, logBarPct(total)));
                const pClean = (eng.stats.cleanMs / total) * 100;
                const pHit = (eng.stats.hitMs / total) * 100;
                const pHot = Math.max(0, 100 - pClean - pHit);

                return `
                  <div class="vlab-engine-row ${eng.winner ? "is-winner" : ""}">
                    <div class="vlab-engine-top">
                      <div class="vlab-engine-name">
                        <span>${escapeHtml(eng.name)}</span>
                        <span class="badge ${eng.badgeCls}">${escapeHtml(eng.badgeText)}</span>
                      </div>
                      <span class="vlab-engine-ms">${formatMs(total)}</span>
                    </div>
                    <div class="vlab-log-track" title="对数标尺总耗时: ${formatMs(total)}">
                      <span class="vlab-log-gridline" style="left:20%;"></span>
                      <span class="vlab-log-gridline" style="left:40%;"></span>
                      <span class="vlab-log-gridline" style="left:60%;"></span>
                      <span class="vlab-log-gridline" style="left:80%;"></span>
                      <div class="vlab-log-bar ${eng.barCls}" style="width:${logWidth.toFixed(1)}%;"></div>
                    </div>
                    <div class="vlab-stack-track" title="耗时构成占比">
                      <div class="vlab-stack-seg seg-clean" style="width:${pClean.toFixed(1)}%;"></div>
                      <div class="vlab-stack-seg seg-hit" style="width:${pHit.toFixed(1)}%;"></div>
                      <div class="vlab-stack-seg seg-hot" style="width:${pHot.toFixed(1)}%;"></div>
                    </div>
                    <div class="vlab-engine-meta">
                      <span>洁净包 ${formatMs(eng.stats.cleanMs)} (${pClean.toFixed(0)}%) ｜ 命中 ${formatMs(eng.stats.hitMs)} (${pHit.toFixed(0)}%) ｜ 热点 ${formatMs(eng.stats.hotMs)} (${pHot.toFixed(0)}%)</span>
                      <span>${escapeHtml(eng.desc)}</span>
                    </div>
                  </div>
                `;
              })
              .join("")}
          </div>
        </div>

        <div class="vlab-funnel-grid">
          <div class="vlab-funnel-card is-bad">
            <div class="vlab-funnel-head">
              <span>反模式 · 无倒排索引全库重扫</span>
              <span class="badge badge-danger">单核 ${p.fullRescanSec.toFixed(1)} s · 打爆 DB IO</span>
            </div>
            <div class="vlab-funnel-stage">
              <div class="vlab-funnel-stage-top"><span>1. PostgreSQL 全量拖出全部存量 SBOM</span><strong>${p.fleetProjects.toLocaleString()} 份 (100%)</strong></div>
              <div class="vlab-funnel-bar-wrap"><div class="vlab-funnel-bar is-muted" style="width:100%;"></div></div>
            </div>
            <div class="vlab-funnel-stage">
              <div class="vlab-funnel-stage-top"><span>2. 逐份遍历反序列化并匹配该 0-day 规则</span><strong>${p.fleetProjects.toLocaleString()} 份 (100%)</strong></div>
              <div class="vlab-funnel-bar-wrap"><div class="vlab-funnel-bar is-bad" style="width:100%;"></div></div>
            </div>
          </div>

          <div class="vlab-funnel-card is-ok">
            <div class="vlab-funnel-head">
              <span>推荐 · PkgKey → RoaringBitmap 倒排漏斗</span>
              <span class="badge badge-ok">耗时 ${p.reverseIndexMs.toFixed(1)} ms · 裁剪 ${p.prunedPct}%</span>
            </div>
            <div class="vlab-funnel-stage">
              <div class="vlab-funnel-stage-top"><span>1. 全平台存量资产池</span><strong>${p.fleetProjects.toLocaleString()} 份</strong></div>
              <div class="vlab-funnel-bar-wrap"><div class="vlab-funnel-bar is-muted" style="width:100%;"></div></div>
            </div>
            <div class="vlab-funnel-stage">
              <div class="vlab-funnel-stage-top"><span>2. 查 PkgKey 位图交集（仅 0.3% 含该包）→ 内存求值</span><strong>${p.affectedProjects.toLocaleString()} 份 (${p.reverseIndexMs.toFixed(1)} ms)</strong></div>
              <div class="vlab-funnel-bar-wrap"><div class="vlab-funnel-bar is-ok" style="width:3%;"></div></div>
            </div>
          </div>
        </div>
      `;
    }

    function renderProfilerTab() {
      return `
        <div class="vlab-controls-bar">
          <div>
            <div class="vlab-section-label">快捷工作负载预设（或直接拖动下方 4 个压测滑块）</div>
            <div class="purl-presets" style="margin-bottom:0;" data-role="preset-bar">
              ${PROFILER_PRESETS.map(
                (pr) =>
                  `<button type="button" class="purl-preset-btn ${pr.id === state.presetId ? "active" : ""}" data-action="pick-preset" data-id="${escapeHtml(pr.id)}">${escapeHtml(pr.label)}</button>`
              ).join("")}
            </div>
          </div>
        </div>

        <div class="vlab-slider-grid">
          <div class="vlab-slider-field">
            <div class="vlab-slider-top">
              <label for="vlab-sbom">SBOM 组件数</label>
              <span data-val="sbomComponents">${state.sbomComponents.toLocaleString()}</span>
            </div>
            <input id="vlab-sbom" class="vlab-range" type="range" min="500" max="20000" step="500" value="${state.sbomComponents}" data-slider="sbomComponents" />
            <div class="vlab-slider-hint">500 微服务 → 20,000 Monorepo</div>
          </div>

          <div class="vlab-slider-field">
            <div class="vlab-slider-top">
              <label for="vlab-vuln">有历史漏洞包占比</label>
              <span data-val="vulnRatioPct">${state.vulnRatioPct}%</span>
            </div>
            <input id="vlab-vuln" class="vlab-range" type="range" min="5" max="30" step="5" value="${state.vulnRatioPct}" data-slider="vulnRatioPct" />
            <div class="vlab-slider-hint">5% 洁净新项目 → 30% 老旧镜像</div>
          </div>

          <div class="vlab-slider-field">
            <div class="vlab-slider-top">
              <label for="vlab-hot">高密度热点包数</label>
              <span data-val="hotPkgCount">${state.hotPkgCount} 个</span>
            </div>
            <input id="vlab-hot" class="vlab-range" type="range" min="0" max="6" step="1" value="${state.hotPkgCount}" data-slider="hotPkgCount" />
            <div class="vlab-slider-hint">如 openssl / linux（~420 规则/包）</div>
          </div>

          <div class="vlab-slider-field">
            <div class="vlab-slider-top">
              <label for="vlab-fleet">存量资产版本数</label>
              <span data-val="fleetProjects">${state.fleetProjects.toLocaleString()}</span>
            </div>
            <input id="vlab-fleet" class="vlab-range" type="range" min="10000" max="200000" step="10000" value="${state.fleetProjects}" data-slider="fleetProjects" />
            <div class="vlab-slider-hint">用于测算 0-day 全平台应急重算</div>
          </div>
        </div>

        <div data-role="profiler-output">
          ${renderProfilerOutput()}
        </div>
      `;
    }

    function renderCompareTab() {
      return `
        <div class="vlab-bw-box">
          <div class="vlab-section-label">日同步传输带宽对数对比（0.1 MB → 300 MB）· 为什么逻辑增量甩开全量包与 bsdiff？</div>
          ${BANDWIDTH_BARS.map((b) => {
            const basePct = bwLogPct(b.mb);
            const extPct = b.extMb ? Math.max(0, bwLogPct(b.extMb) - basePct) : 0;
            return `
              <div class="vlab-bw-row">
                <div class="vlab-bw-head">
                  <strong>${escapeHtml(b.name)}</strong>
                  <span class="vlab-bw-note">${escapeHtml(b.sizeLabel)}</span>
                </div>
                <div class="vlab-bw-track">
                  <div class="vlab-bw-bar ${b.cls}" style="width:${basePct.toFixed(1)}%;"></div>
                  ${extPct > 0 ? `<div class="vlab-bw-ext" style="width:${extPct.toFixed(1)}%;"></div>` : ""}
                </div>
                <div class="vlab-bw-note" style="margin-top:0.18rem;">${escapeHtml(b.note)}</div>
              </div>
            `;
          }).join("")}
        </div>

        <div class="vlab-section-label">三大离线分发与存储底座同屏横评（一目了然看差异）</div>
        <div class="vlab-compare-3">
          ${DB_ARCH_BASELINES.map(
            (arch) => `
              <div class="vlab-arch-card ${arch.recommended ? "is-recommended" : ""}">
                <div class="vlab-arch-head">
                  <span>${escapeHtml(arch.name)}</span>
                  <span class="badge ${escapeHtml(arch.badgeClass)}">${escapeHtml(arch.badgeText)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>存储内核</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.storage)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>分发协议与体积</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.transport)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>解压 / 内存占地</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.uncompressed)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>日增量能力</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.deltaSupport)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>断网部署要点</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.airgapNote)}</span>
                </div>
                <div class="vlab-arch-row">
                  <span>商业合规红线</span>
                  <span class="vlab-arch-val">${escapeHtml(arch.licenseVerdict)}</span>
                </div>
              </div>
            `
          ).join("")}
        </div>
      `;
    }

    function renderActiveWorkbench() {
      const bodyEl = container.querySelector('[data-role="workbench-body"]');
      const statusEl = container.querySelector('[data-role="widget-status"]');
      if (statusEl) {
        statusEl.textContent = tabMeta[state.activeTab] || "";
      }
      container.querySelectorAll("[data-tab]").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.tab === state.activeTab);
      });
      if (!bodyEl) return;

      if (state.activeTab === "chain") {
        bodyEl.innerHTML = renderChainTab();
        bodyEl.querySelectorAll('[data-action="pick-scenario"]').forEach((btn) => {
          btn.addEventListener("click", () => {
            state.scenarioId = btn.dataset.id;
            renderActiveWorkbench();
          });
        });
      } else if (state.activeTab === "profiler") {
        bodyEl.innerHTML = renderProfilerTab();
        bindProfilerEvents(bodyEl);
      } else {
        bodyEl.innerHTML = renderCompareTab();
      }
    }

    function bindProfilerEvents(bodyEl) {
      const outputEl = bodyEl.querySelector('[data-role="profiler-output"]');
      const syncSliderUi = () => {
        const setVal = (key, text) => {
          const el = bodyEl.querySelector(`[data-val="${key}"]`);
          if (el) el.textContent = text;
        };
        setVal("sbomComponents", state.sbomComponents.toLocaleString());
        setVal("vulnRatioPct", `${state.vulnRatioPct}%`);
        setVal("hotPkgCount", `${state.hotPkgCount} 个`);
        setVal("fleetProjects", state.fleetProjects.toLocaleString());
        bodyEl.querySelectorAll('[data-action="pick-preset"]').forEach((b) => {
          b.classList.toggle("active", b.dataset.id === state.presetId);
        });
      };

      bodyEl.querySelectorAll("[data-slider]").forEach((slider) => {
        slider.addEventListener("input", () => {
          state[slider.dataset.slider] = Number(slider.value);
          state.presetId = "";
          syncSliderUi();
          if (outputEl) {
            outputEl.innerHTML = renderProfilerOutput();
          }
        });
      });

      bodyEl.querySelectorAll('[data-action="pick-preset"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          const p = PROFILER_PRESETS.find((x) => x.id === btn.dataset.id);
          if (!p) return;
          state.presetId = p.id;
          state.sbomComponents = p.sbomComponents;
          state.vulnRatioPct = p.vulnRatioPct;
          state.hotPkgCount = p.hotPkgCount;
          state.fleetProjects = p.fleetProjects;
          ["sbomComponents", "vulnRatioPct", "hotPkgCount", "fleetProjects"].forEach((k) => {
            const inp = bodyEl.querySelector(`[data-slider="${k}"]`);
            if (inp) inp.value = String(state[k]);
          });
          syncSliderUi();
          if (outputEl) {
            outputEl.innerHTML = renderProfilerOutput();
          }
        });
      });
    }

    function renderShell() {
      const title = config.title || "可视化交互实验台：离线安全增量链、毫秒级匹配剖析与离线路线对标";
      const intro =
        config.intro ||
        "三大独立全宽工作台：依次演练断网哈希链闸门流转、拖动压测万级组件耗时拆解与 0-day 倒排漏斗、并同屏对比三大离线架构的同步带宽与商用红线。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status" data-role="widget-status">${escapeHtml(tabMeta[state.activeTab])}</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>
        <div class="vlab-tabs">
          <button type="button" class="vlab-tab ${state.activeTab === "chain" ? "active" : ""}" data-tab="chain">
            <span class="vlab-tab-num">1</span>
            <span>断网增量链拓扑与四级闸门演练</span>
          </button>
          <button type="button" class="vlab-tab ${state.activeTab === "profiler" ? "active" : ""}" data-tab="profiler">
            <span class="vlab-tab-num">2</span>
            <span>万级组件耗时拆解与 0-day 漏斗压测</span>
          </button>
          <button type="button" class="vlab-tab ${state.activeTab === "compare" ? "active" : ""}" data-tab="compare">
            <span class="vlab-tab-num">3</span>
            <span>三大离线路线带宽与合规同屏对标</span>
          </button>
        </div>
        <div data-role="workbench-body"></div>
      `;

      container.querySelectorAll("[data-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          if (state.activeTab === btn.dataset.tab) return;
          state.activeTab = btn.dataset.tab;
          renderActiveWorkbench();
        });
      });

      renderActiveWorkbench();
    }

    renderShell();
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
      document.querySelectorAll('[data-widget="vuln-index-lab"]').forEach(initVulnIndexLab);
    });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      computeProfile,
      logBarPct,
      bwLogPct,
      AIRGAP_SCENARIOS,
      DB_ARCH_BASELINES,
      BANDWIDTH_BARS,
    };
  }
})();
