/* ==========================================================================
   可复用交互组件：1 人+AI 模块化单体、Go↔Python 契约与快慢双路径调度实验台（Lesson 0024）
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

  function initServiceOrchestrationLab(container) {
    const dataEl = container.querySelector("script.service-orchestration-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const TOPOLOGIES = [
      {
        id: "solo-modmonolith",
        label: "推荐：Go 模块化单体 + Python 专项 Worker + 构建沙箱",
        opsCost: "极低（1 人 + AI 日常仅维护 2 个核心部署单元）",
        aiCohesion: "极高（Go 控制面/IR/L3 同仓编译，Proto 锁死 Go↔Python）",
        scaleCeiling: "单 PG + Go 多副本轻松支撑数千项目与百万次月扫",
        boundaryNote: "Go 负责 API/鉴权/L1+L3/策略；Python 仅负责 Pickle/AI-BOM/深度学习 AST；不可信 `cdxgen build` 进 gVisor/Kata 隔离沙箱。",
        diagramLines: [
          "┌───────────────────────────────────────────────────────────────┐",
          "│  Go Modular Monolith (API + Auth + L1/L3 Core + Orchestrator) │",
          "└──────────┬─────────────────────────────┬──────────────────────┘",
          "           │ ConnectRPC / Proto3         │ Isolated Sandbox Exec",
          "           ▼                             ▼",
          "  [Python AI/Deep Worker]       [gVisor / Firecracker Sandbox]",
          "  (AI-BOM / Safetensors / ML)   (Untrusted Maven/Gradle/npm build)"
        ]
      },
      {
        id: "premature-micro",
        label: "反例：Day-1 拆成 12 个微服务（租户/扫描/漏洞/工单/报表全拆分）",
        opsCost: "灾难级（1 人被 k8s YAML、服务网格、分布式事务与链路口径拖垮）",
        aiCohesion: "低（AI Agent 改一个字段需跨 5 个仓库同步联调，极易断链）",
        scaleCeiling: "性能反而更差（序列化与跨服务 RPC 放大尾部延迟）",
        boundaryNote: "对于 1 人 + AI 团队，微服务边界不是物理隔离红利，而是成倍增长的上下文碎片与故障排查黑洞。",
        diagramLines: [
          "[svc-tenant] ──HTTP──▶ [svc-project] ──gRPC──▶ [svc-snapshot]",
          "     │                       │                       │",
          "  (Saga?)                 (Outbox?)              (N+1 RPC!)",
          "     ▼                       ▼                       ▼",
          "[svc-finding] ◀──Kafka── [svc-vuln] ◀──REST── [svc-remediation]",
          "// 结果：AI 上下文割裂 + 本地跑不起来 + 私有化交付 12 个镜像吓退客户"
        ]
      }
    ];

    const QUEUE_STAGES = [
      {
        id: "pg-skip-locked",
        label: "Stage 1 (Day 1)：PG `SKIP LOCKED` / River",
        throughput: "~500–2,000 任务/秒（与业务库同事务零丢单）",
        onpremFit: "完美（私有化零额外中间件，少维护一个组件）",
        licenseNote: "PG License；若用 riverqueue/river 须守 MPL-2.0（仅直接调用不改其源文件）"
      },
      {
        id: "nats-jetstream",
        label: "Stage 2 (成长期)：NATS JetStream",
        throughput: "数万级异步流/秒（Go 原生嵌入或单二进制极简集群）",
        onpremFit: "优秀（单二进制 <30MB，天然适合 Hybrid/私有化）",
        licenseNote: "Apache-2.0 纯宽松商用，支持 WorkQueue / Consumer Group / 持久化回溯"
      },
      {
        id: "kafka-temporal",
        label: "Stage 3 (超大规模)：Kafka + Temporal",
        throughput: "十万+事件/秒 + 跨天长任务可恢复编排",
        onpremFit: "重（私有化仅推荐给 Tier 3 金融/大集群，不强制捆绑给中小客）",
        licenseNote: "Apache Kafka (Apache-2.0) · Temporal (MIT)；须通过抽象 Queue 接口平滑切换"
      }
    ];

    const STORM_PRESETS = [
      {
        id: "pr-plus-0day",
        label: "1. 夜间 0-day 全网 5,000 项目重算撞上早高峰 PR 提交",
        desc: "早上 9:30 安全团队触发全网 5,000 个项目的 0-day 重算任务，同时研发人员与 AI Agent 正在频繁提交 PR 与触发 MCP 校验。",
        fastQueue: true,
        idempotency: true,
        tenantQuota: true
      },
      {
        id: "ci-retry-storm",
        label: "2. 同一 Commit 被 CI Webhook + 人工点击重复推送 40 次",
        desc: "某大型 Monorepo 因 CI 网络抖动与开发者连续重跑 Pipeline，1 分钟内向同一 Asset + Commit 发射了 40 次全量扫描请求。",
        fastQueue: true,
        idempotency: true,
        tenantQuota: true
      },
      {
        id: "poison-python",
        label: "3. 畸形超大 AI 模型文件卡死 Python Worker 内存（Poison Pill）",
        desc: "某个 40GB 畸形权重文件导致 Python Worker 在解析头信息时超时 OOM；若无状态机重试上限与死信隔离，任务会无限重启拖垮整机。",
        fastQueue: true,
        idempotency: true,
        tenantQuota: true
      }
    ];

    const state = {
      activeTab: "topology",
      topoId: "solo-modmonolith",
      queueId: "pg-skip-locked",
      presetId: STORM_PRESETS[0].id,
      fastQueue: true,
      idempotency: true,
      tenantQuota: true
    };

    function renderTopologyTab() {
      const topo = TOPOLOGIES.find((t) => t.id === state.topoId) || TOPOLOGIES[0];
      const q = QUEUE_STAGES.find((x) => x.id === state.queueId) || QUEUE_STAGES[0];
      const isGood = topo.id === "solo-modmonolith";

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 对比「1 人 + AI Agent」服务边界方案：</span>
          <div class="grl-pill-group" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${TOPOLOGIES.map(
              (t) => `
                <button type="button" class="grl-pill ${state.topoId === t.id ? "active" : ""}" data-topo="${t.id}">
                  ${escapeHtml(t.label)}
                </button>
              `
            ).join("")}
          </div>

          <span class="grl-control-label">2. 切换异步任务队列演进阶梯（通过统一 Queue Port 接口无感切换）：</span>
          <div class="grl-pill-group" style="margin-top:0.35rem;">
            ${QUEUE_STAGES.map(
              (qs) => `
                <button type="button" class="grl-pill ${state.queueId === qs.id ? "active" : ""}" data-qstage="${qs.id}">
                  ${escapeHtml(qs.label)}
                </button>
              `
            ).join("")}
          </div>
        </div>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Solo 运维心智负担</div>
            <div class="grl-kpi-val" style="color:${isGood ? "var(--ok)" : "var(--danger)"};">${escapeHtml(topo.opsCost)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">AI Agent 上下文聚拢度</div>
            <div class="grl-kpi-val" style="color:${isGood ? "var(--ok)" : "var(--danger)"};">${escapeHtml(topo.aiCohesion)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">当前队列吞吐边界</div>
            <div class="grl-kpi-val" style="color:var(--accent-blue);">${escapeHtml(q.throughput)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">私有化交付适配度</div>
            <div class="grl-kpi-val">${escapeHtml(q.onpremFit)}</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">进程边界与通信拓扑图：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">${topo.diagramLines.map((l) => escapeHtml(l)).join("\n")}</pre></div>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">架构权衡与开源协议红线：</div>
            <p style="font-size:0.82rem;line-height:1.6;color:var(--ink-secondary);margin:0 0 0.5rem;"><strong>服务边界：</strong>${escapeHtml(topo.boundaryNote)}</p>
            <p style="font-size:0.82rem;line-height:1.6;color:var(--ink-secondary);margin:0;"><strong>队列许可与边界：</strong>${escapeHtml(q.licenseNote)}</p>
          </div>
        </div>
      `;
    }

    function renderStormTab() {
      const preset = STORM_PRESETS.find((p) => p.id === state.presetId) || STORM_PRESETS[0];

      const prLatency = state.fastQueue ? (state.tenantQuota ? "4.2s (P95 < 15s SLA 达标)" : "18s (受单租户突增轻度抖动)") : "11分 40秒 (被 5,000 条慢任务队头阻塞!)";
      const dupDrop = state.idempotency ? "拦截 39/40 次重复扫描（省 97% 算力）" : "重复执行 40 次（数据库与 Worker 满载）";
      const poisonFate = state.idempotency && state.fastQueue ? "3 次指数退避后自动移入 DLQ + 标记 FAILED_NON_RETRYABLE" : "持续重入主队列引发 Worker 连环 OOM 雪崩";
      const overallHealthy = state.fastQueue && state.idempotency && state.tenantQuota;

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 注入高并发生产风暴场景：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${STORM_PRESETS.map(
              (p) => `
                <button type="button" class="grl-pill ${state.presetId === p.id ? "active" : ""}" data-storm="${p.id}">
                  ${escapeHtml(p.label)}
                </button>
              `
            ).join("")}
          </div>

          <span class="grl-control-label">2. 开关 Orchestrator 护栏机制：</span>
          <div style="display:flex;flex-direction:column;gap:0.4rem;margin-top:0.35rem;">
            <label class="grl-toggle">
              <input type="checkbox" data-stoggle="fastQueue" ${state.fastQueue ? "checked" : ""} />
              <span><strong>快慢双路径队列隔离（Lane Isolation）</strong>：PR/MCP <code>&lt;15s</code> 专用快车道，绝不与 0-day/全量慢路径混排</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-stoggle="idempotency" ${state.idempotency ? "checked" : ""} />
              <span><strong>幂等键去重 + 有界状态机</strong>：按 <code>(tenant_id, asset_id, commit_or_digest, scan_profile)</code> 去重并限 3 次退避进 DLQ</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-stoggle="tenantQuota" ${state.tenantQuota ? "checked" : ""} />
              <span><strong>多租户令牌桶公平调度（DRR / Tenant Quota）</strong>：防止单个 SaaS 大租户瞬间刷光全站 Worker 池</span>
            </label>
          </div>
        </div>

        <p style="font-size:0.86rem;color:var(--ink-secondary);margin:0 0 0.75rem;"><strong>故障场景：</strong>${escapeHtml(preset.desc)}</p>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">PR / Agent 快路径 P95 延迟</div>
            <div class="grl-kpi-val" style="color:${state.fastQueue ? "var(--ok)" : "var(--danger)"};">${escapeHtml(prLatency)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">重复扫描抑制率</div>
            <div class="grl-kpi-val" style="color:${state.idempotency ? "var(--ok)" : "var(--danger)"};">${escapeHtml(dupDrop)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">毒丸任务（Poison Pill）归宿</div>
            <div class="grl-kpi-val" style="color:${overallHealthy ? "var(--ok)" : "var(--warn)"};">${escapeHtml(poisonFate)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">系统抗雪崩评级</div>
            <div class="grl-kpi-val" style="color:${overallHealthy ? "var(--ok)" : "var(--danger)"};">${overallHealthy ? "稳健（Zero-Blast-Radius）" : "存在连锁雪崩风险"}</div>
          </div>
        </div>

        <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">ScanJob 状态机：PENDING ─(Claim+Lease)─▶ RUNNING ─▶ PARSING ─▶ ENRICHING ─▶ SUCCEEDED
                                   │                                        │
                          (心跳超时/可重试)                        (不可恢复/超3次)
                                   ▼                                        ▼
                            RETRY_BACKOFF ──────────────────────▶ DEAD_LETTER (DLQ)</pre></div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：1 人 + AI 服务拓扑与快慢双路径调度沙盘";
      const intro =
        config.intro ||
        "在模式一中对比「Go 模块化单体 + Python 专项 Worker」与早产微服务的研发成本差异；在模式二中注入生产风暴，实测快慢队列隔离、幂等键与状态机的防雪崩效果。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0024 · Service &amp; Queue Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "topology" ? "active" : ""}" data-tab="topology">
            <span class="grl-tab-num">1</span>
            模式一：模块化单体边界与三段式队列演进
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "storm" ? "active" : ""}" data-tab="storm">
            <span class="grl-tab-num">2</span>
            模式二：快慢双路径隔离、幂等键与防雪崩状态机
          </button>
        </div>

        ${state.activeTab === "topology" ? renderTopologyTab() : renderStormTab()}
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
      container.querySelectorAll("[data-topo]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.topoId = btn.dataset.topo;
          render();
        });
      });
      container.querySelectorAll("[data-qstage]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.queueId = btn.dataset.qstage;
          render();
        });
      });
      container.querySelectorAll("[data-storm]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = btn.dataset.storm;
          const found = STORM_PRESETS.find((p) => p.id === btn.dataset.storm);
          if (found) {
            state.fastQueue = found.fastQueue;
            state.idempotency = found.idempotency;
            state.tenantQuota = found.tenantQuota;
          }
          render();
        });
      });
      container.querySelectorAll("[data-stoggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          state[cb.dataset.stoggle] = cb.checked;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="service-orchestration-lab"]').forEach(initServiceOrchestrationLab);
  });
})();
