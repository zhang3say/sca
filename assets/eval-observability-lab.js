/* ==========================================================================
   可复用交互组件：SCA 黄金样本 Benchmark 门禁、OTel 剖析与 90 天切片实验台（Lesson 0027）
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

  function initEvalObservabilityLab(container) {
    const dataEl = container.querySelector("script.eval-observability-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const AI_PRS = [
      {
        id: "maven-bom-refactor",
        label: "PR #142 (AI 重构 Maven BOM 继承与传递解析器)",
        unitTestStatus: "go test ./... 100% PASS (18/18 单元测试通过)",
        precisionDelta: "-0.4%",
        recallDelta: "-14.2% (漏报 19 个传递依赖!)",
        f1Score: "87.1% (基线 96.4%)",
        latencyDelta: "+8ms",
        passGate: false,
        rootCause: "AI Agent 为了提速顺手跳过了父 POM `dependencyManagement` 的多层 `import` 递归展开，单元测试用例太简单未覆盖该分支，被黄金样本 Benchmark Harness 在合并前精准拦下！"
      },
      {
        id: "deb-evr-fix",
        label: "PR #149 (AI 修复 Debian Epoch `:` 版本比较边界)",
        unitTestStatus: "go test ./... 100% PASS (42/42 单元测试通过)",
        precisionDelta: "+3.8% (消除 11 条历史误报)",
        recallDelta: "0.0% (零漏报回退)",
        f1Score: "98.2% (基线 96.4%)",
        latencyDelta: "+1ms",
        passGate: true,
        rootCause: "黄金样本集覆盖了 Debian `DSA-5724-1` 与 Epoch 混排病例：Precision 提升且 Recall 零下跌，P95 耗时波动 <2ms，自动签发合并绿灯。"
      },
      {
        id: "pickle-regex-tweak",
        label: "PR #155 (AI 精简 Python Worker Pickle 恶意操作码白名单)",
        unitTestStatus: "pytest 100% PASS (30/30 单元测试通过)",
        precisionDelta: "+0.2%",
        recallDelta: "-22.5% (放行了 NullifAI 绕过样本!)",
        f1Score: "81.9% (基线 95.8%)",
        latencyDelta: "-35ms",
        passGate: false,
        rootCause: "AI 为追求性能误把 Fail-Closed 白名单改成了宽松黑名单，导致 6 个已知绕过载荷样本在黄金恶意样本库上直接逃逸！Benchmark 门禁一票否决合并。"
      },
      {
        id: "go-vta-cache",
        label: "PR #161 (AI 为 Go Call Graph 增加包级摘要缓存)",
        unitTestStatus: "go test ./... 100% PASS (64/64 单元测试通过)",
        precisionDelta: "+0.1%",
        recallDelta: "0.0%",
        f1Score: "96.5% (基线 96.4%)",
        latencyDelta: "-68% (P95 14.2s → 4.5s)",
        passGate: true,
        rootCause: "在黄金调用图样本（含跨函数闭包与接口动态派发）上保持零 Recall 损失，同时把 P95 扫仓时间从 14.2s 压到 4.5s，高价值性能跃升合并上线！"
      }
    ];

    const MILESTONES = [
      {
        id: "m1",
        label: "Month 1 (M1 · 垂直切片 1：统一底座 & Agent 左移)",
        deliverable: "Go 单体骨架 + `sqlc`/PG RLS 表 + OSV-SCALIBR 嵌入 + Single Go Core (`--mode=mcp/hook`) + 黄金集 v0.1",
        deployMode: "单机 Docker Compose 与 SaaS 单节点同构启动",
        validation: "能跑通 Go/npm/PyPI 依赖解析、生成 PURL IR 并拦住已知幻觉/CVE 包"
      },
      {
        id: "m2",
        label: "Month 2 (M2 · 垂直切片 2：L3 精确匹配、VEX 与快慢编排)",
        deliverable: "OSV/GHSA/Backport 引擎 + Finding 稳定指纹状态机 + Outbox + Fast/Slow 队列 + OTel `traceparent`",
        deployMode: "SaaS (PG + Valkey) + 首个 Hybrid Runner 出站 PoC",
        validation: "PR 增量门禁 <15s；人工 VEX 跨提交 100% 保留；CI 回归卡死 Precision/Recall"
      },
      {
        id: "m3",
        label: "Month 3 (M3 · 垂直切片 3：差异化壁垒 & 双模首发包)",
        deliverable: "Go/Java 静态可达性 + Python AI-BOM/Safetensors Worker (ConnectRPC) + Ed25519 离线 License + Helm Chart",
        deployMode: "全双模交付就绪（SaaS + Hybrid Runner + Air-Gapped 离线安装包）",
        validation: "拿得出一套可直接签单的 Pro/Enterprise POC 演示与 EU CRA 封板证据包"
      }
    ];

    const state = {
      activeTab: "benchmark",
      prId: AI_PRS[0].id,
      harnessOn: true,
      milestoneId: "m1"
    };

    function renderBenchmarkTab() {
      const pr = AI_PRS.find((x) => x.id === state.prId) || AI_PRS[0];
      const mergedBadly = !state.harnessOn && !pr.passGate;
      const verdictText = state.harnessOn
        ? (pr.passGate ? "PASS：允许自动合并（指标全达标）" : "BLOCKED：Benchmark 门禁拦截（防静默回归！）")
        : "危险：仅靠单元测试直接放行合并！";
      const verdictColor = state.harnessOn
        ? (pr.passGate ? "var(--ok)" : "var(--danger)")
        : (pr.passGate ? "var(--ok)" : "var(--danger)");

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 选择 AI Coding Agent 提交的 Pull Request：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${AI_PRS.map(
              (item) => `
                <button type="button" class="grl-pill ${state.prId === item.id ? "active" : ""}" data-pr="${item.id}">
                  ${escapeHtml(item.label)}
                </button>
              `
            ).join("")}
          </div>

          <label class="grl-toggle">
            <input type="checkbox" data-htog="harnessOn" ${state.harnessOn ? "checked" : ""} />
            <span><strong>启用 SCA 黄金样本回归评测门禁（Benchmark Harness）</strong>：强卡 Precision / Recall 零回退与 P95 延迟预算</span>
          </label>
        </div>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">传统单元测试结果</div>
            <div class="grl-kpi-val" style="color:var(--ok);">${escapeHtml(pr.unitTestStatus)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">黄金库 Precision / Recall 变化</div>
            <div class="grl-kpi-val" style="color:${pr.passGate ? "var(--ok)" : "var(--danger)"};">
              ${escapeHtml(pr.precisionDelta)} / ${escapeHtml(pr.recallDelta)}
            </div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">F1 综合精度 &amp; P95 延迟</div>
            <div class="grl-kpi-val">${escapeHtml(pr.f1Score)} · ${escapeHtml(pr.latencyDelta)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">CI 合并门禁裁决</div>
            <div class="grl-kpi-val" style="color:${verdictColor};">${escapeHtml(verdictText)}</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">评测诊断报告：</div>
            <p style="font-size:0.82rem;line-height:1.62;color:${mergedBadly ? "var(--danger)" : "var(--ink-secondary)"};margin:0;">
              ${mergedBadly ? "【线上事故预警】由于关闭了 Benchmark 门禁，AI 跑绿单元测试后直接把漏报 14%–22% 的改动合进了主干！" : escapeHtml(pr.rootCause)}
            </p>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">CI Gate YAML / 评测命令契约：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">sca-eval --corpus ./testdata/golden-corpus.manifest \
  --fail-on-precision-drop 0.005 \
  --fail-on-recall-drop 0.002 \
  --max-p95-ms 15000</pre></div>
          </div>
        </div>
      `;
    }

    function renderOtelTab() {
      const ms = MILESTONES.find((m) => m.id === state.milestoneId) || MILESTONES[0];
      const spans = [
        { name: "go.api.auth_rls_tx", pct: 4, msText: "18 ms (PG SET LOCAL)" },
        { name: "go.l1.osv_scalibr_extract", pct: 28, msText: "1,120 ms (FS/Lockfile)" },
        { name: "go.l3.version_backport_match", pct: 12, msText: "480 ms (In-Mem Index)" },
        { name: "py.worker.aibom_safetensors", pct: 46, msText: "1,840 ms (ConnectRPC + traceparent)" },
        { name: "go.pg.outbox_finding_upsert", pct: 10, msText: "410 ms (CAS + Outbox)" }
      ];

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">选择 90 天垂直切片（Solo + AI Agent 交付节奏）：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;">
            ${MILESTONES.map(
              (m) => `
                <button type="button" class="grl-pill ${state.milestoneId === m.id ? "active" : ""}" data-ms="${m.id}">
                  ${escapeHtml(m.label)}
                </button>
              `
            ).join("")}
          </div>
        </div>

        <div class="grl-compare-grid is-2col" style="margin-bottom:0.85rem;">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.55rem;">
              OpenTelemetry Go &harr; Python 跨语言 Span 耗时剖面（总计 ~3.87s）
            </div>
            ${spans
              .map(
                (sp) => `
                  <div class="grl-bar-row">
                    <div class="grl-bar-head">
                      <span><code>${escapeHtml(sp.name)}</code></span>
                      <span>${escapeHtml(sp.msText)} (${sp.pct}%)</span>
                    </div>
                    <div class="grl-bar-track">
                      <div class="grl-bar-fill ${sp.pct > 40 ? "is-warn" : "is-blue"}" style="width:${sp.pct}%;"></div>
                    </div>
                  </div>
                `
              )
              .join("")}
          </div>

          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">当前里程碑垂直切片清单：</div>
            <p style="font-size:0.81rem;line-height:1.58;color:var(--ink-secondary);margin:0 0 0.45rem;"><strong>交付模块：</strong>${escapeHtml(ms.deliverable)}</p>
            <p style="font-size:0.81rem;line-height:1.58;color:var(--ink-secondary);margin:0 0 0.45rem;"><strong>双模载体：</strong>${escapeHtml(ms.deployMode)}</p>
            <p style="font-size:0.81rem;line-height:1.58;color:var(--ok);margin:0;"><strong>验收标准：</strong>${escapeHtml(ms.validation)}</p>
          </div>
        </div>

        <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">monorepo/
├── contracts/          # [单一契约真值] proto/ (Buf) · openapi.yaml (oapi-codegen) · db/queries/ (sqlc)
├── services/go-core/   # Go 模块化单体 (--role=all|api|worker) + gen/ 只读生成目录
├── workers/py-aibom/   # Python ConnectRPC ASGI Worker + uv.lock + gen/ 只读生成目录
├── eval/golden-corpus/ # 不可篡改黄金样本 + Precision/Recall CI 门禁
└── docs/adr/ &amp; spec/   # MADR 架构决策 + 垂直切片 Spec（每次开新 AI 会话先读索引）</pre></div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：SCA 黄金样本 Benchmark 门禁与 OTel/90 天落地台";
      const intro =
        config.intro ||
        "模式一模拟 AI Coding Agent 跑绿单元测试后暗藏精度回退的 PR，体验黄金样本回归门禁的拦截威力；模式二查看 Go↔Python 跨语言链路剖析与 90 天垂直切片路径。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0027 · Eval &amp; Ops Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "benchmark" ? "active" : ""}" data-tab="benchmark">
            <span class="grl-tab-num">1</span>
            模式一：防 AI 静默回归 · 黄金样本 Benchmark 门禁
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "otel" ? "active" : ""}" data-tab="otel">
            <span class="grl-tab-num">2</span>
            模式二：OpenTelemetry 耗时剖析 &amp; 90 天垂直切片
          </button>
        </div>

        ${state.activeTab === "benchmark" ? renderBenchmarkTab() : renderOtelTab()}
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
      container.querySelectorAll("[data-pr]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.prId = btn.dataset.pr;
          render();
        });
      });
      container.querySelectorAll("[data-htog]").forEach((cb) => {
        cb.addEventListener("change", () => {
          state[cb.dataset.htog] = cb.checked;
          render();
        });
      });
      container.querySelectorAll("[data-ms]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.milestoneId = btn.dataset.ms;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="eval-observability-lab"]').forEach(initEvalObservabilityLab);
  });
})();
