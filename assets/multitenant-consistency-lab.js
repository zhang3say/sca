/* ==========================================================================
   可复用交互组件：PG RLS 多租户攻防、Finding 指纹状态机与 Outbox 一致性实验台（Lesson 0025）
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

  function initMultitenantConsistencyLab(container) {
    const dataEl = container.querySelector("script.multitenant-consistency-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const RLS_PRESETS = [
      {
        id: "pgbouncer-leak",
        label: "1. PgBouncer 事务连接池复用（跨租户串数高危场景）",
        desc: "Tenant A 请求刚结束释放连接回 PgBouncer 事务池；紧接着 Tenant B 请求拿到了同一个物理连接，却恰好漏掉了某个中间件赋值。",
        setLocal: true,
        forceRls: true,
        noBypass: true,
        failClosed: true
      },
      {
        id: "owner-bypass",
        label: "2. 应用池账号误用了建表 Owner（静默穿透 RLS）",
        desc: "部署脚本偷懒用表 Owner（或超级账号）配置了后端数据库连接串；PostgreSQL 默认对 Table Owner 静默跳过 RLS 策略！",
        setLocal: true,
        forceRls: true,
        noBypass: true,
        failClosed: true
      },
      {
        id: "onprem-single",
        label: "3. Air-Gapped 私有化单租户（零改表复用同一 Schema）",
        desc: "客户内网只部署单一组织，运维担心为了私有化还要维护一套去掉 tenant_id 的 SQL 脚本。",
        setLocal: true,
        forceRls: true,
        noBypass: true,
        failClosed: true
      }
    ];

    const CONSISTENCY_EVENTS = [
      {
        id: "refactor-move",
        label: "事件 1：研发把目录从 `/old-api/go.mod` 重构迁到 `/svc/pay/go.mod`",
        desc: "组件还是同一个 pkg:golang/gin-gonic/gin，漏洞还是同一个 CVE；但文件在仓库内的物理目录变了。",
        naiveFate: "旧位置标记 FIXED，新位置新建 OPEN 漏洞 —— 原有 VEX NOT_AFFECTED 豁免全部丢失！",
        goodFate: "稳定指纹按 (asset_id, branch, purl_type_name, vuln_id, symbol) 匹配，旧豁免 100% 平滑延续，仅更新 locator 元数据。"
      },
      {
        id: "vuln-fixed-reopen",
        label: "事件 2：v1.9 修掉后状态变 FIXED，下周研发回滚旧锁文件（Reopen）",
        desc: "某周二 PR 升级组件消除漏洞（状态转 FIXED），周五因业务 Bug 回滚了整笔 lockfile 提交。",
        naiveFate: "产生两条割裂的重复工单记录，无法统计该漏洞的实际回归次数（Regression Rate）。",
        goodFate: "状态机精准从 FIXED 迁移回 REOPENED（递增 reopen_count），同时保持历史审计轨迹完整并自动唤醒关联任务。"
      },
      {
        id: "outbox-crash",
        label: "事件 3：AppSec 刚在 PG 签发 VEX 豁免，写入 ClickHouse 瞬间进程 Crash",
        desc: "PostgreSQL 已把 LogicalFinding 更新为 VEX_NOT_AFFECTED，但进程尚未调通 ClickHouse HTTP 写入即崩溃重启。",
        naiveFate: "PG 显示已豁免，CISO 大盘 ClickHouse 永久残留虚假高危计数（双写脑裂）！",
        goodFate: "同一 PG 事务已写入 outbox_events(version=txid)；重启后 Poller 自动重放并由 ClickHouse ReplacingMergeTree 幂等收敛。"
      }
    ];

    const state = {
      activeTab: "rls",
      rlsPreset: RLS_PRESETS[0].id,
      setLocal: true,
      forceRls: true,
      noBypass: true,
      failClosed: true,
      eventId: CONSISTENCY_EVENTS[0].id,
      stableFp: true,
      outboxPattern: true
    };

    function renderRlsTab() {
      const preset = RLS_PRESETS.find((p) => p.id === state.rlsPreset) || RLS_PRESETS[0];
      const leakRisks = [];
      if (!state.setLocal) leakRisks.push("会话级 SET 在 PgBouncer 回收连接后不会清空，下一个租户将直接读到上个租户的数据！");
      if (!state.forceRls) leakRisks.push("未开启 FORCE ROW LEVEL SECURITY，若连接账号碰巧是建表 Owner，全部 RLS 策略形同虚设！");
      if (!state.noBypass) leakRisks.push("应用账号带 BYPASSRLS 权限，任何漏加 WHERE 的 sqlc 查询都会返回全网跨租户行！");
      if (!state.failClosed) leakRisks.push("current_setting(..., false) 在未设置时会抛异常或误用空默认租户，存在未初始化访问漏洞！");

      const isSafe = leakRisks.length === 0;
      const isSingleOnPrem = preset.id === "onprem-single";

      const sqlSnippet = [
        "-- 1. 表结构与强制 RLS（SaaS 多租户与私有化单租户 100% 共用）",
        "ALTER TABLE logical_findings ENABLE ROW LEVEL SECURITY;",
        state.forceRls
          ? "ALTER TABLE logical_findings FORCE ROW LEVEL SECURITY; -- 禁止表 Owner 绕过"
          : "-- [缺失!] 未配置 FORCE ROW LEVEL SECURITY",
        "",
        "-- 2. 策略函数（Fail-Closed：未注入租户上下文时返回 NULL，行命中必为 0）",
        state.failClosed
          ? "USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)"
          : "USING (tenant_id = current_setting('app.current_tenant')::uuid) -- [危险!]",
        "",
        "-- 3. Go pgx/sqlc 事务包装器（WithTenantTx）",
        "BEGIN;",
        state.setLocal
          ? (isSingleOnPrem
              ? "SET LOCAL app.current_tenant = '00000000-0000-7000-8000-000000000001'; -- 私有化固定单租户"
              : "SET LOCAL app.current_tenant = '7d1f9b20-...'; -- 事务提交/回滚自动失效")
          : "SET app.current_tenant = '7d1f9b20-...'; -- [严重事故! 会话级残留污染连接池]",
        "SELECT finding_id, status FROM logical_findings WHERE project_id = $1;",
        "COMMIT;"
      ];

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 选择租户隔离高压场景：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${RLS_PRESETS.map(
              (p) => `
                <button type="button" class="grl-pill ${state.rlsPreset === p.id ? "active" : ""}" data-rlspreset="${p.id}">
                  ${escapeHtml(p.label)}
                </button>
              `
            ).join("")}
          </div>

          <span class="grl-control-label">2. 检查 PostgreSQL RLS 四重保险丝：</span>
          <div style="display:flex;flex-direction:column;gap:0.4rem;margin-top:0.35rem;">
            <label class="grl-toggle">
              <input type="checkbox" data-rtoggle="setLocal" ${state.setLocal ? "checked" : ""} />
              <span>使用事务级 <code>SET LOCAL</code>（配合 PgBouncer 事务模式在 <code>COMMIT/ROLLBACK</code> 自动销毁）</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-rtoggle="forceRls" ${state.forceRls ? "checked" : ""} />
              <span>显式开启 <code>FORCE ROW LEVEL SECURITY</code>（防建表账号/Owner 静默绕过）</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-rtoggle="noBypass" ${state.noBypass ? "checked" : ""} />
              <span>应用池账号强制 <code>NOSUPERUSER NOBYPASSRLS</code>（迁移账号与业务账号严格分离）</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-rtoggle="failClosed" ${state.failClosed ? "checked" : ""} />
              <span>Fail-Closed 策略表达式（<code>NULLIF(current_setting(..., true), '')::uuid</code>）</span>
            </label>
          </div>
        </div>

        <p style="font-size:0.86rem;color:var(--ink-secondary);margin:0 0 0.75rem;"><strong>场景说明：</strong>${escapeHtml(preset.desc)}</p>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">跨租户隔离安全评级</div>
            <div class="grl-kpi-val" style="color:${isSafe ? "var(--ok)" : "var(--danger)"};">${isSafe ? "安全（纵深闭环）" : "存在严重串数风险"}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">PgBouncer 连接池安全性</div>
            <div class="grl-kpi-val" style="color:${state.setLocal ? "var(--ok)" : "var(--danger)"};">${state.setLocal ? "事务结束自动清零" : "连接污染泄密"}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">双模代码与迁移复用度</div>
            <div class="grl-kpi-val" style="color:var(--ok);">100% 同一套 Schema</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">漏洞风险项数</div>
            <div class="grl-kpi-val" style="color:${isSafe ? "var(--ok)" : "var(--danger)"};">${leakRisks.length} 项高危缺陷</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">PostgreSQL 实际执行 SQL 链路：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">${sqlSnippet.map((l) => escapeHtml(l)).join("\n")}</pre></div>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">安全审计结论：</div>
            ${
              isSafe
                ? `<p style="font-size:0.82rem;line-height:1.62;color:var(--ok);margin:0;">四道防线全部就位：即便 AI Agent 在某个新写的 sqlc 查询里漏写了 <code>WHERE tenant_id = $1</code>，PostgreSQL 引擎层也会在底层自动拦截跨租户行；同时私有化客户仅需注入固定 <code>DEFAULT_TENANT_ID</code> 即可零分叉运行。</p>`
                : `<ul style="margin:0;padding-left:1.1rem;font-size:0.81rem;line-height:1.62;color:var(--danger);">${leakRisks.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
            }
          </div>
        </div>
      `;
    }

    function renderLifecycleTab() {
      const ev = CONSISTENCY_EVENTS.find((e) => e.id === state.eventId) || CONSISTENCY_EVENTS[0];
      const isGood = state.stableFp && state.outboxPattern;

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">1. 触发业务状态与存储一致性挑战事件：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;margin-bottom:0.75rem;">
            ${CONSISTENCY_EVENTS.map(
              (item) => `
                <button type="button" class="grl-pill ${state.eventId === item.id ? "active" : ""}" data-ev="${item.id}">
                  ${escapeHtml(item.label)}
                </button>
              `
            ).join("")}
          </div>

          <span class="grl-control-label">2. 启用架构一致性护栏：</span>
          <div style="display:flex;flex-direction:column;gap:0.4rem;margin-top:0.35rem;">
            <label class="grl-toggle">
              <input type="checkbox" data-ctoggle="stableFp" ${state.stableFp ? "checked" : ""} />
              <span><strong>Finding 稳定逻辑指纹 + 5 态生命周期机</strong>（<code>OPEN ↔ FIXED ↔ REOPENED</code>，解耦物理文件路径漂移）</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-ctoggle="outboxPattern" ${state.outboxPattern ? "checked" : ""} />
              <span><strong>Transactional Outbox + ClickHouse <code>ReplacingMergeTree(version)</code></strong>（PG 同事务写事件表，防崩溃脑裂）</span>
            </label>
          </div>
        </div>

        <p style="font-size:0.86rem;color:var(--ink-secondary);margin:0 0 0.75rem;"><strong>事件背景：</strong>${escapeHtml(ev.desc)}</p>

        <div class="grl-compare-grid is-2col" style="margin-bottom:0.85rem;">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:${isGood ? "var(--ok)" : "var(--danger)"};margin-bottom:0.4rem;">
              ${isGood ? "当前稳态结果（护栏生效）" : "当前异常结果（护栏缺失）"}
            </div>
            <p style="font-size:0.82rem;line-height:1.62;color:var(--ink-secondary);margin:0;">
              ${escapeHtml(isGood ? ev.goodFate : ev.naiveFate)}
            </p>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">Finding 跨提交指纹公式 &amp; Outbox 落盘契约：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">fingerprint = SHA256(tenant_id | asset_id | branch | canonical_purl_no_ver | vuln_id | symbol)
-- 同事务同步写入 outbox_events，ClickHouse 用 ReplacingMergeTree(version, is_deleted) 幂等收敛</pre></div>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：PG RLS 多租户防串数与 Outbox 一致性仿真器";
      const intro =
        config.intro ||
        "模式一测试 PostgreSQL RLS 四重保险丝在 PgBouncer 池化与私有化单租户下的真实隔离效果；模式二推演代码重构、回滚与进程崩溃时 Finding 指纹和 Transactional Outbox 的收敛表现。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0025 · Storage &amp; Consistency Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "rls" ? "active" : ""}" data-tab="rls">
            <span class="grl-tab-num">1</span>
            模式一：PostgreSQL RLS 多租户防串数攻防实验台
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "lifecycle" ? "active" : ""}" data-tab="lifecycle">
            <span class="grl-tab-num">2</span>
            模式二：Finding 稳定指纹与 Outbox 一致性推演
          </button>
        </div>

        ${state.activeTab === "rls" ? renderRlsTab() : renderLifecycleTab()}
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
      container.querySelectorAll("[data-rlspreset]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.rlsPreset = btn.dataset.rlspreset;
          const found = RLS_PRESETS.find((p) => p.id === btn.dataset.rlspreset);
          if (found) {
            state.setLocal = found.setLocal;
            state.forceRls = found.forceRls;
            state.noBypass = found.noBypass;
            state.failClosed = found.failClosed;
          }
          render();
        });
      });
      container.querySelectorAll("[data-rtoggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          state[cb.dataset.rtoggle] = cb.checked;
          render();
        });
      });
      container.querySelectorAll("[data-ev]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.eventId = btn.dataset.ev;
          render();
        });
      });
      container.querySelectorAll("[data-ctoggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          state[cb.dataset.ctoggle] = cb.checked;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="multitenant-consistency-lab"]').forEach(initMultitenantConsistencyLab);
  });
})();
