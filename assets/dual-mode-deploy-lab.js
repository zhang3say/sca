/* ==========================================================================
   可复用交互组件：一套代码三态部署拓扑、基础设施许可排雷与企业安全实验台（Lesson 0026）
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

  function initDualModeDeployLab(container) {
    const dataEl = container.querySelector("script.dual-mode-deploy-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const DEPLOY_MODES = [
      {
        id: "saas",
        label: "1. 公有云多租户 SaaS",
        sovereignty: "云端托管（L2 IR + 托管/混合代码库接入）",
        components: "Go API/Worker + Python Worker + PG(RLS) + Valkey + S3 + ClickHouse",
        licenseGate: "OpenFeature Cloud Provider（动态租户订阅与试用解锁）",
        networkFlow: "Webhook / OAuth / 云端构建拉取；出口代理强制阻断私网 SSRF",
        opsEffort: "极低（1 人 + AI 维护单个 K8s Helm Release + 托管 RDS/S3）",
        topologyLines: [
          "[GitHub/GitLab SaaS] ──Webhook/App──▶ [Go Control Plane (RLS)] ──▶ [S3 + ClickHouse]",
          "                                              │ ConnectRPC",
          "                                              ▼",
          "                                     [Python AI/ML Worker]"
        ]
      },
      {
        id: "hybrid",
        label: "2. Hybrid Runner（源码不出内网，控制面在云）",
        sovereignty: "极高（源码、密钥、大模型权重 100% 留驻客户内网）",
        components: "客户内网：Single Go Runner + 本地沙箱；云端：SaaS 控制面 + 漏洞图谱",
        licenseGate: "OpenFeature Cloud Provider + SPIFFE SVID 短命证书自动轮转",
        networkFlow: "纯出站（Outbound-Only）mTLS 通道回传脱敏 L2 IR 与摘要，云端无需入站开端口",
        opsEffort: "低（客户内网仅需一条 Docker/Helm 命令跑 Runner，漏洞库云端零延迟更新）",
        topologyLines: [
          "[客户内网 Git / 镜像 / AI 权重] ──(源码不出域)──▶ [Hybrid Runner (Go + Sandbox)]",
          "                                                         │ Outbound-Only mTLS (SPIFFE)",
          "                                                         ▼ (仅传脱敏 PURL/IR/Digest)",
          "                                            [云端控制面 + L3 情报 + Triage UI]"
        ]
      },
      {
        id: "airgapped",
        label: "3. Air-Gapped 极简离线私有化（单机 Compose / Helm）",
        sovereignty: "绝对主权（零外网连接、物理断网运行）",
        components: "Go 单体(--role=all) + Python Worker + PG + LocalFS/SeaweedFS + Valkey",
        licenseGate: "Ed25519 (RFC 8032) 本地公钥校验离线签名 License JSON，到期优雅降级",
        networkFlow: "离线 OCI Artifact 增量注入漏洞/规则包（Ref 04）；Private Rekor v2 验签",
        opsEffort: "极简（Compose 4 容器一键拉起；零 Kafka/MinIO/Redis 重型与法务雷区）",
        topologyLines: [
          "[离线 OCI U盘/内网仓] ──oras copy──▶ [Go Monolith (--role=all) + Ed25519 License]",
          "                                              │ Local Volume / SeaweedFS + Valkey",
          "                                              ▼",
          "                                     [PG(固定 DEFAULT_TENANT_ID) + Python Worker]"
        ]
      }
    ];

    const state = {
      activeTab: "deploy",
      modeId: "hybrid",
      objStore: "seaweedfs", // "seaweedfs" | "minio" | "garage"
      cacheStore: "valkey", // "valkey" | "redis8"
      webhookGuard: true,
      scimEnabled: true
    };

    function renderDeployTab() {
      const m = DEPLOY_MODES.find((x) => x.id === state.modeId) || DEPLOY_MODES[1];
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <span class="grl-control-label">选择同一套代码库的运行时交付拓扑：</span>
          <div class="grl-preset-bar" style="margin-top:0.35rem;">
            ${DEPLOY_MODES.map(
              (item) => `
                <button type="button" class="grl-pill ${state.modeId === item.id ? "active" : ""}" data-dmode="${item.id}">
                  ${escapeHtml(item.label)}
                </button>
              `
            ).join("")}
          </div>
        </div>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">客户源码/数据主权边界</div>
            <div class="grl-kpi-val" style="color:var(--ok);">${escapeHtml(m.sovereignty)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">授权与能力开关引擎</div>
            <div class="grl-kpi-val">${escapeHtml(m.licenseGate)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">网络与同步通道</div>
            <div class="grl-kpi-val" style="color:var(--accent-blue);">${escapeHtml(m.networkFlow)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Solo 运维复杂度</div>
            <div class="grl-kpi-val">${escapeHtml(m.opsEffort)}</div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">拓扑数据流图：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">${m.topologyLines.map((l) => escapeHtml(l)).join("\n")}</pre></div>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">部署组件清单（同一份核心镜像）：</div>
            <p style="font-size:0.83rem;line-height:1.62;color:var(--ink-secondary);margin:0;">${escapeHtml(m.components)}</p>
          </div>
        </div>
      `;
    }

    function renderComplianceTab() {
      const objMap = {
        seaweedfs: { ok: true, label: "SeaweedFS (Apache-2.0) / 云 S3 / 本地 FS", msg: "合规通过：纯 Apache-2.0 Go 实现，私有化离线打包与 SaaS 托管均无传染风险。" },
        minio: { ok: false, label: "MinIO 社区版 (AGPL-3.0)", msg: "红线暴雷：2021 年起改为 AGPL-3.0（且近年社区版削减管理功能）；捆绑交付或网络服务触发全栈强传染/商业违约！" },
        garage: { ok: false, label: "Garage (AGPL-3.0)", msg: "红线暴雷：Rust 轻量实现但同样采用 AGPL-3.0 网络传染协议，禁止作为商业闭源 SaaS/私有化内嵌组件！" }
      };
      const cacheMap = {
        valkey: { ok: true, label: "Valkey (BSD-3-Clause · LF 托管)", msg: "合规通过：基于 Redis 7.2.4 延续纯 BSD-3-Clause，协议与接口 100% 兼容且永无商业托管封锁。" },
        redis8: { ok: false, label: "Redis 8 (RSALv2 / SSPLv1 / AGPLv3)", msg: "红线暴雷：RSALv2/SSPLv1 非 OSI 宽松开源且限制商业竞争托管，AGPLv3 触发强网络传染！" }
      };

      const obj = objMap[state.objStore];
      const cac = cacheMap[state.cacheStore];
      const allGreen = obj.ok && cac.ok && state.webhookGuard && state.scimEnabled;

      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0.75rem;margin-bottom:0.65rem;">
            <div>
              <span class="grl-control-label">1. 对象存储（SBOM/Bundle/模型缓存）选型：</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.objStore === "seaweedfs" ? "active" : ""}" data-obj="seaweedfs">SeaweedFS / 本地FS</button>
                <button type="button" class="grl-pill ${state.objStore === "minio" ? "active" : ""}" data-obj="minio">MinIO</button>
                <button type="button" class="grl-pill ${state.objStore === "garage" ? "active" : ""}" data-obj="garage">Garage</button>
              </div>
            </div>
            <div>
              <span class="grl-control-label">2. 内存缓存 / 限流令牌桶选型：</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.cacheStore === "valkey" ? "active" : ""}" data-cac="valkey">Valkey (BSD-3)</button>
                <button type="button" class="grl-pill ${state.cacheStore === "redis8" ? "active" : ""}" data-cac="redis8">Redis 8</button>
              </div>
            </div>
          </div>

          <span class="grl-control-label">3. 企业身份与开放平台安全门禁：</span>
          <div style="display:flex;flex-direction:column;gap:0.4rem;margin-top:0.35rem;">
            <label class="grl-toggle">
              <input type="checkbox" data-ctog="scimEnabled" ${state.scimEnabled ? "checked" : ""} />
              <span><strong>RBAC × ABAC + OIDC + SCIM 2.0 (RFC 7643/7644)</strong>：员工离职自动秒级同步吊销 Token 与审批权限</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-ctog="webhookGuard" ${state.webhookGuard ? "checked" : ""} />
              <span><strong>Standard Webhooks 签名 + 出口 SSRF 阻断</strong>：<code>id.timestamp.body</code> HMAC 验签 + 封堵 <code>169.254.169.254</code>/内网 IP</span>
            </label>
          </div>
        </div>

        <div class="grl-kpi-grid" style="margin-bottom:0.85rem;">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">对象存储法务合规</div>
            <div class="grl-kpi-val" style="color:${obj.ok ? "var(--ok)" : "var(--danger)"};">${escapeHtml(obj.label)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">缓存引擎法务合规</div>
            <div class="grl-kpi-val" style="color:${cac.ok ? "var(--ok)" : "var(--danger)"};">${escapeHtml(cac.label)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">企业准入与防 SSRF</div>
            <div class="grl-kpi-val" style="color:${state.scimEnabled && state.webhookGuard ? "var(--ok)" : "var(--danger)"};">
              ${state.scimEnabled && state.webhookGuard ? "SCIM + SSRF 护栏就绪" : "存在高危权限/SSRF 缺口"}
            </div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">商业交付终审结论</div>
            <div class="grl-kpi-val" style="color:${allGreen ? "var(--ok)" : "var(--danger)"};">
              ${allGreen ? "准予上线（零法务与安全硬伤）" : "拦截退回（存在合规或安全红线）"}
            </div>
          </div>
        </div>

        <div class="grl-compare-grid is-2col">
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">存储与缓存许可诊断：</div>
            <ul style="margin:0;padding-left:1.1rem;font-size:0.81rem;line-height:1.62;color:var(--ink-secondary);">
              <li style="color:${obj.ok ? "var(--ok)" : "var(--danger)"};">${escapeHtml(obj.msg)}</li>
              <li style="color:${cac.ok ? "var(--ok)" : "var(--danger)"};">${escapeHtml(cac.msg)}</li>
            </ul>
          </div>
          <div class="grl-bar-card">
            <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.4rem;">Standard Webhooks + SSRF 防护报文头：</div>
            <div class="grl-payload-box" style="margin:0;"><pre style="margin:0;padding:0.65rem 0.85rem;font-family:var(--font-mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;max-width:100%;">webhook-id: msg_29f1a8c0
webhook-timestamp: 1795772000  (±5min window)
webhook-signature: v1,HMAC_SHA256(secret, "msg_29f1a8c0.1795772000." + rawBody)
// Dialer Control: block 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16 after DNS resolve</pre></div>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：三态部署拓扑与基础设施许可/安全审计台";
      const intro =
        config.intro ||
        "模式一对比同一套镜像在 SaaS、Hybrid Runner 与极简 Air-Gapped 间的拓扑与 Ed25519 授权切换；模式二实测对象存储、缓存许可替换以及 SCIM/Webhook SSRF 防线。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0026 · Dual-Mode Deploy Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "deploy" ? "active" : ""}" data-tab="deploy">
            <span class="grl-tab-num">1</span>
            模式一：SaaS / Hybrid / Air-Gapped 一套代码三态拓扑
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "compliance" ? "active" : ""}" data-tab="compliance">
            <span class="grl-tab-num">2</span>
            模式二：基础设施许可排雷 &amp; RBAC/SCIM/Webhook 检查
          </button>
        </div>

        ${state.activeTab === "deploy" ? renderDeployTab() : renderComplianceTab()}
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
      container.querySelectorAll("[data-dmode]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.modeId = btn.dataset.dmode;
          render();
        });
      });
      container.querySelectorAll("[data-obj]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.objStore = btn.dataset.obj;
          render();
        });
      });
      container.querySelectorAll("[data-cac]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.cacheStore = btn.dataset.cac;
          render();
        });
      });
      container.querySelectorAll("[data-ctog]").forEach((cb) => {
        cb.addEventListener("change", () => {
          state[cb.dataset.ctog] = cb.checked;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="dual-mode-deploy-lab"]').forEach(initDualModeDeployLab);
  });
})();
