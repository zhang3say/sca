/* ==========================================================================
   可复用交互组件：SLSA v1.2、in-toto DSSE 与 Sigstore 溯源闭环实验台（Lesson 0020+）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：Sigstore + SLSA v1.2 验签攻防演练台
   模式二：可信溯源与 VSA 落地方案诊断器
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

  function initProvenanceSigstoreLab(container) {
    const dataEl = container.querySelector("script.provenance-sigstore-lab-data");
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
        id: "compliant-slsa-v12",
        label: "1. 企业合规交付 (Build L3 + Source L3 + Private Sigstore)",
        desc: "制品由受保护分支触发的加固临时构建器生成，携带符合 SLSA v1.2 的 Build Provenance 与 Source VSA，采用私有 Fulcio/Rekor v2 签发 Sigstore Bundle v0.3 并随 OCI Referrers 分发。",
        digestStatus: "sha256:7617...1f4c 精确匹配策略摘要",
        oidcIdentity: "Issuer: https://oidc.corp.internal | SAN: https://git.corp.internal/platform/sca-core/.github/workflows/release.yml@refs/tags/v2.4.0",
        payloadLines: [
          '"_type": "https://in-toto.io/Statement/v1",',
          '"subject": [{"name": "oci://registry.corp.internal/sca/engine", "digest": {"sha256": "76176ffa33808b54..."}}],',
          '"predicateType": "https://slsa.dev/verification_summary/v1",',
          '"predicate": {"verifier":{"id":"https://policy.corp.internal/v1"},"verificationResult":"PASSED","verifiedLevels":["SLSA_BUILD_LEVEL_3","SLSA_SOURCE_LEVEL_3"]}',
          '// Bundle v0.3 -> DSSEv1 PAE 签名 + 私有 Fulcio OID (.1.8 / .1.9 / .1.12 / .1.21) + 私有 Rekor v2 Inclusion Proof'
        ],
        apply: { bindIdentity: true, bindDigestAndPae: true, enforcePrivateAndContinuity: true }
      },
      {
        id: "confused-deputy-fork",
        label: "2. 身份冒充 (合法公共 Fulcio 签名，但来自攻击者 Fork)",
        desc: "攻击者在自己的公开 GitHub Fork 仓库中触发 GitHub Actions 并通过公共 Fulcio/Rekor 签出完全合法的 Sigstore Bundle，企图冒充上游官方 release.yml 制品。",
        digestStatus: "sha256:99ab...c301 与恶意镜像一致（仅签名数学合法）",
        oidcIdentity: "Issuer: https://token.actions.githubusercontent.com | SAN: https://github.com/evil-fork/sca-core/.github/workflows/release.yml@refs/heads/main",
        payloadLines: [
          '// X.509 Fulcio V2 Extensions (全部数学有效!)',
          'OID 1.3.6.1.4.1.57264.1.8  (OIDC Issuer V2): "https://token.actions.githubusercontent.com"',
          'OID 1.3.6.1.4.1.57264.1.12 (Source Repo URI): "https://github.com/evil-fork/sca-core"  <-- 非官方源仓!',
          'OID 1.3.6.1.4.1.57264.1.9  (Build Signer URI): ".../evil-fork/sca-core/.github/workflows/release.yml@refs/heads/main"',
          'OID 1.3.6.1.4.1.57264.1.21 (Run Invocation URI): "https://github.com/evil-fork/sca-core/actions/runs/981234"'
        ],
        apply: { bindIdentity: true, bindDigestAndPae: true, enforcePrivateAndContinuity: true }
      },
      {
        id: "tag-drift-tamper",
        label: "3. 构建后制品调包 (:latest Tag 漂移 / Digest 失配)",
        desc: "上游确实产生过一份合法签名和 Provenance，但集群或包管理器拉取时仅指定了可变 :latest 标签；仓库侧或中间代理将镜像替换为后门版，旧 Provenance 的 subject digest 已与实际字节不符。",
        digestStatus: "失配! 实测 sha256:dead...beef != Provenance 声明 sha256:7617...1f4c",
        oidcIdentity: "Issuer: https://token.actions.githubusercontent.com | SAN: 官方 release.yml（旧版合法证明被移花接木）",
        payloadLines: [
          '// 部署清单引用: image: registry.corp.internal/app:latest  <-- 可变标签未钉死 Digest!',
          '// 攻击者替换 :latest 指向 sha256:deadbeef... 但保留旧制品的 .sigstore.json',
          'DSSE Payload: PAE("application/vnd.in-toto+json", statementBytes)',
          'statement.subject[0].digest.sha256 = "76176ffa33808b54..."  <-- sigstore-go WithArtifactDigest 比对失败!'
        ],
        apply: { bindIdentity: true, bindDigestAndPae: true, enforcePrivateAndContinuity: true }
      },
      {
        id: "public-rekor-and-continuity-break",
        label: "4. 公共 Rekor 泄密 + Source Track 连续性断链",
        desc: "闭源商业流水线误用公共 Sigstore 实例，把内部私有仓库 URI、内部工作流路径写入全球公开的 Rekor 透明度日志；同时代码仓上周曾临时关闭分支保护 2 小时，破坏 SLSA v1.2 Source Track 连续性。",
        digestStatus: "sha256:31fe...88a1 摘要匹配，但信任根与连续性双失守",
        oidcIdentity: "公开泄露至公共 Rekor: git.internal-bank.local/core-ledger/pay-svc + 员工邮箱",
        payloadLines: [
          '// 公共 Rekor 全球检索命中内部敏感元数据（不可逆永久公开!）:',
          '{"sourceRepo": "https://git.internal-bank.local/core-ledger/pay-svc", "builder": ".../deploy-prod.yml"}',
          '// SLSA v1.2 Source Track 审计记录:',
          '{"branch": "refs/heads/main", "protection_disabled_window": "2026-11-19T02:00Z..04:00Z", "continuity": "BROKEN"}'
        ],
        apply: { bindIdentity: true, bindDigestAndPae: true, enforcePrivateAndContinuity: true }
      }
    ];

    const DEPLOY_EXAMPLES = [
      {
        label: "开源公共包 (PyPI PEP 740 / npm)",
        artifactType: "oss-package",
        logMode: "public-sigstore",
        enableSourceTrack: true,
        emitVsa: false,
        kyvernoGate: false
      },
      {
        label: "闭源企业 K8s 私有化交付",
        artifactType: "closed-container",
        logMode: "private-sigstore",
        enableSourceTrack: true,
        emitVsa: true,
        kyvernoGate: true
      },
      {
        label: "AI 模型权重 + 推理容器统一溯源",
        artifactType: "ai-model-bundle",
        logMode: "private-sigstore",
        enableSourceTrack: true,
        emitVsa: true,
        kyvernoGate: true
      }
    ];

    const state = {
      activeTab: "verify", // "verify" | "deploy"
      presetId: "confused-deputy-fork",
      bindIdentity: true,
      bindDigestAndPae: true,
      enforcePrivateAndContinuity: true,
      // 模式二
      artifactType: "closed-container", // "oss-package" | "closed-container" | "ai-model-bundle"
      logMode: "public-sigstore", // "public-sigstore" | "private-sigstore"
      enableSourceTrack: true,
      emitVsa: false,
      kyvernoGate: false
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function evaluatePreset(preset) {
      let naiveVerifier;
      if (preset.id === "compliant-slsa-v12") {
        naiveVerifier = {
          tone: "is-warn",
          verdict: "看似通过 · 但缺乏 Source Track 与受众收口",
          meta: "仅验密码学签名有效",
          desc: "虽能放行合规制品，但因为未校验 VSA 的 SLSA_SOURCE_LEVEL_3 与精确 SAN 正则，遇到攻击者换仓重签时将全线失明。"
        };
      } else if (preset.id === "confused-deputy-fork") {
        naiveVerifier = {
          tone: "is-bad",
          verdict: "严重沦陷 · 放行攻击者 Fork 恶意制品!",
          meta: "只调用 verify 不锁定 Issuer + 精确 SAN",
          desc: "公共 Fulcio 为攻击者 GitHub Actions 签发了数学完全合法的证书，裸验签名直接返回 PASS，触发典型的 Confused Deputy。"
        };
      } else if (preset.id === "tag-drift-tamper") {
        naiveVerifier = {
          tone: "is-bad",
          verdict: "严重沦陷 · :latest 被调包却沿用旧签名",
          meta: "只按可变标签名取证，未绑定 sha256",
          desc: "集群拉取了被篡改的 :latest 镜像，而验证器只读了旧版 .sigstore.json 却没把实际镜像 Digest 传给 WithArtifactDigest。"
        };
      } else {
        naiveVerifier = {
          tone: "is-bad",
          verdict: "双重事故 · 私仓域名永久泄密且强推绕过失察",
          meta: "闭源连公共 Rekor + 忽略分支保护断链",
          desc: "内部仓库路径与邮箱永久公开在公共 Rekor；且只看 Build Track 忽略了主干曾被关闭保护窗口期注入的后门提交。"
        };
      }

      let strictVerifier;
      if (preset.id === "compliant-slsa-v12") {
        strictVerifier = {
          tone: "is-ok",
          verdict: "零信任放行 · Build L3 + Source L3 全闭环",
          meta: "Bundle v0.3 离线验签 + Private TUF Root",
          desc: "同时锁定制品 sha256、私有 OIDC Issuer、精确发布工作流 URI、私有 Rekor v2 包含性证明与 Source VSA，离线毫秒级准入。"
        };
      } else if (preset.id === "confused-deputy-fork") {
        if (!state.bindIdentity) {
          strictVerifier = {
            tone: "is-bad",
            verdict: "门户大开 · 已关闭 OIDC Issuer 与精确 SAN 锁定",
            meta: "未约束 CertIdentity",
            desc: "不绑定具体组织/仓库与受保护 Workflow URI，就等于信任全世界任意开源或恶意 OIDC 用户的签名。"
          };
        } else {
          strictVerifier = {
            tone: "is-ok",
            verdict: "精准拦截 · 拒绝非授权 Fork 仓库签名身份",
            meta: "OID .1.12 / .1.9 与策略预期不匹配",
            desc: "sigstore-go WithCertificateIdentity 检查出证书扩展 OID .1.12 指向 evil-fork 而非官方仓库，立即拒签阻断。"
          };
        }
      } else if (preset.id === "tag-drift-tamper") {
        if (!state.bindDigestAndPae) {
          strictVerifier = {
            tone: "is-bad",
            verdict: "失守 · 未强校验实测 Digest 与 DSSE PAE",
            meta: "跳过 WithArtifactDigest",
            desc: "验证器未将实际待部署镜像的不可变 SHA-256 摘要代入策略校验，放任旧签名背书被调包的新制品。"
          };
        } else {
          strictVerifier = {
            tone: "is-ok",
            verdict: "立即熔断 · 实际 Digest 与 DSSE Subject 失配",
            meta: "WithArtifactDigest 校验失败 + 禁可变 Tag",
            desc: "强制按 sha256 Digest 验签并与 DSSE PAE 解码后的 in-toto subject 比对，发现字节级调包后立即拒绝部署。"
          };
        }
      } else {
        if (!state.enforcePrivateAndContinuity) {
          strictVerifier = {
            tone: "is-bad",
            verdict: "合规失守 · 公共 Rekor 泄密且无视连续性断链",
            meta: "未启用私有信任根与 Source Continuity",
            desc: "私仓拓扑持续外泄至公共透明度日志，同时放行了分支保护中断窗口期内合入的未审代码。"
          };
        } else {
          strictVerifier = {
            tone: "is-ok",
            verdict: "红线阻断 · 强制切回私有 Rekor v2 并重签连续性基线",
            meta: "Private TUF Root + Source L3 Continuity Gate",
            desc: "验签策略仅信任企业私有 TUF Trusted Root（拒绝公共 Rekor 凭据），并捕获 Source VSA 连续性断裂，强制人工复核与重建。"
          };
        }
      }

      return { naiveVerifier, strictVerifier };
    }

    function renderVerifyTab() {
      const preset = getCurrentPreset();
      const res = evaluatePreset(preset);

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
          <strong>攻防推演：</strong>${escapeHtml(preset.desc)}
        </p>

        <div class="grl-layout">
          <div class="grl-controls">
            <div class="grl-control-group">
              <span class="grl-control-label">1. 零信任验签三大刚性约束开关</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="identity" ${state.bindIdentity ? "checked" : ""} />
                <span>锁定 <strong>OIDC Issuer &amp; 精确 Workflow SAN</strong>（防 Fork 冒名）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="digest" ${state.bindDigestAndPae ? "checked" : ""} />
                <span>强绑定 <strong>制品 SHA256 Digest &amp; DSSE PAE</strong>（防 Tag 调包/类型混淆）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="continuity" ${state.enforcePrivateAndContinuity ? "checked" : ""} />
                <span>启用 <strong>私有 Trusted Root + Source Continuity</strong> 连续性门禁</span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 证书身份扩展与摘要核验遥测</span>
              <div style="font-size:0.77rem;line-height:1.58;color:var(--ink-secondary);">
                <div>&bull; <strong>摘要核验：</strong><code>${escapeHtml(preset.digestStatus)}</code></div>
                <div>&bull; <strong>证书身份：</strong><code>${escapeHtml(preset.oidcIdentity)}</code></div>
                <div>&bull; <strong>信封格式：</strong><code>DSSEv1 PAE + application/vnd.in-toto+json</code></div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">
              <div class="grl-card ${res.naiveVerifier.tone}">
                <div class="grl-card-kicker">反例 · 只验数学签名 / 依赖可变标签</div>
                <div class="grl-card-title">${escapeHtml(res.naiveVerifier.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.naiveVerifier.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.naiveVerifier.desc)}</p>
              </div>

              <div class="grl-card ${res.strictVerifier.tone}">
                <div class="grl-card-kicker">推荐 · SLSA v1.2 + sigstore-go 零信任验签</div>
                <div class="grl-card-title">${escapeHtml(res.strictVerifier.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.strictVerifier.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.strictVerifier.desc)}</p>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">in-toto v1 / VSA / Fulcio OID 载荷切片</span>
                <span class="badge ${res.strictVerifier.tone === "is-ok" ? "badge-ok" : res.strictVerifier.tone === "is-warn" ? "badge-warn" : "badge-danger"}">
                  ${escapeHtml(res.strictVerifier.verdict)}
                </span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(preset.payloadLines.join("\n"))}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function evaluateDeploy() {
      const isPrivateArtifact = state.artifactType !== "oss-package";
      const leakRisk = isPrivateArtifact && state.logMode === "public-sigstore";

      let slsaLevel = "SLSA Build L3";
      if (state.enableSourceTrack) {
        slsaLevel += " + Source L3/L4";
      } else {
        slsaLevel += "（缺 Source Track 源码防篡改）";
      }

      let sovereignty = leakRisk
        ? "高危泄密! 闭源元数据直写公共 Rekor"
        : state.logMode === "private-sigstore"
          ? "私有化闭环 (Rekor v2 Tile + 私有 TUF)"
          : "开源合规 (公共 Rekor 可公开审计)";

      let offlinePerf = state.emitVsa
        ? "Sigstore Bundle v0.3 + VSA (亚毫秒离线准入)"
        : "全量原始 Provenance 递归解析（高延迟风险）";

      let badgeCls = "badge-ok";
      let verdict = "READY · 符合 SLSA v1.2 企业级可信交付基线";
      const actions = [];

      if (leakRisk) {
        badgeCls = "badge-danger";
        verdict = "BLOCK · 严禁闭源资产接入公共 Rekor 日志";
        actions.push("红线整改：闭源容器或私有 AI 权重使用公共 Sigstore 会把内部仓库地址、工作流路径与员工身份永久公开，必须部署 Private Sigstore（Fulcio + Rekor v2 Tile-backed Log + 私有 TUF Trusted Root）。");
      } else if (state.logMode === "private-sigstore") {
        actions.push("已采用 Private Sigstore（Rekor v2 Tile-backed 架构 + 私有 TUF 分发信任根），兼顾无密钥敏捷性与闭源数据主权零外泄。");
      } else {
        actions.push("开源公共包采用 Public Sigstore + Trusted Publishers（PyPI PEP 740 / npm Provenance），彻底淘汰长期静态 API Token。");
      }

      if (!state.enableSourceTrack) {
        if (badgeCls === "badge-ok") {
          badgeCls = "badge-warn";
          verdict = "WARN · 缺少 SLSA v1.2 Source Track 防线";
        }
        actions.push("补齐 Source Track（L2/L3/L4）：仅靠 Build Track 无法防范有权限的维护者绕过代码审查直接推恶意代码触发正规构建；须接入分支保护与 Two-Party Review 连续性证明。");
      } else {
        actions.push("已启用 SLSA v1.2 Source Track：验证 Onboarding & Continuity 连续性，确保受保护分支未出现保护关闭窗口期且满足双人审查。");
      }

      if (!state.emitVsa) {
        if (badgeCls === "badge-ok") {
          badgeCls = "badge-warn";
          verdict = "WARN · 缺少 VSA 预验签摘要，消费端性能受限";
        }
        actions.push("建议在企业中心策略引擎验签通过后签发 Verification Summary Attestation（slsa.dev/verification_summary/v1），避免 K8s 准入节点重复解析长依赖树。");
      } else {
        actions.push("已集成 VSA（verification_summary/v1）+ Sigstore Bundle v0.3，K8s 节点或离线客户环境无需访问外网即可秒级验证 SLSA_BUILD_LEVEL_3 与 SLSA_SOURCE_LEVEL_3。");
      }

      if (state.artifactType === "ai-model-bundle") {
        actions.push("AI 权重与容器协同：使用 sigstore/model-transparency（Apache-2.0）对 Safetensors / ModelPack 权重哈希签发 Bundle，并与 Lesson 0017 AI-BOM 及 Lesson 0018 序列化扫描结果共同写入 OCI Referrers。");
      }

      if (state.kyvernoGate && isPrivateArtifact) {
        actions.push("运行时最后一公里已启用 Kyverno（Apache-2.0）verifyImages 准入拦截，仅放行具备有效私有 Sigstore 签名及 VSA PASSED 的 Digest 镜像。");
      } else if (!state.kyvernoGate && isPrivateArtifact) {
        actions.push("建议在生产 K8s 集群补充 Kyverno（Apache-2.0）图像验证策略，否则即便 CI 产出了全套证明，运行侧依然可能被人工 kubectl apply 绕过。");
      }

      return { slsaLevel, sovereignty, offlinePerf, badgeCls, verdict, actions };
    }

    function renderDeployOutput() {
      const r = evaluateDeploy();
      return `
        <div class="grl-impact-panel" style="margin-bottom:0.85rem;">
          <div class="grl-impact-head">
            <span>SLSA v1.2 + Sigstore 企业溯源架构评估</span>
            <span class="badge ${r.badgeCls}">${escapeHtml(r.verdict)}</span>
          </div>
          <div class="grl-impact-list">
            <div class="grl-impact-item ${r.badgeCls === "badge-ok" ? "is-clear" : "is-hit"}">
              <strong>达标水位：</strong>${escapeHtml(r.slsaLevel)}
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">SLSA v1.2 覆盖轨道</div>
            <div class="grl-kpi-val">${escapeHtml(r.slsaLevel)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">透明度日志与数据主权</div>
            <div class="grl-kpi-val" style="color:${r.badgeCls === "badge-danger" ? "var(--danger)" : "var(--ok)"};">${escapeHtml(r.sovereignty)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">离线验签与 VSA 形态</div>
            <div class="grl-kpi-val">${escapeHtml(r.offlinePerf)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">核心开源许可底座</div>
            <div class="grl-kpi-val" style="color:var(--ok);">全栈 Apache-2.0</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">架构落地与防线补齐建议：</div>
          <ul style="margin:0;padding-left:1.1rem;font-size:0.8rem;line-height:1.58;color:var(--ink-secondary);">
            ${r.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    function renderDeployTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div class="grl-preset-bar" style="margin-bottom:0.45rem;">
            ${DEPLOY_EXAMPLES.map(
              (ex, idx) => `
                <button type="button" class="grl-pill" data-deployex="${idx}">
                  载入蓝图：${escapeHtml(ex.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">交付制品类型</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.artifactType === "oss-package" ? "active" : ""}" data-atype="oss-package">开源包 (PyPI/npm)</button>
                <button type="button" class="grl-pill ${state.artifactType === "closed-container" ? "active" : ""}" data-atype="closed-container">闭源容器镜像</button>
                <button type="button" class="grl-pill ${state.artifactType === "ai-model-bundle" ? "active" : ""}" data-atype="ai-model-bundle">AI 模型权重+镜像</button>
              </div>

              <span class="grl-control-label" style="margin-top:0.65rem;display:block;">Sigstore 信任根与日志部署模式</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.logMode === "public-sigstore" ? "active" : ""}" data-lmode="public-sigstore">Public Sigstore (公网 Rekor)</button>
                <button type="button" class="grl-pill ${state.logMode === "private-sigstore" ? "active" : ""}" data-lmode="private-sigstore">Private Sigstore (Rekor v2 + 私有 TUF)</button>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.42rem;">
              <span class="grl-control-label">规范闭环与运行时门禁选项</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="srctrack" ${state.enableSourceTrack ? "checked" : ""} />
                <span>启用 <strong>SLSA v1.2 Source Track</strong>（保护分支连续性 + 双人审查）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="vsa" ${state.emitVsa ? "checked" : ""} />
                <span>策略验签后签发 <strong>VSA (<code>verification_summary/v1</code>)</strong> + Bundle v0.3</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="kyverno" ${state.kyvernoGate ? "checked" : ""} />
                <span>生产集群挂载 <strong>Kyverno (<code>Apache-2.0</code>)</strong> 强制验签准入</span>
              </label>
            </div>
          </div>
        </div>

        <div class="grl-psl-deploy-out">${renderDeployOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：Sigstore 零信任验签演练与 SLSA v1.2 蓝图诊断";
      const intro =
        config.intro ||
        "在模式一中切入 4 大真伪溯源场景验证 Identity/Digest/Continuity 绑定；在模式二中评估公私 Rekor 数据主权与 VSA 离线准入方案。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0020 · SLSA v1.2 &amp; Sigstore Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "verify" ? "active" : ""}" data-tab="verify">
            <span class="grl-tab-num">1</span>
            模式一：Sigstore 身份绑定、Digest 校验与 Source 断链演练
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "deploy" ? "active" : ""}" data-tab="deploy">
            <span class="grl-tab-num">2</span>
            模式二：公私 Rekor 数据主权、VSA 签发与准入网关诊断
          </button>
        </div>

        ${state.activeTab === "verify" ? renderVerifyTab() : renderDeployTab()}
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
          if (t === "identity") state.bindIdentity = cb.checked;
          if (t === "digest") state.bindDigestAndPae = cb.checked;
          if (t === "continuity") state.enforcePrivateAndContinuity = cb.checked;
          if (t === "srctrack") state.enableSourceTrack = cb.checked;
          if (t === "vsa") state.emitVsa = cb.checked;
          if (t === "kyverno") state.kyvernoGate = cb.checked;
          render();
        });
      });

      container.querySelectorAll("[data-deployex]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ex = DEPLOY_EXAMPLES[Number(btn.dataset.deployex)];
          if (!ex) return;
          state.artifactType = ex.artifactType;
          state.logMode = ex.logMode;
          state.enableSourceTrack = ex.enableSourceTrack;
          state.emitVsa = ex.emitVsa;
          state.kyvernoGate = ex.kyvernoGate;
          render();
        });
      });

      container.querySelectorAll("[data-atype]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.artifactType = btn.dataset.atype;
          render();
        });
      });

      container.querySelectorAll("[data-lmode]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.logMode = btn.dataset.lmode;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="provenance-sigstore-lab"]')
      .forEach(initProvenanceSigstoreLab);
  });
})();
