/* ==========================================================================
   Reusable Interactive Component: Prioritization (EPSS/KEV/SSVC) & VEX Lab
   Zero-dependency vanilla JS for Lesson 0013+.
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

  function estimateEpssPercentile(epssPct) {
    if (epssPct >= 70) return 99.7;
    if (epssPct >= 40) return 99.1;
    if (epssPct >= 20) return 97.6;
    if (epssPct >= 10) return 95.2;
    if (epssPct >= 5) return 91.5;
    if (epssPct >= 1) return 79.0;
    if (epssPct >= 0.4) return 58.0;
    return 28.0;
  }

  function initPrioritizationVexLab(container) {
    const dataEl = container.querySelector("script.prioritization-vex-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const state = {
      activeTab: "triage", // "triage" | "funnel"
      presetId: "high-cvss-dead-code",
      // Tab 1 controls
      cvss: 9.8,
      epssPct: 62.0,
      kevStatus: "none", // "none" | "kev" | "kev_ransomware"
      reachability: "VERIFIED_UNREACHABLE", // "CONFIRMED_EXPLOITABLE" | "REACHABLE" | "LATENT_REACHABLE" | "POTENTIALLY_REACHABLE" | "VERIFIED_UNREACHABLE"
      exposure: "internal_key", // "internet_core" | "internal_key" | "isolated_batch"
      vexSource: "internal_verified", // "none" | "community_unsigned" | "vendor_signed" | "internal_verified"
      vexFormat: "openvex", // "openvex" | "cyclonedx" | "csaf"
      // Tab 2 controls
      totalCves: 1000,
      useReachability: true,
      useThreatSsvc: true,
      useVexLedger: true,
      epssThreshold: 10, // 5 | 10 | 20
      activeTriggerId: "cg-changed",
    };

    const PRESETS = [
      {
        id: "high-cvss-dead-code",
        label: "1. 高 CVSS 死代码陷阱",
        apply: {
          cvss: 9.8,
          epssPct: 62.0,
          kevStatus: "none",
          reachability: "VERIFIED_UNREACHABLE",
          exposure: "internal_key",
          vexSource: "internal_verified",
        },
      },
      {
        id: "low-cvss-kev-ransomware",
        label: "2. 低 CVSS + KEV 勒索反杀",
        apply: {
          cvss: 5.3,
          epssPct: 78.0,
          kevStatus: "kev_ransomware",
          reachability: "REACHABLE",
          exposure: "internet_core",
          vexSource: "none",
        },
      },
      {
        id: "low-epss-latent-reachable",
        label: "3. 低 EPSS 潜伏可达护栏",
        apply: {
          cvss: 8.8,
          epssPct: 0.4,
          kevStatus: "none",
          reachability: "LATENT_REACHABLE",
          exposure: "internet_core",
          vexSource: "none",
        },
      },
      {
        id: "vex-conflict-safety-floor",
        label: "4. 外部 VEX 冲突底线拦截",
        apply: {
          cvss: 9.1,
          epssPct: 45.0,
          kevStatus: "none",
          reachability: "CONFIRMED_EXPLOITABLE",
          exposure: "internet_core",
          vexSource: "community_unsigned",
        },
      },
    ];

    const KEV_OPTIONS = [
      { id: "none", label: "无 KEV" },
      { id: "kev", label: "在 KEV 目录" },
      { id: "kev_ransomware", label: "KEV + 勒索已知" },
    ];

    const REACH_OPTIONS = [
      { id: "CONFIRMED_EXPLOITABLE", label: "CONFIRMED_EXPLOITABLE" },
      { id: "REACHABLE", label: "REACHABLE" },
      { id: "LATENT_REACHABLE", label: "LATENT_REACHABLE" },
      { id: "POTENTIALLY_REACHABLE", label: "POTENTIALLY_REACHABLE" },
      { id: "VERIFIED_UNREACHABLE", label: "VERIFIED_UNREACHABLE" },
    ];

    const EXPOSURE_OPTIONS = [
      { id: "internet_core", label: "公网核心业务" },
      { id: "internal_key", label: "内网关键服务" },
      { id: "isolated_batch", label: "离线隔离批处理" },
    ];

    const VEX_SOURCE_OPTIONS = [
      { id: "none", label: "无 VEX 声明" },
      { id: "community_unsigned", label: "社区 VEX Hub（未签名）" },
      { id: "vendor_signed", label: "上游厂商签名 VEX" },
      { id: "internal_verified", label: "本平台实证签发 VEX" },
    ];

    const TRIGGERS = [
      {
        id: "cg-changed",
        title: "1. 代码提交变更调用图",
        eventName: "CODE_REACHABILITY_CHANGED",
        oldState: "not_affected (code_not_reachable)",
        newState: "REVOKED -> under_investigation / affected",
        action: "PR 新增导入并连通原漏洞 Sink；Ledger 自动将旧 VEX 标记为 REVOKED 并生成带新 commit_sha 的新事件，阻断当前 PR 合并。",
      },
      {
        id: "runtime-loaded",
        title: "2. 运行态捕获类加载",
        eventName: "RUNTIME_SIGNAL_DETECTED",
        oldState: "not_affected (code_not_reachable)",
        newState: "REVOKED -> affected (STATIC_SOUNDNESS_ALERT)",
        action: "JFR jdk.ClassLoad 或 eBPF 在生产 Pod 捕获到原判不可达的漏洞类装载；立即撤销旧 VEX，升为 P0 Act 并向 L4 引擎提报缺失调用边。",
      },
      {
        id: "kev-added",
        title: "3. 漏洞新入 CISA KEV",
        eventName: "THREAT_KEV_ADDED",
        oldState: "deferred / low-priority Track*",
        newState: "ESCALATED -> Act (SLA <= 24h~72h)",
        action: "虽不直接推翻严格实证的 code_not_reachable，但所有 LATENT_REACHABLE / POTENTIALLY_REACHABLE / 人工缓解项强制重新进入 SSVC Act 复核队列。",
      },
      {
        id: "epss-spike",
        title: "4. EPSS 单周飙升 >=20%",
        eventName: "THREAT_EPSS_SPIKE",
        oldState: "Track / Track* (低概率观察)",
        newState: "ESCALATED -> Attend / Act",
        action: "每日同步的 FIRST EPSS CSV 检测到 7 天 delta >= +20%（通常伴随公开 PoC 或野战扫描出现），触发异步重算流水线并通知服务 Owner。",
      },
      {
        id: "ttl-expired",
        title: "5. 人工缓解 TTL 到期",
        eventName: "MANUAL_WAIVER_EXPIRED",
        oldState: "not_affected (inline_mitigations_already_exist)",
        newState: "EXPIRED -> under_investigation",
        action: "WAF/配置缓解型人工 VEX 强制绑定 30~90 天 TTL（expires_at）；到期未续签则自动失效并重新暴露于发布门禁，杜绝“永久静默黑洞”。",
      },
    ];

    function evaluateTraditionalCvss() {
      if (state.cvss >= 7.0) {
        return {
          tone: state.reachability === "VERIFIED_UNREACHABLE" ? "is-warn" : "is-bad",
          verdict: "P0 阻断发布 / 紧急修复",
          meta: `CVSS-B = ${state.cvss.toFixed(1)} (>= 7.0 阈值)`,
          desc:
            state.reachability === "VERIFIED_UNREACHABLE"
              ? "盲区：只看抽象严重性 CVSS-B，把死代码或不可达函数也一刀切阻断，引发严重告警疲劳。"
              : "虽然命中阻断，但无法区分在野利用概率与暴露面，和上百条死代码高危混在一起。",
        };
      }
      return {
        tone: state.kevStatus !== "none" ? "is-bad" : "is-ok",
        verdict: "忽略放行（不阻断）",
        meta: `CVSS-B = ${state.cvss.toFixed(1)} (< 7.0 阈值)`,
        desc:
          state.kevStatus !== "none"
            ? "致命漏杀！低 CVSS 漏洞已被 CISA KEV 收录或用于勒索软件，传统静态阈值直接放行进生产。"
            : "低于 7.0 阈值即默认忽略，若后续 EPSS 飙升或进入 KEV 缺乏自动升级机制。",
      };
    }

    function evaluateLinearWeighted() {
      const reachWeight = {
        CONFIRMED_EXPLOITABLE: 10,
        REACHABLE: 8.5,
        LATENT_REACHABLE: 7.0,
        POTENTIALLY_REACHABLE: 5.0,
        VERIFIED_UNREACHABLE: 0.5,
      }[state.reachability];
      const kevBonus = state.kevStatus === "kev_ransomware" ? 10 : state.kevStatus === "kev" ? 8 : 0;
      const expWeight = state.exposure === "internet_core" ? 10 : state.exposure === "internal_key" ? 6 : 2;
      const epssNorm = Math.min(10, (state.epssPct / 100) * 10);
      const score =
        0.3 * state.cvss +
        0.25 * epssNorm +
        0.2 * kevBonus +
        0.15 * reachWeight +
        0.1 * expWeight;

      let tier = "低危观察";
      let tone = "is-ok";
      if (score >= 7.0) {
        tier = "高优紧急";
        tone = "is-bad";
      } else if (score >= 4.5) {
        tier = "中危排期";
        tone = "is-warn";
      }

      let flaw = "线性加权存在「补偿掩蔽」缺陷：高维度会把零可达性或无利用维度的信号平均掉。";
      if (state.reachability === "VERIFIED_UNREACHABLE" && score >= 4.5) {
        flaw = `补偿掩蔽反模式：函数已证不可达，但高 CVSS(${state.cvss.toFixed(1)}) + 高 EPSS 硬把总分拉到 ${score.toFixed(1)}，依然误报。`;
      } else if (state.kevStatus !== "none" && score < 7.0) {
        flaw = `补偿掩蔽反模式：低 CVSS(${state.cvss.toFixed(1)}) 拉低了 KEV 实战在野利用权重，总分仅 ${score.toFixed(1)}，险些降级延误。`;
      }

      return {
        tone,
        verdict: `${tier} · 加权分 ${score.toFixed(1)} / 10`,
        meta: "0.30*CVSS + 0.25*EPSS + 0.20*KEV + 0.15*Reach + 0.10*Exp",
        desc: flaw,
      };
    }

    function evaluateSsvcAndVex() {
      const hardReachable =
        state.reachability === "CONFIRMED_EXPLOITABLE" ||
        state.reachability === "REACHABLE" ||
        state.reachability === "LATENT_REACHABLE";
      const externalNotAffectedClaim =
        state.vexSource === "community_unsigned" || state.vexSource === "vendor_signed";

      // 1. Safety Floor: hard evidence overrides any external VEX claim
      if (hardReachable && externalNotAffectedClaim) {
        return {
          tone: "is-bad",
          ssvc: "Act（P0 立即阻断）",
          sla: "24–72 小时（触发 Safety Floor）",
          vexDecision: "REJECTED_VEX_CONFLICT（驳回外部 VEX 豁免）",
          reason:
            "安全底线拦截：L4 静态/运行态已证实代码路径可达（或已执行），外部/社区 VEX 声称 not_affected 被强行驳回，升级 P0 Act 并记录信任冲突告警。",
          canAutoIssueVex: false,
          vexStatus: "affected",
          vexJustification: null,
        };
      }

      // 2. Verified Unreachable -> Track + eligible for internal VEX
      if (state.reachability === "VERIFIED_UNREACHABLE") {
        return {
          tone: "is-ok",
          ssvc: "Track（可审计降噪）",
          sla: "常规周期 / 已豁免",
          vexDecision:
            state.vexSource === "internal_verified" || state.vexSource === "vendor_signed"
              ? "VALID_NOT_AFFECTED（VEX 生效消警）"
              : "AUTO_ISSUE_ELIGIBLE（可由本平台签发 VEX）",
          reason:
            "静动态双证不可达（Lesson 0011+0012）：无论 CVSS/EPSS 多高，死代码路径可安全压降至 Track，并自动签发带 CallGraph/Runtime 证据摘要的 VEX not_affected。",
          canAutoIssueVex: true,
          vexStatus: "not_affected",
          vexJustification: "vulnerable_code_not_in_execute_path",
        };
      }

      // 3. Active Exploitation Floor: KEV or high EPSS + Reachable
      const activeExploit =
        state.kevStatus !== "none" || state.epssPct >= 20.0;
      const pocLikely = state.epssPct >= 5.0 || state.cvss >= 8.5;

      if (
        (state.kevStatus !== "none" && state.reachability !== "VERIFIED_UNREACHABLE") ||
        (state.reachability === "CONFIRMED_EXPLOITABLE" && (activeExploit || state.exposure === "internet_core")) ||
        (state.reachability === "REACHABLE" && activeExploit && state.exposure !== "isolated_batch")
      ) {
        return {
          tone: "is-bad",
          ssvc: "Act（P0 阻断合并与发布）",
          sla: state.kevStatus === "kev_ransomware" ? "<= 24 小时（勒索 KEV）" : "<= 72 小时",
          vexDecision: "VEX_PROHIBITED（严禁签发豁免）",
          reason:
            state.kevStatus !== "none"
              ? "KEV 在野实证底线命中：即使 CVSS 偏低，只要存在真实在野利用且非不可达，SSVC 非补偿决策树直接锁定 Act。"
              : "高在野概率/已实证可达 + 核心暴露面命中 Act 路径，直接进入 Lesson 0014 自动修复队列。",
          canAutoIssueVex: false,
          vexStatus: "affected",
          vexJustification: null,
        };
      }

      // 4. Valid Tier 1/2 VEX for non-hard-reachable states (matches EvaluatePriorityAndVEX)
      if (
        state.reachability === "POTENTIALLY_REACHABLE" &&
        state.kevStatus === "none" &&
        (state.vexSource === "vendor_signed" || state.vexSource === "internal_verified")
      ) {
        return {
          tone: "is-ok",
          ssvc: "Track（可审计降噪）",
          sla: "常规周期 / 已豁免",
          vexDecision: "VALID_EXTERNAL_VEX（Tier 1/2 VEX 生效）",
          reason:
            "静态存疑且未命中 KEV，经已验签上游厂商或本平台内审 VEX 确认不受影响（非 Tier 0 硬可达冲突），安全压降至 Track 并保留审计账本。",
          canAutoIssueVex: false,
          vexStatus: "not_affected",
          vexJustification: "vulnerable_code_not_in_execute_path",
        };
      }

      // 4. Low EPSS but Reachable/Latent -> Attend (never auto-VEX!)
      if (
        state.reachability === "LATENT_REACHABLE" ||
        state.reachability === "REACHABLE" ||
        (state.reachability === "POTENTIALLY_REACHABLE" && (pocLikely || state.exposure === "internet_core"))
      ) {
        return {
          tone: "is-warn",
          ssvc: "Attend（P1/P2 排期修复）",
          sla: state.exposure === "internet_core" ? "<= 7 天" : "<= 14 天",
          vexDecision: "NO_AUTO_VEX（低 EPSS 绝非豁免理由）",
          reason:
            state.epssPct < 1.0
              ? "低 EPSS 护栏生效：30 天利用概率低仅说明“近期大概率还没被大规模扫描”，不代表路径不可达！严禁因低 EPSS 自动签发 VEX，定级 Attend 正常排期。"
              : "路径可达或静态存疑且具公网暴露/潜在利用风险，定级 Attend，优先纳入常规迭代修复。",
          canAutoIssueVex: false,
          vexStatus: "under_investigation",
          vexJustification: null,
        };
      }

      return {
        tone: "is-info",
        ssvc: "Track*（P3 增强监控）",
        sla: "<= 30 天（监听 EPSS/KEV 异动）",
        vexDecision: "WATCHLIST_ONLY（待观测或待确认）",
        reason:
          "当前未在公网核心路径实证触发且 EPSS 较低，归入 Track* 增强监控；若后续 EPSS 飙升或入 KEV 将自动升级。",
        canAutoIssueVex: false,
        vexStatus: "under_investigation",
        vexJustification: null,
      };
    }

    function buildVexPreview(ssvcResult) {
      const cveId = state.kevStatus !== "none" ? "CVE-2026-41082" : "CVE-2026-39210";
      const productPurl = "pkg:oci/checkout-api@sha256:9f86d081884c7d659a2feaa0c55ad015";
      const subPurl = "pkg:golang/github.com/example/codec@v1.4.2";
      const isNotAffected = ssvcResult.vexStatus === "not_affected";
      const cdxState = isNotAffected
        ? "not_affected"
        : ssvcResult.vexStatus === "affected"
        ? "exploitable"
        : "in_triage";
      const csafGroup = isNotAffected
        ? "known_not_affected"
        : ssvcResult.vexStatus === "affected"
        ? "known_affected"
        : "under_investigation";

      const detailMsg = isNotAffected
        ? "L4 Static VTA + 14d JFR/eBPF confirmed vulnerable symbol unreachable from entrypoints."
        : ssvcResult.vexDecision.indexOf("REJECTED") === 0
        ? "Safety Floor Override: external VEX rejected due to confirmed reachable call path."
        : "SSVC triage active; low EPSS or potential edge cannot suppress reachable path.";

      if (state.vexFormat === "openvex") {
        const doc = {
          "@context": "https://openvex.dev/ns/v0.2.0",
          "@id": "https://sca.internal/vex/2026-11-24/stmt-0192",
          author: "Platform Layer-4 Governance Engine",
          timestamp: "2026-11-24T08:30:00Z",
          version: 1,
          statements: [
            {
              vulnerability: { name: cveId },
              products: [
                {
                  "@id": productPurl,
                  subcomponents: [{ "@id": subPurl }],
                },
              ],
              status: ssvcResult.vexStatus,
              ...(isNotAffected
                ? {
                    justification: ssvcResult.vexJustification,
                    impact_statement: detailMsg,
                  }
                : {
                    action_statement: detailMsg,
                    action_statement_timestamp: "2026-11-24T08:30:00Z",
                  }),
            },
          ],
        };
        return JSON.stringify(doc, null, 2);
      }

      if (state.vexFormat === "cyclonedx") {
        const doc = {
          bomFormat: "CycloneDX",
          specVersion: "1.7",
          serialNumber: "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
          version: 1,
          metadata: {
            component: {
              "bom-ref": productPurl,
              type: "container",
              name: "checkout-api",
              purl: productPurl,
            },
          },
          components: [
            {
              "bom-ref": subPurl,
              type: "library",
              name: "github.com/example/codec",
              version: "v1.4.2",
              purl: subPurl,
            },
          ],
          vulnerabilities: [
            {
              id: cveId,
              analysis: {
                state: cdxState,
                ...(isNotAffected
                  ? { justification: "code_not_reachable" }
                  : {}),
                response: isNotAffected ? ["will_not_fix"] : ["update"],
                detail: detailMsg,
              },
              affects: [{ ref: subPurl }],
            },
          ],
        };
        return JSON.stringify(doc, null, 2);
      }

      // CSAF 2.0 VEX
      const csafDoc = {
        document: {
          category: "csaf_vex",
          csaf_version: "2.0",
          title: `VEX Advisory for ${cveId}`,
          publisher: {
            category: "vendor",
            name: "Platform Security Governance",
            namespace: "https://sca.internal/security",
          },
          tracking: {
            id: "SCA-VEX-2026-0192",
            status: "final",
            version: "1",
            initial_release_date: "2026-11-24T08:30:00Z",
            current_release_date: "2026-11-24T08:30:00Z",
          },
        },
        product_tree: {
          full_product_names: [
            {
              product_id: "CSAFPID-0001",
              name: "checkout-api container image",
              product_identification_helper: { purl: productPurl },
            },
          ],
        },
        vulnerabilities: [
          {
            cve: cveId,
            product_status: {
              [csafGroup]: ["CSAFPID-0001"],
            },
            ...(isNotAffected
              ? {
                  flags: [
                    {
                      label: "vulnerable_code_not_in_execute_path",
                      product_ids: ["CSAFPID-0001"],
                    },
                  ],
                }
              : {}),
          },
        ],
      };
      return JSON.stringify(csafDoc, null, 2);
    }

    function computeFunnelStats() {
      const N = state.totalCves; // e.g., 1000
      // Baseline composition of 1000 raw CVEs in a typical enterprise container+app estate:
      // 420 High/Crit (CVSS >= 7.0), 580 Med/Low (CVSS < 7.0), including 8 KEV items where 2 have CVSS < 7.0
      const cvssHighCount = Math.round(N * 0.42);
      const totalKev = 8;
      const missedKevByCvss = 2; // low-CVSS KEVs missed by CVSS >= 7.0 gate

      let remainingActionable = N;
      let reachEliminated = 0;
      let threatDeferred = 0;
      let vexAudited = 0;

      if (state.useReachability) {
        // Static + runtime reachability proves ~68% unreachable (app dead code + inactive OS pkgs)
        reachEliminated = Math.round(N * 0.68);
        remainingActionable -= reachEliminated;
      }

      if (state.useVexLedger) {
        // VEX ledger formally seals unreachable + upstream verified not_affected with audit trail
        if (state.useReachability) {
          vexAudited = reachEliminated;
        } else {
          vexAudited = Math.round(N * 0.14);
          remainingActionable = Math.max(totalKev, remainingActionable - vexAudited);
        }
      }

      if (state.useThreatSsvc) {
        // Among remaining reachable/potentially-reachable items, EPSS threshold separates immediate Act vs Attend/Track*
        const passRatio =
          state.epssThreshold === 5 ? 0.24 : state.epssThreshold === 10 ? 0.16 : 0.11;
        const p0Act = Math.max(totalKev, Math.round(remainingActionable * passRatio));
        threatDeferred = remainingActionable - p0Act;
        remainingActionable = p0Act;
      }

      const noiseDropPct = (((N - remainingActionable) / N) * 100).toFixed(1);

      return {
        N,
        cvssHighCount,
        totalKev,
        missedKevByCvss,
        reachEliminated,
        threatDeferred,
        vexAudited,
        remainingActionable,
        noiseDropPct,
      };
    }

    function renderTriageOutput() {
      const trad = evaluateTraditionalCvss();
      const lin = evaluateLinearWeighted();
      const ssvc = evaluateSsvcAndVex();
      const jsonText = buildVexPreview(ssvc);

      return `
        <div class="pvl-verdict-compare">
          <div class="pvl-verdict-card ${trad.tone}">
            <div class="pvl-verdict-kicker">反例 A · 传统 CVSS 门禁</div>
            <div class="pvl-verdict-title">${escapeHtml(trad.verdict)}</div>
            <div class="pvl-verdict-meta">${escapeHtml(trad.meta)}</div>
            <p class="pvl-verdict-desc">${escapeHtml(trad.desc)}</p>
          </div>

          <div class="pvl-verdict-card ${lin.tone}">
            <div class="pvl-verdict-kicker">反例 B · 线性加权平均</div>
            <div class="pvl-verdict-title">${escapeHtml(lin.verdict)}</div>
            <div class="pvl-verdict-meta">${escapeHtml(lin.meta)}</div>
            <p class="pvl-verdict-desc">${escapeHtml(lin.desc)}</p>
          </div>

          <div class="pvl-verdict-card ${ssvc.tone}">
            <div class="pvl-verdict-kicker">推荐 · SSVC 非补偿 + VEX</div>
            <div class="pvl-verdict-title">${escapeHtml(ssvc.ssvc)}</div>
            <div class="pvl-verdict-meta">SLA: ${escapeHtml(ssvc.sla)}</div>
            <p class="pvl-verdict-desc"><strong>${escapeHtml(ssvc.vexDecision)}</strong>：${escapeHtml(ssvc.reason)}</p>
          </div>
        </div>

        <div class="pvl-code-box">
          <div class="pvl-code-head">
            <span class="pvl-code-head-title">Layer 2 账本实时三协议投影（注意 PURL subcomponents 与枚举差异）</span>
            <div class="pvl-format-tabs">
              <button type="button" class="pvl-format-tab ${state.vexFormat === "openvex" ? "active" : ""}" data-format="openvex">OpenVEX v0.2</button>
              <button type="button" class="pvl-format-tab ${state.vexFormat === "cyclonedx" ? "active" : ""}" data-format="cyclonedx">CycloneDX 1.7</button>
              <button type="button" class="pvl-format-tab ${state.vexFormat === "csaf" ? "active" : ""}" data-format="csaf">CSAF 2.0 VEX</button>
            </div>
          </div>
          <pre class="pvl-code-pre">${escapeHtml(jsonText)}</pre>
        </div>
      `;
    }

    function bindFormatTabs() {
      container.querySelectorAll("[data-format]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.vexFormat = btn.dataset.format;
          updateTriageOutput();
        });
      });
    }

    function updateTriageOutput() {
      const outEl = container.querySelector(".pvl-triage-output");
      if (!outEl) return;
      outEl.innerHTML = renderTriageOutput();
      bindFormatTabs();
    }

    function renderTriageTab() {
      const percentile = estimateEpssPercentile(state.epssPct);

      return `
        <div class="pvl-presets">
          ${PRESETS.map(
            (p) => `
              <button type="button" class="pvl-preset-btn ${state.presetId === p.id ? "active" : ""}" data-preset="${p.id}">
                ${escapeHtml(p.label)}
              </button>
            `
          ).join("")}
        </div>

        <div class="pvl-grid">
          <div class="pvl-controls">
            <div class="pvl-control-group">
              <div class="pvl-slider-row">
                <div class="pvl-slider-head">
                  <span class="pvl-control-label">1. CVSS-B 基础严重性分（0.0–10.0）</span>
                  <strong data-readout="cvss">${state.cvss.toFixed(1)}</strong>
                </div>
                <input type="range" class="pvl-slider" data-slider="cvss" min="3.0" max="10.0" step="0.1" value="${state.cvss}" />
                <span class="pvl-slider-sub">CVSS-B 默认假设最坏威胁态（E:A），仅反映潜在破坏力而非利用概率。</span>
              </div>
            </div>

            <div class="pvl-control-group">
              <div class="pvl-slider-row">
                <div class="pvl-slider-head">
                  <span class="pvl-control-label">2. FIRST EPSS v4（30 天在野利用概率）</span>
                  <strong data-readout="epss">${state.epssPct.toFixed(1)}% <span style="color:var(--ink-muted);font-weight:500;">(≈ 第 ${percentile.toFixed(1)} 百分位)</span></strong>
                </div>
                <input type="range" class="pvl-slider" data-slider="epss" min="0.1" max="95.0" step="0.1" value="${state.epssPct}" />
                <span class="pvl-slider-sub">警戒：Percentile（分位数）≠ Probability（绝对概率）！0.4% 概率仍排全库前 ~42%。</span>
              </div>
            </div>

            <div class="pvl-control-group">
              <span class="pvl-control-label">3. CISA KEV 实战在野目录与勒索情报</span>
              <div class="pvl-pill-group">
                ${KEV_OPTIONS.map(
                  (opt) => `
                    <button type="button" class="pvl-pill ${state.kevStatus === opt.id ? "active" : ""}" data-kev="${opt.id}">
                      ${escapeHtml(opt.label)}
                    </button>
                  `
                ).join("")}
              </div>
            </div>

            <div class="pvl-control-group">
              <span class="pvl-control-label">4. L4 静动态可达性融合态（Lesson 0011–0012）</span>
              <div class="pvl-pill-group">
                ${REACH_OPTIONS.map(
                  (opt) => `
                    <button type="button" class="pvl-pill ${state.reachability === opt.id ? "active" : ""}" data-reach="${opt.id}">
                      ${escapeHtml(opt.label)}
                    </button>
                  `
                ).join("")}
              </div>
            </div>

            <div class="pvl-control-group">
              <span class="pvl-control-label">5. 资产暴露面与业务权重</span>
              <div class="pvl-pill-group">
                ${EXPOSURE_OPTIONS.map(
                  (opt) => `
                    <button type="button" class="pvl-pill ${state.exposure === opt.id ? "active" : ""}" data-exposure="${opt.id}">
                      ${escapeHtml(opt.label)}
                    </button>
                  `
                ).join("")}
              </div>
            </div>

            <div class="pvl-control-group">
              <span class="pvl-control-label">6. VEX 声明来源（检验 Safety Floor 冲突裁决）</span>
              <div class="pvl-pill-group">
                ${VEX_SOURCE_OPTIONS.map(
                  (opt) => `
                    <button type="button" class="pvl-pill ${state.vexSource === opt.id ? "active" : ""}" data-vex-source="${opt.id}">
                      ${escapeHtml(opt.label)}
                    </button>
                  `
                ).join("")}
              </div>
            </div>
          </div>

          <div class="pvl-triage-output">${renderTriageOutput()}</div>
        </div>
      `;
    }

    function renderFunnelTab() {
      const stats = computeFunnelStats();
      const activeTrigger =
        TRIGGERS.find((t) => t.id === state.activeTriggerId) || TRIGGERS[0];

      const pct = (v) => ((v / stats.N) * 100).toFixed(1);

      return `
        <div class="pvl-controls" style="margin-bottom:0.9rem;">
          <div style="display:flex;flex-wrap:wrap;gap:0.75rem 1.4rem;align-items:center;">
            <label class="rrl-toggle-label">
              <input type="checkbox" data-funnel-toggle="reach" ${state.useReachability ? "checked" : ""} />
              启用 L4 静动态可达性过滤（消除 ~68% 死代码与休眠 OS 包）
            </label>
            <label class="rrl-toggle-label">
              <input type="checkbox" data-funnel-toggle="threat" ${state.useThreatSsvc ? "checked" : ""} />
              启用 EPSS + KEV + SSVC 非补偿分级（区分 Act vs Attend/Track*）
            </label>
            <label class="rrl-toggle-label">
              <input type="checkbox" data-funnel-toggle="vex" ${state.useVexLedger ? "checked" : ""} />
              启用不可变 VEX 账本自动签发与跨团队豁免流转
            </label>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:0.65rem;align-items:center;padding-top:0.45rem;border-top:1px dashed var(--rule);">
            <span class="pvl-control-label">P0 紧急阻断 EPSS 辅助门槛（KEV 永远置顶不受限）：</span>
            <div class="pvl-pill-group">
              ${[5, 10, 20]
                .map(
                  (th) => `
                    <button type="button" class="pvl-pill ${state.epssThreshold === th ? "active" : ""}" data-epss-th="${th}">
                      EPSS &ge; ${th}%
                    </button>
                  `
                )
                .join("")}
            </div>
          </div>
        </div>

        <div class="pvl-kpi-strip">
          <div class="pvl-kpi-card">
            <div class="pvl-kpi-label">传统 CVSS &ge; 7.0 阻断量</div>
            <div class="pvl-kpi-val" style="color:var(--danger);">${stats.cvssHighCount} 条</div>
          </div>
          <div class="pvl-kpi-card">
            <div class="pvl-kpi-label">传统方案漏杀 KEV 数</div>
            <div class="pvl-kpi-val" style="color:var(--danger);">${stats.missedKevByCvss} / ${stats.totalKev} 条</div>
          </div>
          <div class="pvl-kpi-card">
            <div class="pvl-kpi-label">协同后立即 P0 (Act) 队列</div>
            <div class="pvl-kpi-val" style="color:var(--ok);">${stats.remainingActionable} 条</div>
          </div>
          <div class="pvl-kpi-card">
            <div class="pvl-kpi-label">总体紧急告警压降率 / KEV 漏杀</div>
            <div class="pvl-kpi-val" style="color:var(--accent-blue);">${stats.noiseDropPct}% / 0 漏杀</div>
          </div>
        </div>

        <div class="pvl-funnel-card">
          <div class="pvl-funnel-row">
            <div class="pvl-funnel-head">
              <span>阶段 0 · 原始组件匹配 CVE 全量（Layer 3 产出基线）</span>
              <span>${stats.N} 条 (100%)</span>
            </div>
            <div class="pvl-funnel-track">
              <div class="pvl-funnel-fill is-bad" style="width:100%;"></div>
            </div>
          </div>

          <div class="pvl-funnel-row">
            <div class="pvl-funnel-head">
              <span>对照基线 · 传统单纯 CVSS &ge; 7.0 门禁（误报高企且漏掉 ${stats.missedKevByCvss} 条低 CVSS KEV）</span>
              <span>${stats.cvssHighCount} 条 (${pct(stats.cvssHighCount)}%)</span>
            </div>
            <div class="pvl-funnel-track">
              <div class="pvl-funnel-fill is-warn" style="width:${pct(stats.cvssHighCount)}%;"></div>
            </div>
          </div>

          <div class="pvl-funnel-row">
            <div class="pvl-funnel-head">
              <span>阶段 1 · 经 L4 静动态可达性过滤后剩余（已剔除 ${stats.reachEliminated} 条不可达死代码/休眠包）</span>
              <span>${stats.N - stats.reachEliminated} 条 (${pct(stats.N - stats.reachEliminated)}%)</span>
            </div>
            <div class="pvl-funnel-track">
              <div class="pvl-funnel-fill is-blue" style="width:${pct(stats.N - stats.reachEliminated)}%;"></div>
            </div>
          </div>

          <div class="pvl-funnel-row">
            <div class="pvl-funnel-head">
              <span>${
                state.useThreatSsvc
                  ? `阶段 2 · SSVC (KEV + EPSS &ge; ${state.epssThreshold}% + 暴露面) 精筛 P0 Act 立即修复（其余 ${stats.threatDeferred} 条分流至 Attend/Track*）`
                  : "阶段 2 · 未启用 EPSS / KEV / SSVC 分流（保持上一步全量进入处理队列）"
              }</span>
              <span>${stats.remainingActionable} 条 (${pct(stats.remainingActionable)}%)</span>
            </div>
            <div class="pvl-funnel-track">
              <div class="pvl-funnel-fill is-ok" style="width:${Math.max(2, Number(pct(stats.remainingActionable)))}%;"></div>
            </div>
            <p class="pvl-funnel-note">
              ${
                state.useVexLedger
                  ? `<strong>可审计 VEX 账本闭环：</strong>已自动归档签发 <strong>${stats.vexAudited} 条</strong>带证据链的 VEX <code>not_affected</code> 声明，且全数 ${stats.totalKev} 条 CISA KEV（含低 CVSS 勒索条目）100% 强制留在处理队列中。`
                  : `<strong>提示：</strong>当前未启用 VEX 账本自动签发，全数 ${stats.totalKev} 条 CISA KEV 均强制留在处理队列中。`
              }
            </p>
          </div>
        </div>

        <div class="pvl-card">
          <div style="font-size:0.83rem;font-weight:700;color:var(--ink);margin-bottom:0.55rem;">
            VEX 事件驱动撤销触发器检查器（点击触发生产环境变更事件，检验为何不能“永久静默”）：
          </div>
          <div class="pvl-trigger-grid">
            ${TRIGGERS.map(
              (tr) => `
                <button type="button" class="pvl-trigger-btn ${activeTrigger.id === tr.id ? "active" : ""}" data-trigger="${tr.id}">
                  ${escapeHtml(tr.title)}
                </button>
              `
            ).join("")}
          </div>
          <div class="pvl-trigger-detail">
            <div><strong>事件类型：</strong><code>${escapeHtml(activeTrigger.eventName)}</code> &nbsp;|&nbsp; <strong>状态跃迁：</strong><code>${escapeHtml(activeTrigger.oldState)}</code> &rarr; <code>${escapeHtml(activeTrigger.newState)}</code></div>
            <div style="margin-top:0.35rem;">${escapeHtml(activeTrigger.action)}</div>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：EPSS / KEV / SSVC 非补偿裁决与 VEX 信任网关";
      const intro =
        config.intro ||
        "亲手调控 CVSS、EPSS 30 天概率、KEV 与 L4 可达性，直观对比传统阈值、线性加权与 SSVC+VEX 的裁决差异。";

      const html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0013 · SSVC &times; VEX Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="pvl-tabs">
          <button type="button" class="pvl-tab ${state.activeTab === "triage" ? "active" : ""}" data-tab="triage">
            <span class="pvl-tab-num">1</span>
            模式一：SSVC 非补偿决策树与 VEX 信任/多协议生成
          </button>
          <button type="button" class="pvl-tab ${state.activeTab === "funnel" ? "active" : ""}" data-tab="funnel">
            <span class="pvl-tab-num">2</span>
            模式二：1,000 条 CVE 协同降噪漏斗与 VEX 撤销触发器
          </button>
        </div>

        ${state.activeTab === "triage" ? renderTriageTab() : renderFunnelTab()}
      `;

      container.innerHTML = html;
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

      const cvssSlider = container.querySelector('[data-slider="cvss"]');
      if (cvssSlider) {
        cvssSlider.addEventListener("input", (e) => {
          state.presetId = "";
          state.cvss = parseFloat(e.target.value);
          container.querySelectorAll(".pvl-preset-btn.active").forEach((b) => b.classList.remove("active"));
          const readout = container.querySelector('[data-readout="cvss"]');
          if (readout) readout.textContent = state.cvss.toFixed(1);
          updateTriageOutput();
        });
      }

      const epssSlider = container.querySelector('[data-slider="epss"]');
      if (epssSlider) {
        epssSlider.addEventListener("input", (e) => {
          state.presetId = "";
          state.epssPct = parseFloat(e.target.value);
          container.querySelectorAll(".pvl-preset-btn.active").forEach((b) => b.classList.remove("active"));
          const readout = container.querySelector('[data-readout="epss"]');
          if (readout) {
            const pctl = estimateEpssPercentile(state.epssPct);
            readout.innerHTML = `${state.epssPct.toFixed(1)}% <span style="color:var(--ink-muted);font-weight:500;">(≈ 第 ${pctl.toFixed(1)} 百分位)</span>`;
          }
          updateTriageOutput();
        });
      }

      container.querySelectorAll("[data-kev]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "";
          state.kevStatus = btn.dataset.kev;
          render();
        });
      });

      container.querySelectorAll("[data-reach]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "";
          state.reachability = btn.dataset.reach;
          render();
        });
      });

      container.querySelectorAll("[data-exposure]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "";
          state.exposure = btn.dataset.exposure;
          render();
        });
      });

      container.querySelectorAll("[data-vex-source]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "";
          state.vexSource = btn.dataset.vexSource;
          render();
        });
      });

      bindFormatTabs();

      container.querySelectorAll("[data-funnel-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          if (cb.dataset.funnelToggle === "reach") state.useReachability = cb.checked;
          if (cb.dataset.funnelToggle === "threat") state.useThreatSsvc = cb.checked;
          if (cb.dataset.funnelToggle === "vex") state.useVexLedger = cb.checked;
          render();
        });
      });

      container.querySelectorAll("[data-epss-th]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.epssThreshold = Number(btn.dataset.epssTh);
          render();
        });
      });

      container.querySelectorAll("[data-trigger]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTriggerId = btn.dataset.trigger;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="prioritization-vex-lab"]')
      .forEach(initPrioritizationVexLab);
  });
})();
