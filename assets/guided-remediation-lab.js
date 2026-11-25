/* ==========================================================================
   可复用交互组件：无破坏性自动修复求解与升级影响分析实验室（Lesson 0014+）
   零依赖原生 JS，支持策略对比、调用图 API Diff 交集、双触点载荷与防 PR 风暴模拟。
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

  function initGuidedRemediationLab(container) {
    const dataEl = container.querySelector("script.guided-remediation-lab-data");
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
        id: "safe-major-ochoa",
        label: "1. 隐形 Major 安全升级 · Ochoa 实证",
        desc: "某直连解析库需从 2.14.3 跨 Major 升至 3.0.4 才能拔除 3 条可达 CVE；新版本含 18 处库级 API 破坏性变更，但第一方调用图实测命中 0 处。",
        apply: {
          strategy: "relock-major",
          useCallGraphDiff: true,
          useRegressionBrake: true,
          payloadMode: "pr",
        },
        nodes: {
          direct: { name: "jackson-databind (直接依赖)", from: "2.14.3", safeTo: "3.0.4", minorTo: "2.17.2", license: "Apache-2.0" },
          parent: { name: "spring-boot-starter-json (中间父包)", from: "3.2.5", safeTo: "3.3.4", minorTo: "3.2.9", role: "框架桥接层" },
          vuln: { name: "CVE-2025-1042 / 1089 / 1102", from: "3 条可达高危", safeTo: "0 条（全数消除）", minorTo: "仅修 1 条（余 2 条）" },
        },
        apiDiffTotal: 18,
        apiHitCalls: [],
        clearNote: "japicmp 检测到 18 个已移除或签名变更方法，经与 L4 第一方调用图求交，本仓库实际仅调用 ObjectMapper.readValue 等兼容接口（命中 0 处）。",
        licenseShift: "Apache-2.0 → Apache-2.0（合规通过）",
        newCveCheck: "目标依赖子树无新增中高危 / KEV 漏洞",
      },
      {
        id: "maven-override-bomb",
        label: "2. Maven Override 隐形定时炸弹",
        desc: "3 层传递依赖 netty-codec-http 存在 KEV 漏洞。若直接用 <dependencyManagement> override 跨大版本硬改传递库，将撕裂中间父包调用契约；relock 升级顶层父包才安全。",
        apply: {
          strategy: "override",
          useCallGraphDiff: true,
          useRegressionBrake: true,
          payloadMode: "pr",
        },
        nodes: {
          direct: { name: "grpc-netty-shaded-client (直接依赖)", from: "1.58.0", safeTo: "1.66.0", minorTo: "1.61.1", license: "Apache-2.0" },
          parent: { name: "reactor-netty-http (中间父包)", from: "1.1.12", safeTo: "1.2.0", minorTo: "1.1.22", role: "强绑定 Netty ABI" },
          vuln: { name: "io.netty:netty-codec-http (传递)", from: "4.1.94.Final", safeTo: "4.1.115.Final (跟随父包)", minorTo: "4.1.108.Final" },
        },
        apiDiffTotal: 9,
        apiHitCalls: [
          "reactor.netty.http.HttpServerBind -> HttpServerCodec.<init>(III) [NoSuchMethodError!]",
        ],
        clearNote: "通过 relock 同步抬升顶层直接父依赖后，中间父依赖与传递库 ABI 保持同源一致，编译与运行态零签名冲突。",
        licenseShift: "Apache-2.0 → Apache-2.0（合规通过）",
        newCveCheck: "无新增 CVE（消除 1 条 CISA KEV）",
      },
      {
        id: "license-and-cve-regression",
        label: "3. 许可与新 CVE 回归双刹车",
        desc: "漏洞库唯一声明修复的 4.0.0 新版将开源协议从 MIT 改为 AGPL-3.0，且连带引入一条新传递高危 CVE。求解器必须自动否决该候选并回退到合规方案。",
        apply: {
          strategy: "relock-major",
          useCallGraphDiff: true,
          useRegressionBrake: true,
          payloadMode: "pr",
        },
        nodes: {
          direct: { name: "pdf-render-core (直接依赖)", from: "3.4.1", safeTo: "3.4.9-sec (合规热修版)", minorTo: "3.4.9-sec", license: "MIT -> AGPL-3.0 (v4.0.0)" },
          parent: { name: "font-layout-engine (新增传递)", from: "1.2.0", safeTo: "1.2.0 (未引入)", minorTo: "1.2.0", role: "4.0.0 新增子依赖" },
          vuln: { name: "CVE-2026-2201 + 新 CVE-2026-3099", from: "1 条原 KEV", safeTo: "通过最小补丁版消除原漏洞且零新危", minorTo: "零新危" },
        },
        apiDiffTotal: 4,
        apiHitCalls: [],
        clearNote: "虽未触发代码调用破坏，但 v4.0.0 触犯闭源商业许可证红线（AGPL-3.0）及新 CVE 回归门禁，已自动拦截并降级选举 3.4.9-sec。",
        licenseShift: "v4.0.0 触发 MIT → AGPL-3.0 漂移（红线拦截）；候选 3.4.9-sec 保持 MIT",
        newCveCheck: "v4.0.0 携带新传递高危 CVE-2026-3099（拦截）；候选 3.4.9-sec 零新增",
      },
      {
        id: "targeted-breaking-dual-touchpoint",
        label: "4. 精准命中破坏点 · PR + Agent MCP 双触点",
        desc: "升级 auth-token-sdk 至 5.0.0 仅在库内变动 6 个接口，但调用图精准命中本仓库 2 处业务调用点。求解器拒绝自动合并，并同时生成人类 LST 补丁与 Coding Agent MCP 修复计划。",
        apply: {
          strategy: "relock-major",
          useCallGraphDiff: true,
          useRegressionBrake: true,
          payloadMode: "mcp",
        },
        nodes: {
          direct: { name: "auth-token-sdk (直接依赖)", from: "4.2.0", safeTo: "5.0.2 (需微调 2 处调用)", minorTo: "4.2.9 (未修复)", license: "Apache-2.0" },
          parent: { name: "jose-jwt-verifier (传递依赖)", from: "2.1.0", safeTo: "3.0.1", minorTo: "2.1.0", role: "密码学验签核心" },
          vuln: { name: "CVE-2026-1844 (JWT alg=none 绕过)", from: "Act P0 · 可达", safeTo: "0 条（已修复）", minorTo: "4.x 分支已停止维护" },
        },
        apiDiffTotal: 6,
        apiHitCalls: [
          "src/main/java/com/app/OrderService.java:142 -> JwtParser.parseClaims(String) 已废弃，需迁移 parseSignedClaims(String, Key)",
          "src/main/java/com/app/AuthFilter.java:88 -> TokenOptions.allowLegacyAlg(boolean) 已移除",
        ],
        clearNote: "精准识别到 2 处受影响调用点，自动生成 OpenRewrite LST 重构配方与 MCP 结构化修改指令，避免盲推破版 PR。",
        licenseShift: "Apache-2.0 → Apache-2.0（合规通过）",
        newCveCheck: "目标 5.0.2 无新增高危或 KEV 漏洞",
      },
    ];

    const STRATEGIES = [
      { id: "in-place", label: "in-place (原位锁文件)" },
      { id: "relock-minor", label: "relock (放宽至 Minor)" },
      { id: "relock-major", label: "relock (允许 Major)" },
      { id: "override", label: "override (强制传递覆写)" },
    ];

    const state = {
      activeTab: "solver", // "solver" | "pareto"
      presetId: "safe-major-ochoa",
      strategy: "relock-major",
      useCallGraphDiff: true,
      useRegressionBrake: true,
      payloadMode: "pr", // "pr" | "mcp"
      // 模式二参数
      maxSpan: "major", // "patch" | "minor" | "major"
      allowSafeMajor: true,
      aggregationMode: "direct-root", // "per-cve" | "direct-root"
      prCap: 4,
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function evaluateSolver(preset) {
      const s = state.strategy;

      // 反例 A：传统单包 PR Bot（每个 CVE 单独提 PR）
      const legacyBot = {
        tone: "is-bad",
        verdict: "单包盲提 PR · 易崩且发风暴",
        meta: preset.id === "license-and-cve-regression" ? "可能直接升级 AGPL-3.0 版本" : "不校验中间父包与业务调用点",
        desc:
          preset.id === "maven-override-bomb"
            ? "直接对底层 netty-codec-http 发单包升级 PR，无法通过或撕裂中间依赖 ABI。"
            : "机械把最新补丁号塞进 PR 队列，既不聚合顶层依赖，也不区分 18 处破坏变更是否真被业务调用。",
      };

      // 反例 B：纯 SemVer 规则引擎（Major 一刀切禁止）
      let semverRes;
      if (preset.id === "safe-major-ochoa") {
        semverRes = {
          tone: "is-warn",
          verdict: "误杀拦截 · 错失 0 破坏升级",
          meta: "仅凭 2.x→3.x 大版本号即判高风险阻断",
          desc: "虽有 3 条可达高危 CVE，但仅因 SemVer 主版本号递增就直接放弃自动修复，逼迫研发手工积压。",
        };
      } else if (preset.id === "maven-override-bomb") {
        semverRes = {
          tone: "is-warn",
          verdict: "仍漏判传递依赖签名冲突",
          meta: "未核验中间父包字节码调用契约",
          desc: "如果仅按 SemVer 次版本规则强行覆写传递库，可能忽略内部类或桥接方法已被移除的事实。",
        };
      } else {
        semverRes = {
          tone: "is-warn",
          verdict: "无法识别合规漂移与具体代码行",
          meta: "停留在“版本号文本对比”层面",
          desc: "无法判断哪些业务行受影响，也缺乏许可证漂移与传递新 CVE 的回溯重算能力。",
        };
      }

      // 推荐：第三代 Guided Remediation 求解器
      let thirdGen;
      if (preset.id === "maven-override-bomb" && s === "override") {
        thirdGen = {
          tone: state.useCallGraphDiff ? "is-bad" : "is-warn",
          verdict: state.useCallGraphDiff ? "拦截 Override 炸弹！建议改走 Relock" : "危险放行（未开调用图契约检查）",
          meta: "Override 破坏中间父包 reactor-netty ABI",
          desc: state.useCallGraphDiff
            ? "L4 契约检查发现强制 override 会导致中间父包抛出 NoSuchMethodError，求解器拒绝覆写并推荐改用 relock 升级顶层 grpc-netty。"
            : "当前关闭了调用图 API Diff 检查，强制 override 虽表面改了 pom.xml，线上极易触发运行期方法缺失崩溃！",
        };
      } else if (preset.id === "license-and-cve-regression") {
        if (state.useRegressionBrake) {
          thirdGen = {
            tone: "is-ok",
            verdict: "双刹车生效 · 选出 3.4.9-sec 合规解",
            meta: "否决 AGPL-3.0 与新 CVE 候选 v4.0.0",
            desc: "回归护栏在求解阶段直接剔除协议传染与新引入高危路径的 v4.0.0，收敛至 MIT 授权且零新增 CVE 的最小热修方案。",
          };
        } else {
          thirdGen = {
            tone: "is-bad",
            verdict: "高危失守！未拦截 AGPL-3.0 漂移",
            meta: "合规刹车已关闭 · 可能污染闭源/业务仓",
            desc: "未启用许可证与新 CVE 回归校验，求解器贪心选中了 v4.0.0，把强传染性 AGPL-3.0 依赖带入主干！",
          };
        }
      } else if (preset.id === "safe-major-ochoa") {
        if (s === "in-place" || s === "relock-minor") {
          thirdGen = {
            tone: "is-warn",
            verdict: "策略过窄 · 仍遗留 2 条可达 CVE",
            meta: `当前策略 ${s} 无法跨出 2.x 分支`,
            desc: "受限于当前策略边界，仅修补了 1 条漏洞；切换至 relock (允许 Major) 并配合调用图交集即可实现零破坏全消。",
          };
        } else {
          thirdGen = {
            tone: state.useCallGraphDiff ? "is-ok" : "is-warn",
            verdict: state.useCallGraphDiff ? "Safe Major 自动放行 · 0 破坏拔除 3 CVE" : "需人工兜底审阅（未开调用图求交）",
            meta: state.useCallGraphDiff ? "18 处库级变更 ∩ 第一方调用图 = 0 命中" : "盲升 Major 缺乏符号兼容性证据",
            desc: state.useCallGraphDiff
              ? "依托 Ochoa 等人实证规律与字节码 API Diff 交集证明，3.0.4 对本仓库零破坏，直接生成带调用图证明的安全 PR。"
              : "未开启调用图交集检查，研发面对 Major PR 不敢合并，极易被长期搁置。",
          };
        }
      } else {
        // targeted-breaking-dual-touchpoint
        if (s === "in-place" || s === "relock-minor") {
          thirdGen = {
            tone: "is-warn",
            verdict: "4.x 已停止安全维护 · 无法修复 KEV",
            meta: `策略 ${s} 找不到无漏洞版本`,
            desc: "必须放宽至 Major 5.0.2 并结合 OpenRewrite LST / Coding Agent MCP 完成 2 处精准代码重构。",
          };
        } else {
          thirdGen = {
            tone: state.useCallGraphDiff ? "is-info" : "is-bad",
            verdict: state.useCallGraphDiff ? "拒绝盲目合并 · 联动 LST + Agent MCP 修复" : "盲推破坏性升级 · CI 编译必挂",
            meta: state.useCallGraphDiff ? "精准定位 2 处受影响业务调用行" : "关闭调用图求交导致遗漏签名变更",
            desc: state.useCallGraphDiff
              ? "求解器附带 OpenRewrite 迁移配方与 MCP 结构化调用点清单，让研发或 Coding Agent 在本地单测通过后再提 PR。"
              : "没有 API Diff 交集护栏，直接升级 5.0.2 会打断 OrderService 与 AuthFilter 编译。",
          };
        }
      }

      return { legacyBot, semverRes, thirdGen };
    }

    function buildPayloadText(preset) {
      if (state.payloadMode === "pr") {
        if (preset.id === "safe-major-ochoa") {
          return [
            `# [SCA Guided Remediation] Safe Major 升级：${preset.nodes.direct.name} 2.14.3 -> 3.0.4`,
            `strategy: ${state.strategy} | regression_brake: ${state.useRegressionBrake} | callgraph_intersection: ${state.useCallGraphDiff}`,
            "",
            "## 1. 安全收益（来自 L3/L4 优先级队列）",
            "- 一次性拔除 3 条可达漏洞：CVE-2025-1042, CVE-2025-1089, CVE-2025-1102",
            "- 许可证校验：Apache-2.0 -> Apache-2.0（零传染性漂移）",
            "- 新 CVE 回归检查：0 条新增中高危或 KEV",
            "",
            "## 2. 升级影响证明（Upgrade Impact Analysis）",
            state.useCallGraphDiff
              ? "- japicmp 库级破坏性变更总计：18 处\n- 与本仓库 L4 调用图求交命中：0 处（已覆盖 100% 业务入口调用）\n- 结论：Safe Major，推荐直接合入并触发 CI 回归验证。"
              : "- [警告] 未启用调用图 API Diff 交集校验，建议人工核对 3.0.4 Release Notes。",
          ].join("\n");
        }
        if (preset.id === "maven-override-bomb") {
          return [
            `# [pom.xml 最小修复 Diff] 策略对比：${state.strategy === "override" ? "OVERRIDE (高风险冲突!)" : "RELOCK 顶层父依赖 (推荐)"}`,
            state.strategy === "override"
              ? [
                  "--- a/pom.xml  (Danger: 强行 Override 传递依赖破坏中间层契约)",
                  "+++ b/pom.xml",
                  " <dependencyManagement><dependencies>",
                  "+  <dependency>",
                  "+    <groupId>io.netty</groupId><artifactId>netty-codec-http</artifactId>",
                  "+    <version>4.2.0.Final</version> <!-- 冲突：reactor-netty-http 1.1.12 调用的旧构造函数已删除！-->",
                  "+  </dependency>",
                ].join("\n")
              : [
                  "--- a/pom.xml  (Safe Relock: 同步升级顶层直连父包)",
                  "+++ b/pom.xml",
                  " <dependency>",
                  "   <groupId>io.grpc</groupId><artifactId>grpc-netty-shaded-client</artifactId>",
                  "-  <version>1.58.0</version>",
                  "+  <version>1.66.0</version> <!-- 自动同源拉起 reactor-netty 1.2.0 + netty 4.1.115.Final -->",
                  " </dependency>",
                ].join("\n"),
          ].join("\n");
        }
        if (preset.id === "license-and-cve-regression") {
          return [
            `# [Solver 决策日志] 双重回归刹车（License Gate + New-CVE Gate）`,
            `候选版本 1: pdf-render-core@4.0.0`,
            state.useRegressionBrake
              ? `  [REJECTED] 触发许可证红线：MIT -> AGPL-3.0\n  [REJECTED] 触发新 CVE 回归：引入传递高危 CVE-2026-3099`
              : `  [ACCEPTED - DANGEROUS!] 刹车已关闭，错误选中 AGPL-3.0 版本！`,
            "",
            `候选版本 2: pdf-render-core@3.4.9-sec`,
            `  [ELECTED]  消除原 KEV CVE-2026-2201 | 许可维持 MIT | 新增高危 = 0`,
          ].join("\n");
        }
        return [
          `# [OpenRewrite LST 自动迁移配方 + PR Diff] auth-token-sdk 4.2.0 -> 5.0.2`,
          `type: specs.openrewrite.org/v1beta/recipe`,
          `name: com.sca.remediation.UpgradeAuthTokenSdkV5`,
          `recipeList:`,
          `  - org.openrewrite.maven.UpgradeDependencyVersion:`,
          `      groupId: com.auth`,
          `      artifactId: auth-token-sdk`,
          `      newVersion: 5.0.2`,
          `  - org.openrewrite.java.ChangeMethodName:`,
          `      methodPattern: com.auth.JwtParser parseClaims(java.lang.String)`,
          `      newMethodName: parseSignedClaims`,
          "",
          `# 精确调用点命中清单 (L4 Call Graph ∩ API Diff = 2 hits):`,
          `#   1) src/main/java/com/app/OrderService.java:142`,
          `#   2) src/main/java/com/app/AuthFilter.java:88`,
        ].join("\n");
      }

      // AI Coding Agent MCP JSON 载荷
      const mcpObj = {
        jsonrpc: "2.0",
        tool: "sca_plan_remediation",
        result: {
          preset: preset.id,
          selected_strategy: state.strategy,
          target_direct_dependency: preset.nodes.direct.name,
          recommended_version:
            state.strategy === "in-place" || state.strategy === "relock-minor"
              ? preset.nodes.direct.minorTo
              : preset.nodes.direct.safeTo,
          regression_gates: {
            license_gate_enabled: state.useRegressionBrake,
            license_transition: preset.licenseShift,
            new_cve_check: preset.newCveCheck,
          },
          callgraph_impact: {
            enabled: state.useCallGraphDiff,
            library_breaking_symbols: preset.apiDiffTotal,
            reachable_breaking_sites: state.useCallGraphDiff ? preset.apiHitCalls : ["未扫描（调用图交集已关闭）"],
          },
          agent_next_actions:
            preset.apiHitCalls.length > 0 && state.useCallGraphDiff
              ? [
                  "1. 在沙箱工作区应用依赖版本变更并更新 lockfile",
                  "2. 按 reachable_breaking_sites 精准重构受影响调用行",
                  "3. 运行受影响模块单元测试通过后，再向人类提交绿灯 PR",
                ]
              : [
                  "1. 更新 manifest/lockfile 并验证哈希一致性",
                  "2. 附上 0-breaking 调用图证明签发自动化 PR",
                ],
        },
      };
      return JSON.stringify(mcpObj, null, 2);
    }

    function renderSolverTab() {
      const preset = getCurrentPreset();
      const res = evaluateSolver(preset);
      const payload = buildPayloadText(preset);

      const useMinorOnly = state.strategy === "in-place" || state.strategy === "relock-minor";
      const overrideDanger = preset.id === "maven-override-bomb" && state.strategy === "override";

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
          <strong>场景说明：</strong>${escapeHtml(preset.desc)}
        </p>

        <div class="grl-layout">
          <div class="grl-controls">
            <div class="grl-control-group">
              <span class="grl-control-label">1. 选择依赖图修改策略（对标 OSV-Scanner v2）</span>
              <div class="grl-pill-group">
                ${STRATEGIES.map(
                  (st) => `
                    <button type="button" class="grl-pill ${state.strategy === st.id ? "active" : ""}" data-strategy="${st.id}">
                      ${escapeHtml(st.label)}
                    </button>
                  `
                ).join("")}
              </div>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 求解器安全护栏（Safety Brakes）</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="callgraph" ${state.useCallGraphDiff ? "checked" : ""} />
                <span>启用 <strong>L4 调用图 &cap; API Diff</strong> 影响交集（Ochoa 实证：区分“库有破坏变更”与“本仓库真调用到”）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="brake" ${state.useRegressionBrake ? "checked" : ""} />
                <span>启用 <strong>许可证漂移（AGPL/GPL）&amp; 新 CVE 回归双刹车</strong></span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">3. 交付触点协议切换（人类 vs Coding Agent）</span>
              <div class="grl-pill-group">
                <button type="button" class="grl-pill is-accent ${state.payloadMode === "pr" ? "active" : ""}" data-payload="pr">
                  人类 PR + OpenRewrite LST Diff
                </button>
                <button type="button" class="grl-pill is-accent ${state.payloadMode === "mcp" ? "active" : ""}" data-payload="mcp">
                  AI Coding Agent MCP JSON
                </button>
              </div>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">当前沙箱与合规检查摘要</span>
              <div style="font-size:0.77rem;line-height:1.52;color:var(--ink-secondary);">
                <div>&bull; <strong>许可证门禁：</strong>${escapeHtml(preset.licenseShift)}</div>
                <div>&bull; <strong>新 CVE 检查：</strong>${escapeHtml(preset.newCveCheck)}</div>
                <div>&bull; <strong>重锁沙箱：</strong><code>Tier 3</code>（禁宿主机直接执行 npm <code>postinstall</code>）</div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid">
              <div class="grl-card ${res.legacyBot.tone}">
                <div class="grl-card-kicker">反例 A · 传统单包 PR Bot</div>
                <div class="grl-card-title">${escapeHtml(res.legacyBot.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.legacyBot.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.legacyBot.desc)}</p>
              </div>

              <div class="grl-card ${res.semverRes.tone}">
                <div class="grl-card-kicker">反例 B · 纯 SemVer 规则引擎</div>
                <div class="grl-card-title">${escapeHtml(res.semverRes.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.semverRes.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.semverRes.desc)}</p>
              </div>

              <div class="grl-card ${res.thirdGen.tone}">
                <div class="grl-card-kicker">推荐 · 第三代 Guided Solver</div>
                <div class="grl-card-title">${escapeHtml(res.thirdGen.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.thirdGen.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.thirdGen.desc)}</p>
              </div>
            </div>

            <div class="grl-graph-grid">
              <div class="grl-dep-node ${overrideDanger ? "is-conflict" : "is-upgraded"}">
                <div class="grl-dep-role">1. 顶层直接依赖 (Direct)</div>
                <div class="grl-dep-name">${escapeHtml(preset.nodes.direct.name)}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.nodes.direct.from)} &rarr; <strong>${escapeHtml(useMinorOnly ? preset.nodes.direct.minorTo : preset.nodes.direct.safeTo)}</strong></div>
                <div class="grl-dep-note">License: ${escapeHtml(preset.nodes.direct.license)}</div>
              </div>

              <div class="grl-dep-node ${overrideDanger ? "is-conflict" : "is-safe"}">
                <div class="grl-dep-role">2. 中间父依赖 (Transitive Parent)</div>
                <div class="grl-dep-name">${escapeHtml(preset.nodes.parent.name)}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.nodes.parent.from)} &rarr; <strong>${escapeHtml(overrideDanger ? "未同步升级（ABI 撕裂!）" : useMinorOnly ? preset.nodes.parent.minorTo : preset.nodes.parent.safeTo)}</strong></div>
                <div class="grl-dep-note">${escapeHtml(preset.nodes.parent.role)}</div>
              </div>

              <div class="grl-dep-node ${useMinorOnly && preset.id !== "license-and-cve-regression" ? "is-conflict" : "is-safe"}">
                <div class="grl-dep-role">3. 目标漏洞状态 (CVE Target)</div>
                <div class="grl-dep-name">${escapeHtml(preset.nodes.vuln.name)}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.nodes.vuln.from)} &rarr; <strong>${escapeHtml(useMinorOnly ? preset.nodes.vuln.minorTo : preset.nodes.vuln.safeTo)}</strong></div>
                <div class="grl-dep-note">${overrideDanger ? "强行 override 引发运行期方法缺失风险" : "随依赖图求解收敛"}</div>
              </div>
            </div>

            <div class="grl-impact-panel">
              <div class="grl-impact-head">
                <span>API 破坏面交集明细：库级变更 ${preset.apiDiffTotal} 处 &cap; 第一方调用图</span>
                <span class="badge ${
                  !state.useCallGraphDiff
                    ? "badge-warn"
                    : preset.apiHitCalls.length > 0
                    ? "badge-danger"
                    : "badge-ok"
                }">
                  ${
                    !state.useCallGraphDiff
                      ? "调用图交集未开启（盲升风险）"
                      : preset.apiHitCalls.length > 0
                      ? `精准命中 ${preset.apiHitCalls.length} 处真实破坏点`
                      : "0 处业务调用命中（Safe Upgrade）"
                  }
                </span>
              </div>
              <div class="grl-impact-list">
                ${
                  !state.useCallGraphDiff
                    ? `<div class="grl-impact-item">未开启调用图交集：只能看到库级存在 ${preset.apiDiffTotal} 处 Breaking Changes，无法判断本仓库是否真调用到这些符号。</div>`
                    : preset.apiHitCalls.length > 0
                    ? preset.apiHitCalls
                        .map((hit) => `<div class="grl-impact-item is-hit">HIT: ${escapeHtml(hit)}</div>`)
                        .join("")
                    : `<div class="grl-impact-item is-clear">CLEAR: ${escapeHtml(preset.clearNote)}</div>`
                }
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">${
                  state.payloadMode === "pr"
                    ? "人类侧输出：PR 描述 + OpenRewrite LST / 最小 Manifest Diff"
                    : "AI Agent 侧输出：MCP 结构化修复计划（先本地自愈+单测再提 PR）"
                }</span>
              </div>
              <pre class="grl-payload-pre">${escapeHtml(payload)}</pre>
            </div>
          </div>
        </div>
      `;
    }

    function computeParetoStats() {
      // 假设企业仓库经 Lesson 0013 降噪后剩 30 条必须修的 Act/Attend 漏洞，分布在 6 棵直接依赖子树中
      const totalActionable = 30;
      let fixed = 11; // patch only
      if (state.maxSpan === "minor") fixed = 21;
      if (state.maxSpan === "major") {
        fixed = state.allowSafeMajor ? 29 : 25;
      }

      const rawPrCount = state.aggregationMode === "per-cve" ? fixed : Math.min(6, Math.max(1, Math.ceil(fixed / 5)));
      const effectivePrCount = Math.min(rawPrCount, state.prCap);
      const suppressedByCap = Math.max(0, rawPrCount - effectivePrCount);

      let breakRate = 2;
      if (state.maxSpan === "minor") breakRate = 4;
      if (state.maxSpan === "major") {
        breakRate = state.allowSafeMajor ? 3 : 19;
      }

      let mergeAcceptRate = 88;
      if (state.aggregationMode === "per-cve") mergeAcceptRate -= 42;
      if (state.maxSpan === "major" && !state.allowSafeMajor) mergeAcceptRate -= 28;
      if (state.maxSpan === "major" && state.allowSafeMajor && state.aggregationMode === "direct-root") mergeAcceptRate = 92;

      return {
        totalActionable,
        fixed,
        fixedPct: ((fixed / totalActionable) * 100).toFixed(0),
        rawPrCount,
        effectivePrCount,
        suppressedByCap,
        breakRate,
        mergeAcceptRate,
        candidates: [
          {
            name: "A · in-place 锁文件原位修补",
            fixed: "11 / 30 (37%)",
            span: "仅 Patch",
            breaks: "0 处（极稳但遗漏 19 条）",
            licenseGate: "通过",
            verdict: "保守兜底（适合热修复窗口）",
            badge: "badge-blue",
          },
          {
            name: "B · relock 放宽至 Minor",
            fixed: "21 / 30 (70%)",
            span: "Patch + Minor",
            breaks: "1 处（需人工确认）",
            licenseGate: "通过",
            verdict: "遗留 9 条跨大版本漏洞",
            badge: "badge-warn",
          },
          {
            name: "C · relock + 调用图 Safe Major 聚合（帕累托最优）",
            fixed: "29 / 30 (97%)",
            span: "最小直接父包（含 0-Break Major）",
            breaks: "0 处未保护破坏（剩余 1 条含 2 处精准 LST 引导）",
            licenseGate: "已自动剔除 1 个 AGPL 候选",
            verdict: "推荐主策略 · 仅 6 个聚合 PR",
            badge: "badge-ok",
          },
          {
            name: "D · 盲目全量 Override + 逐 CVE 发 PR",
            fixed: "30 / 30 (100% 账面)",
            span: "强制覆写传递层",
            breaks: "7 处中间父包 ABI 崩毁",
            licenseGate: "未校验",
            verdict: "灾难模式（30 个 PR 轰炸 + 线上崩溃）",
            badge: "badge-danger",
          },
        ],
      };
    }

    function renderParetoOutput() {
      const st = computeParetoStats();
      const prStormPct = Math.min(100, Math.round((st.rawPrCount / 30) * 100));

      return `
        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">待执行修复 PR 数（含限流）</div>
            <div class="grl-kpi-val" style="color:var(--accent-blue);">${st.effectivePrCount} 个 ${st.suppressedByCap > 0 ? `(限流排队 ${st.suppressedByCap})` : ""}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Act/Attend 漏洞一次消除率</div>
            <div class="grl-kpi-val" style="color:var(--ok);">${st.fixed} / ${st.totalActionable} (${st.fixedPct}%)</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">预计 CI / 运行期破坏率</div>
            <div class="grl-kpi-val" style="color:${st.breakRate > 10 ? "var(--danger)" : "var(--ok)"};">${st.breakRate}%</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">研发 PR 合并接受率</div>
            <div class="grl-kpi-val" style="color:${st.mergeAcceptRate >= 80 ? "var(--ok)" : "var(--warn)"};">${st.mergeAcceptRate}%</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div class="grl-bar-row">
            <div class="grl-bar-head">
              <span>PR 噪音规模对比（相对于“30 条漏洞逐一提 PR”的 100% 基准）</span>
              <span>当前产生 ${st.rawPrCount} 个候选 PR (${prStormPct}%)</span>
            </div>
            <div class="grl-bar-track">
              <div class="grl-bar-fill ${st.rawPrCount > 10 ? "is-bad" : "is-ok"}" style="width:${prStormPct}%;"></div>
            </div>
          </div>
          <div class="grl-bar-row">
            <div class="grl-bar-head">
              <span>当前策略一次拔除漏洞比例（目标：高覆盖且低破坏）</span>
              <span>${st.fixedPct}%</span>
            </div>
            <div class="grl-bar-track">
              <div class="grl-bar-fill is-blue" style="width:${st.fixedPct}%;"></div>
            </div>
          </div>
        </div>

        <div class="table-wrap">
          <table class="table-fixed">
            <colgroup>
              <col style="width:24%" />
              <col style="width:15%" />
              <col style="width:18%" />
              <col style="width:23%" />
              <col style="width:20%" />
            </colgroup>
            <thead>
              <tr>
                <th>帕累托求解策略</th>
                <th>消除漏洞</th>
                <th>版本跨度 / 范围</th>
                <th>API 破坏点 &amp; 许可护栏</th>
                <th>架构裁决</th>
              </tr>
            </thead>
            <tbody>
              ${st.candidates
                .map(
                  (c) => `
                    <tr>
                      <td><strong>${escapeHtml(c.name)}</strong></td>
                      <td><code>${escapeHtml(c.fixed)}</code></td>
                      <td>${escapeHtml(c.span)}</td>
                      <td>${escapeHtml(c.breaks)}<br/><span style="color:var(--ink-muted);font-size:0.75rem;">许可：${escapeHtml(c.licenseGate)}</span></td>
                      <td><span class="badge ${c.badge}">${escapeHtml(c.verdict)}</span></td>
                    </tr>
                  `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `;
    }

    function updateParetoOutput() {
      const out = container.querySelector(".grl-pareto-output");
      if (out) out.innerHTML = renderParetoOutput();
    }

    function renderParetoTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0.85rem;">
            <div>
              <span class="grl-control-label">1. 允许升级跨度上限</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.maxSpan === "patch" ? "active" : ""}" data-span="patch">仅 Patch</button>
                <button type="button" class="grl-pill ${state.maxSpan === "minor" ? "active" : ""}" data-span="minor">放宽至 Minor</button>
                <button type="button" class="grl-pill ${state.maxSpan === "major" ? "active" : ""}" data-span="major">允许 Major</button>
              </div>
            </div>

            <div>
              <span class="grl-control-label">2. PR 聚合与防风暴策略</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.aggregationMode === "per-cve" ? "active" : ""}" data-agg="per-cve">单 CVE 逐条提 PR</button>
                <button type="button" class="grl-pill ${state.aggregationMode === "direct-root" ? "active" : ""}" data-agg="direct-root">按顶层直接依赖聚合 PR</button>
              </div>
            </div>

            <div>
              <div class="grl-slider-head">
                <span class="grl-control-label">3. 单仓并发开放 PR 上限</span>
                <strong data-readout="prcap">${state.prCap} 个</strong>
              </div>
              <input type="range" class="grl-slider" data-slider="prcap" min="1" max="10" step="1" value="${state.prCap}" />
            </div>
          </div>

          <div style="padding-top:0.45rem;border-top:1px dashed var(--rule);">
            <label class="grl-toggle">
              <input type="checkbox" data-toggle="safemajor" ${state.allowSafeMajor ? "checked" : ""} />
              <span>启用 <strong>0-Breaking Safe Major 自动放行</strong>（当 Major 升级与第一方调用图交集为 0 时降低破坏率并提高研发合并意愿）</span>
            </label>
          </div>
        </div>

        <div class="grl-pareto-output">${renderParetoOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：依赖图修复求解、API Diff 破坏面与防 PR 风暴模拟器";
      const intro =
        config.intro ||
        "切换不同修复策略、安全护栏与交付载体，直观验证如何在「零破坏、不引 AGPL/新 CVE、不轰炸研发」约束下求解最优升级路径。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0014 · Guided Remediation Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "solver" ? "active" : ""}" data-tab="solver">
            <span class="grl-tab-num">1</span>
            模式一：依赖图修复策略、API Diff 交集与双触点输出
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "pareto" ? "active" : ""}" data-tab="pareto">
            <span class="grl-tab-num">2</span>
            模式二：多目标帕累托求解与企业级防 PR 风暴限流
          </button>
        </div>

        ${state.activeTab === "solver" ? renderSolverTab() : renderParetoTab()}
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

      container.querySelectorAll("[data-strategy]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.strategy = btn.dataset.strategy;
          render();
        });
      });

      container.querySelectorAll("[data-payload]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.payloadMode = btn.dataset.payload;
          render();
        });
      });

      container.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          if (cb.dataset.toggle === "callgraph") state.useCallGraphDiff = cb.checked;
          if (cb.dataset.toggle === "brake") state.useRegressionBrake = cb.checked;
          if (cb.dataset.toggle === "safemajor") state.allowSafeMajor = cb.checked;
          render();
        });
      });

      container.querySelectorAll("[data-span]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.maxSpan = btn.dataset.span;
          render();
        });
      });

      container.querySelectorAll("[data-agg]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.aggregationMode = btn.dataset.agg;
          render();
        });
      });

      const prSlider = container.querySelector('[data-slider="prcap"]');
      if (prSlider) {
        prSlider.addEventListener("input", (e) => {
          state.prCap = Number(e.target.value);
          const readout = container.querySelector('[data-readout="prcap"]');
          if (readout) readout.textContent = `${state.prCap} 个`;
          updateParetoOutput();
        });
      }
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="guided-remediation-lab"]')
      .forEach(initGuidedRemediationLab);
  });
})();
