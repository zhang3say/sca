/* ==========================================================================
   Reusable Interactive Component: Runtime Reachability & Container Debloating Lab
   Zero-dependency vanilla JS for Lesson 0012+.
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

  function initRuntimeReachabilityLab(container) {
    const dataEl = container.querySelector("script.runtime-reachability-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const state = {
      activeTab: "fusion", // "fusion" | "roi"
      presetId: "log4j-cold-path",
      // Tab 1: 3D Fusion Simulator
      staticState: "REACHABLE", // "REACHABLE" | "POTENTIALLY_REACHABLE" | "UNREACHABLE" | "OS_PKG_L0"
      runtimeSignal: "NOT_OBSERVED", // "EXECUTED_FUNC" | "LOADED_CLASS_OR_LIB" | "NOT_OBSERVED" | "NO_TELEMETRY"
      windowDays: 14, // 1 | 7 | 14
      batchCovered: true,
      internetExposed: true,
      // Tab 2: Container Debloating & Telemetry ROI Calculator
      imageStrategy: "distroless-apko", // "standard" | "distroless-apko" | "mint-runtime"
      telemetryMode: "jvm-jfr", // "none" | "os-ebpf" | "jvm-jfr" | "sampling-mon" | "full-bytecode"
      rawOsCves: 180,
      rawAppCves: 60,
      coveragePct: 55,
    };

    const PRESETS = [
      {
        id: "log4j-cold-path",
        label: "1. Exploit-Only 冷路径（静态可达 + 运行时未观测）",
        apply: {
          staticState: "REACHABLE",
          runtimeSignal: "NOT_OBSERVED",
          windowDays: 14,
          batchCovered: true,
          internetExposed: true,
        },
      },
      {
        id: "spring-reflection-confirm",
        label: "2. Spring 反射盲区实锤（JFR jdk.ClassLoad 确认）",
        apply: {
          staticState: "POTENTIALLY_REACHABLE",
          runtimeSignal: "LOADED_CLASS_OR_LIB",
          windowDays: 7,
          batchCovered: false,
          internetExposed: true,
        },
      },
      {
        id: "static-soundness-alert",
        label: "3. 静态漏报反哺（UNREACHABLE 却在生产执行）",
        apply: {
          staticState: "UNREACHABLE",
          runtimeSignal: "EXECUTED_FUNC",
          windowDays: 1,
          batchCovered: false,
          internetExposed: true,
        },
      },
      {
        id: "os-bloat-container",
        label: "4. 容器冗余 OS 包（窗未成熟 vs 14天完整周期）",
        apply: {
          staticState: "OS_PKG_L0",
          runtimeSignal: "NOT_OBSERVED",
          windowDays: 14,
          batchCovered: true,
          internetExposed: false,
        },
      },
    ];

    const STATIC_META = {
      REACHABLE: {
        short: "L4 REACHABLE",
        detail: "完整静态调用栈已连通公开 Trigger API / Sink",
        pkg: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        symbol: "org.apache.logging.log4j.core.lookup.JndiLookup#lookup",
      },
      POTENTIALLY_REACHABLE: {
        short: "POTENTIALLY_REACHABLE",
        detail: "含 UNKNOWN_DYNAMIC（Spring 反射 / Jackson 多态断链）",
        pkg: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
        symbol: "com.fasterxml.jackson.databind.ObjectMapper#readValue",
      },
      UNREACHABLE: {
        short: "L4 UNREACHABLE",
        detail: "静态图封闭剪枝判定不可达（待校验静态完备性）",
        pkg: "pkg:pypi/pyyaml@5.3.1",
        symbol: "yaml#load",
      },
      OS_PKG_L0: {
        short: "OS_PKG_L0 (无调用图)",
        detail: "基础镜像 apt/dpkg 安装的工具链（curl / openssl / bash）",
        pkg: "pkg:deb/debian/curl@7.88.1-10+deb12u5?arch=amd64",
        symbol: "/usr/bin/curl (OS ELF binary)",
      },
    };

    const RUNTIME_META = {
      EXECUTED_FUNC: {
        short: "EXECUTED_FUNC",
        source: "JFR ExecutionSample / PEP 669 PY_START / V8 Coverage",
        detail: "采样栈或事件钩子直接捕获目标函数真实执行",
      },
      LOADED_CLASS_OR_LIB: {
        short: "LOADED_CLASS_OR_LIB",
        source: "JFR jdk.ClassLoad / Kubescape eBPF File Open",
        detail: "目标类或共享库已被装载进进程内存，但具体函数尚未采样命中",
      },
      NOT_OBSERVED: {
        short: "NOT_OBSERVED",
        source: "Kubescape ApplicationProfile / JFR Window Aggregator",
        detail: "观测周期内探针正常工作，但目标文件/类/函数均未触发记录",
      },
      NO_TELEMETRY: {
        short: "NO_TELEMETRY",
        source: "Offline / CI-only / Probe Detached",
        detail: "未部署运行时探针或探针心跳失联（无可用运行上下文）",
      },
    };

    function evaluateFusion() {
      const s = state.staticState;
      const r = state.runtimeSignal;
      const mature = state.windowDays >= 14 && state.batchCovered;
      const staticInfo = STATIC_META[s];
      const runtimeInfo = RUNTIME_META[r];

      let fusedStatus = "";
      let bannerCls = "is-info";
      let vexAllowed = false;
      let vexJustification = "none";
      let actionLabel = "";
      let summary = "";
      let gateNote = "";
      let soundnessAlert = false;

      if (r === "NO_TELEMETRY") {
        if (s === "UNREACHABLE") {
          fusedStatus = "STATIC_UNREACHABLE";
          bannerCls = "is-ok";
          vexAllowed = true;
          vexJustification = "code_not_reachable";
          actionLabel = "沿用静态结论：签发 VEX 降噪";
          summary = "无运行时探针介入，但静态调用图已完成封闭剪枝，保持 Lesson 0011 静态 VEX 降噪逻辑。";
          gateNote = "VEX 理由码：code_not_reachable（纯静态证明）。";
        } else {
          fusedStatus = "STATIC_FALLBACK_" + s;
          bannerCls = s === "REACHABLE" ? "is-bad" : "is-warn";
          vexAllowed = false;
          actionLabel = s === "REACHABLE" ? "P0 阻断与修复" : "回退静态置信度队列";
          summary = "探针离线或处于 CI 构建阶段（NO_TELEMETRY），严禁静默降级，完全回退至静态 L4 / L0 基线策略。";
          gateNote = "VEX 禁止签发：无运行态数据不可替代静态约束。";
        }
      } else if (s === "UNREACHABLE" && (r === "EXECUTED_FUNC" || r === "LOADED_CLASS_OR_LIB")) {
        fusedStatus = "STATIC_SOUNDNESS_ALERT";
        bannerCls = "is-bad";
        vexAllowed = false;
        soundnessAlert = true;
        actionLabel = "立即升级 P0 + 触发静态调用图缺陷工单";
        summary =
          "致命反向校验命中！静态分析误判为 UNREACHABLE，但生产运行时却观测到了实际加载/执行。说明静态图存在反射、动态代理或入口缺失漏边，必须立刻撤回任何 VEX 豁免并把缺失边反哺回 Layer 4 引擎！";
        gateNote = "自愈闭环：自动撤销旧 VEX 并上报 CALLGRAPH_FN_BUG。";
      } else if (r === "EXECUTED_FUNC") {
        fusedStatus = "CONFIRMED_EXPLOITABLE_PATH";
        bannerCls = "is-bad";
        vexAllowed = false;
        actionLabel = state.internetExposed ? "最高优先 P0 · 紧急阻断与热修" : "P1 高危 · 函数已在生产热路径运行";
        summary =
          "静态可达与运行时函数执行双重实锤！漏洞代码正在承载真实业务流量" +
          (state.internetExposed ? "且暴露于公网入口，构成最高优先级可利用风险。" : "（内部隔离网格暴露面），建议直接进入 Lesson 0014 自动修复。");
        gateNote = "VEX 严格禁止：双模态实证确认处于活跃执行路径。";
      } else if (r === "LOADED_CLASS_OR_LIB") {
        if (s === "POTENTIALLY_REACHABLE" || s === "REACHABLE") {
          fusedStatus = "RUNTIME_CONFIRMED_REACHABLE";
          bannerCls = "is-bad";
          vexAllowed = false;
          actionLabel = "P0/P1 阻断（静态盲区已由加载事件补全）";
          summary =
            s === "POTENTIALLY_REACHABLE"
              ? "成功击穿静态断链！静态侧因反射/Spring DI 标记为 UNKNOWN_DYNAMIC，但运行时 JFR/eBPF 实锤类/共享库已装载进进程内存，确认组件活跃且可被触发。"
              : "静态可达 + 运行时类已装载进内存，属于高确定性真实暴露风险，严禁因暂未采到函数帧而降级。";
          gateNote = "VEX 严格禁止：目标字节码/共享库已进入运行时内存空间。";
        } else {
          fusedStatus = "OS_IN_USE_RUNTIME";
          bannerCls = state.internetExposed ? "is-bad" : "is-warn";
          vexAllowed = false;
          actionLabel = "纳入容器真实在用依赖清单（SBOMFiltered 保留）";
          summary =
            "OS 组件或工具文件在运行期被进程打开/execve 调用，从冗余噪声升级为「运行态在用依赖」，必须保留并按暴露面排序修复。";
          gateNote = "Kubescape SBOMSyftFiltered：保留该资产并触发告警。";
        }
      } else if (r === "NOT_OBSERVED") {
        if (s === "REACHABLE") {
          fusedStatus = "LATENT_REACHABLE";
          bannerCls = "is-bad";
          vexAllowed = false;
          actionLabel = "保留 P1 高危！严禁因“未观测到”关闭";
          summary =
            "【冷路径 / Exploit-Only Gadget 铁律】尽管已观测 " +
            state.windowDays +
            " 天且" +
            (state.batchCovered ? "覆盖批处理" : "未覆盖批处理") +
            "，但静态调用图已证明入口可达。类似 Log4j JndiLookup 在正常业务下从不执行，专等攻击载荷触发，绝不能让动态“未观测”推翻静态可达！";
          gateNote = "VEX 严格禁止：静态证明可达时 NOT_OBSERVED 仅作 P0→P1 微调依据，绝不可签发 code_not_reachable。";
        } else if (s === "POTENTIALLY_REACHABLE") {
          if (mature) {
            fusedStatus = "DORMANT_POTENTIAL_CANDIDATE";
            bannerCls = "is-warn";
            vexAllowed = false;
            actionLabel = "降权为 P2 观察态（暂不自动签发 VEX）";
            summary =
              "静态仅因动态派发保守标记，且历经 ≥14 天并覆盖完整批处理周期后依然零加载记录。可将优先级从 P1 降至 P2 释放研发带宽，但因静态未封死仍建议靠 EPSS/KEV（Lesson 0013）二次把关。";
            gateNote = "降噪但不豁免：保留记录降级告警，不自动签发 VEX。";
          } else {
            fusedStatus = "INSUFFICIENT_WINDOW";
            bannerCls = "is-warn";
            vexAllowed = false;
            actionLabel = "观测窗口未成熟，维持 P1 待核";
            summary =
              "当前观测窗仅 " +
              state.windowDays +
              " 天" +
              (state.batchCovered ? "" : "且未覆盖月结/定时批处理周期") +
              "。存在强冷路径漏报风险，必须等待窗口成熟后再下调优先级。";
            gateNote = "窗口守门拦截：须满足 >= 14 天且 batch_cycle_covered = true。";
          }
        } else if (s === "UNREACHABLE") {
          fusedStatus = "VERIFIED_UNREACHABLE";
          bannerCls = "is-ok";
          vexAllowed = true;
          vexJustification = "code_not_reachable";
          actionLabel = "双证合璧消噪 · 自动签发 OpenVEX 豁免";
          summary =
            "黄金组合！静态调用图证明无任何可达路径，且运行时观测同样零装载/零执行。可将误报安全置信度推至最高并自动签发可审计 VEX。";
          gateNote = "VEX 自动放行：code_not_reachable（静动态双证闭环）。";
        } else {
          // OS_PKG_L0 + NOT_OBSERVED
          if (mature) {
            fusedStatus = "OS_INACTIVE_CANDIDATE";
            bannerCls = "is-ok";
            vexAllowed = true;
            vexJustification = "vulnerable_code_not_in_execute_path";
            actionLabel = state.internetExposed
              ? "P3 低危 + 建议迁移 Distroless 彻底删包"
              : "60%–80% OS 消噪命中 · 建议下一版镜像裁剪消除";
            summary =
              "OS 工具链/包历经 ≥14 天完整业务与批处理周期后从未被进程打开或执行，属于典型的容器镜像臃肿残留（对标 Kubescape SBOMSyftFiltered）。" +
              (state.internetExposed
                ? "注意：容器直面公网时，留存未用 curl/bash 仍可能被 RCE 后渗透利用，根本治本路径是迁移 Distroless/apko！"
                : "");
            gateNote = "VEX / 过滤允许：标注非活跃组件并建议构建期裁剪（Distroless / apko）。";
          } else {
            fusedStatus = "INSUFFICIENT_WINDOW";
            bannerCls = "is-warn";
            vexAllowed = false;
            actionLabel = "窗口过短（未过批处理周期），暂缓剔除";
            summary =
              "虽然目前未观测到该 OS 包被读取，但观测窗口仅 " +
              state.windowDays +
              " 天" +
              (state.batchCovered ? "" : "且未涵盖周末/月结任务") +
              "，若此时盲目过滤或使用 Mint 删文件，极易误删冷门运维或故障恢复脚本。";
            gateNote = "窗口守门拦截：至少观测 14 天并覆盖批处理周期。";
          }
        }
      }

      const payload = {
        component_purl: staticInfo.pkg,
        static_reachability: s,
        runtime_evidence: {
          signal_level: r,
          collector_source: runtimeInfo.source,
          observation_window_days: r === "NO_TELEMETRY" ? 0 : state.windowDays,
          batch_cycle_covered: r === "NO_TELEMETRY" ? false : state.batchCovered,
          internet_exposed: state.internetExposed,
          observed_symbol_or_file: r === "NOT_OBSERVED" || r === "NO_TELEMETRY" ? null : staticInfo.symbol,
        },
        fusion_decision: {
          status: fusedStatus,
          vex_auto_suppress_allowed: vexAllowed,
          vex_justification: vexAllowed ? vexJustification : null,
          static_soundness_feedback: soundnessAlert,
        },
      };

      return {
        staticInfo,
        runtimeInfo,
        mature,
        fusedStatus,
        bannerCls,
        vexAllowed,
        actionLabel,
        summary,
        gateNote,
        soundnessAlert,
        payloadJson: JSON.stringify(payload, null, 2),
      };
    }

    function evaluateRoi() {
      const imgProfiles = {
        standard: {
          name: "常规 Debian/Ubuntu 基础镜像",
          osFactor: 1.0,
          missingRiskBase: 2,
          debugScore: "高（保留 shell / apt 易排查）",
          note: "镜像携带大量闲置基础包（~180+ CVE），极度依赖运行期 eBPF 过滤噪声。",
        },
        "distroless-apko": {
          name: "构建期最小化（Distroless / Wolfi apko）",
          osFactor: 0.12,
          missingRiskBase: 14,
          debugScore: "中（无 shell，需配 kubectl debug 临时容器）",
          note: "在构建期用显式依赖闭包直接消除 85%–90% OS 臃肿 CVE，且生成完整确定性 SBOM，商业闭源零红线。",
        },
        "mint-runtime": {
          name: "运行期动态裁剪（MinToolkit / Mint）",
          osFactor: 0.16,
          missingRiskBase: 72,
          debugScore: "极低（黑盒破坏风险 + 易剥离包管理器收据）",
          note: "按测试期文件访问删文件，一旦测试覆盖率不足（<85%），极易把冷路径 libnss_dns.so 或异常模块误删导致线上崩溃。",
        },
      };

      const telProfiles = {
        none: {
          name: "无运行时探针（仅静态基线）",
          osNoiseCut: 0.0,
          appNoiseCut: 0.35,
          cpuOverhead: 0.0,
          blindRisk: "低（依赖静态保守判定）",
        },
        "os-ebpf": {
          name: "Tier R1 · OS 文件/进程活跃度（Kubescape eBPF）",
          osNoiseCut: 0.74,
          appNoiseCut: 0.38,
          cpuOverhead: 0.6,
          blindRisk: "中低（可消 70%+ 冗余 OS 包噪音，不碰函数冷路径）",
        },
        "jvm-jfr": {
          name: "Tier R2 · 类/模块装载事件（JFR jdk.ClassLoad）",
          osNoiseCut: 0.74,
          appNoiseCut: 0.56,
          cpuOverhead: 0.85,
          blindRisk: "低（只证实已加载类以打穿反射盲区，不凭空豁免未调用类）",
        },
        "sampling-mon": {
          name: "Tier R3 · 轻量采样/原生钩子（JFR + PEP 669 / V8）",
          osNoiseCut: 0.75,
          appNoiseCut: 0.65,
          cpuOverhead: 1.8,
          blindRisk: "中（若错误直接剔除未采样冷路径会漏报，须配合 14 天窗口门控）",
        },
        "full-bytecode": {
          name: "反面教材：全量字节码/sys.settrace 逐行插桩",
          osNoiseCut: 0.75,
          appNoiseCut: 0.7,
          cpuOverhead: 14.5,
          blindRisk: "极高运维代价（远超 3% 生产 SLA 门限，引发延迟毛刺与研发抗拒）",
        },
      };

      const img = imgProfiles[state.imageStrategy];
      const tel = telProfiles[state.telemetryMode];

      const effectiveRawOs = Math.round(state.rawOsCves * img.osFactor);
      const remainingOs = Math.round(effectiveRawOs * (1 - tel.osNoiseCut));
      const remainingApp = Math.round(state.rawAppCves * (1 - tel.appNoiseCut));
      const totalRaw = state.rawOsCves + state.rawAppCves;
      const totalRemaining = remainingOs + remainingApp;
      const cutPct = Math.max(0, Math.min(99, Math.round(((totalRaw - totalRemaining) / totalRaw) * 100)));

      // Cold-path breakage / false-negative risk index (0-100)
      let crashOrFnRisk = img.missingRiskBase;
      if (state.imageStrategy === "mint-runtime") {
        crashOrFnRisk = Math.min(98, Math.max(18, Math.round((100 - state.coveragePct) * 1.15)));
      } else if (state.imageStrategy === "distroless-apko") {
        crashOrFnRisk = Math.max(6, Math.round((100 - state.coveragePct) * 0.2));
      } else {
        crashOrFnRisk = Math.max(2, Math.round((100 - state.coveragePct) * 0.12));
      }

      let riskLabel = "低（生产稳健）";
      let riskCls = "is-ok";
      if (crashOrFnRisk >= 55) {
        riskLabel = "极高（冷路径误删/崩溃高发）";
        riskCls = "is-warn";
      } else if (crashOrFnRisk >= 28) {
        riskLabel = "中等（需配套回归与临时调试容器）";
        riskCls = "is-blue";
      }

      const slaPass = tel.cpuOverhead <= 3.0;
      let verdictTitle = "";
      let verdictCls = "is-ok";
      let verdictDesc = "";

      if (!slaPass) {
        verdictTitle = "严重超出 3% 生产性能 SLA 红线：全量插桩将在业务峰值拖垮吞吐与 P99 延迟";
        verdictCls = "is-bad";
        verdictDesc =
          "生产环境严禁使用 sys.settrace、全量字节码插桩或高频轮询 Instrumentation.getAllLoadedClasses()。应切换为 OpenJDK JFR（<1% 开销）、PEP 669 sys.monitoring 或 V8 原生采样钩子。";
      } else if (state.imageStrategy === "mint-runtime" && state.coveragePct < 80) {
        verdictTitle = "高危生产事故预警：测试覆盖率仅 " + state.coveragePct + "% 时启用 Mint 动态删文件极易删掉冷路径依赖";
        verdictCls = "is-bad";
        verdictDesc =
          "动态去臃肿无法识别未走到的异常处理器、DNS 解析库（libnss_dns.so）或夜间对账分支。当前误删风险指数高达 " +
          crashOrFnRisk +
          "/100，强烈建议先改用构建期 Distroless / apko 声明式最小闭包。";
      } else if (state.imageStrategy === "distroless-apko" && (state.telemetryMode === "os-ebpf" || state.telemetryMode === "jvm-jfr" || state.telemetryMode === "sampling-mon")) {
        verdictTitle = "商业甜点架构：构建期最小闭包（Distroless / apko）+ 轻量运行态观测，兼顾 < 2% 开销与高消噪";
        verdictCls = "is-ok";
        verdictDesc =
          "既在源头靠 Apache-2.0 构建底座消灭了近九成 OS 臃肿包与 Shell 武器库，又在运行期以极低 CPU 开销实证补齐反射盲区，把待修 CVE 从 " +
          totalRaw +
          " 条压至 " +
          totalRemaining +
          " 条（降噪 " +
          cutPct +
          "%）。";
      } else {
        verdictTitle = "可执行配置：消噪 " + cutPct + "% · 运行时 CPU 税 " + tel.cpuOverhead.toFixed(1) + "%";
        verdictCls = state.imageStrategy === "standard" && state.telemetryMode === "none" ? "is-warn" : "is-info";
        verdictDesc = img.note + " " + tel.blindRisk + "。";
      }

      return {
        img,
        tel,
        effectiveRawOs,
        remainingOs,
        remainingApp,
        totalRaw,
        totalRemaining,
        cutPct,
        crashOrFnRisk,
        riskLabel,
        riskCls,
        slaPass,
        verdictTitle,
        verdictCls,
        verdictDesc,
      };
    }

    function render() {
      let bodyHtml = "";

      if (state.activeTab === "fusion") {
        const res = evaluateFusion();
        const presetBtns = PRESETS.map(
          (p) =>
            `<button type="button" class="rrl-preset-btn ${state.presetId === p.id ? "active" : ""}" data-action="set-preset" data-id="${escapeHtml(
              p.id
            )}">${escapeHtml(p.label)}</button>`
        ).join("");

        const staticOpts = [
          { val: "REACHABLE", label: "L4 REACHABLE" },
          { val: "POTENTIALLY_REACHABLE", label: "POTENTIALLY_REACHABLE" },
          { val: "UNREACHABLE", label: "L4 UNREACHABLE" },
          { val: "OS_PKG_L0", label: "OS_PKG_L0 (无图)" },
        ];
        const runtimeOpts = [
          { val: "EXECUTED_FUNC", label: "EXECUTED_FUNC" },
          { val: "LOADED_CLASS_OR_LIB", label: "LOADED_CLASS_OR_LIB" },
          { val: "NOT_OBSERVED", label: "NOT_OBSERVED" },
          { val: "NO_TELEMETRY", label: "NO_TELEMETRY" },
        ];
        const windowOpts = [
          { val: 1, label: "1 天" },
          { val: 7, label: "7 天" },
          { val: 14, label: "14 天" },
        ];

        bodyHtml = `
          <div class="vlab-section-label">典型生产实景预设（亦可下方自由组合静态态、运行时信号与观测窗口）</div>
          <div class="rrl-preset-bar">${presetBtns}</div>

          <div class="rrl-controls-grid">
            <div class="rrl-ctrl-group">
              <span class="rrl-ctrl-label">1. 静态 L4 / L0 结论：</span>
              <div class="rrl-pill-row">
                ${staticOpts
                  .map(
                    (o) =>
                      `<button type="button" class="rrl-pill-btn ${state.staticState === o.val ? "active" : ""}" data-action="set-static" data-val="${escapeHtml(
                        o.val
                      )}">${escapeHtml(o.label)}</button>`
                  )
                  .join("")}
              </div>
            </div>
            <div class="rrl-ctrl-group">
              <span class="rrl-ctrl-label">2. 运行时采集信号：</span>
              <div class="rrl-pill-row">
                ${runtimeOpts
                  .map(
                    (o) =>
                      `<button type="button" class="rrl-pill-btn ${state.runtimeSignal === o.val ? "active" : ""}" data-action="set-runtime" data-val="${escapeHtml(
                        o.val
                      )}">${escapeHtml(o.label)}</button>`
                  )
                  .join("")}
              </div>
            </div>
            <div class="rrl-ctrl-group rrl-ctrl-inline">
              <div class="rrl-pill-row">
                <span class="rrl-ctrl-label">3. 观测窗口：</span>
                ${windowOpts
                  .map(
                    (w) =>
                      `<button type="button" class="rrl-pill-btn ${state.windowDays === w.val ? "active" : ""}" data-action="set-window" data-val="${w.val}">${escapeHtml(
                        w.label
                      )}</button>`
                  )
                  .join("")}
              </div>
              <label class="rrl-toggle-label">
                <input type="checkbox" data-action="toggle-batch" ${state.batchCovered ? "checked" : ""} />
                <span>已覆盖批处理/定时周期 (<code>batch_cycle_covered</code>)</span>
              </label>
              <label class="rrl-toggle-label">
                <input type="checkbox" data-action="toggle-exposed" ${state.internetExposed ? "checked" : ""} />
                <span>公网暴露面 (<code>internet_exposed</code>)</span>
              </label>
            </div>
          </div>

          <div class="rrl-verdict-banner ${res.bannerCls}">
            <div>
              <strong>融合裁决态：<code>${escapeHtml(res.fusedStatus)}</code></strong>
              <span style="margin-left:0.55rem;">${escapeHtml(res.actionLabel)}</span>
            </div>
            <span class="badge ${res.vexAllowed ? "badge-ok" : "badge-danger"}">
              ${res.vexAllowed ? "允许自动 VEX 豁免" : "禁止自动 VEX 豁免"}
            </span>
          </div>

          <div class="rrl-stage-row">
            <div class="rrl-stage-card is-static">
              <div class="rrl-stage-kicker">输入 A · 静态分析基线</div>
              <div class="rrl-stage-title">${escapeHtml(res.staticInfo.short)}</div>
              <div class="rrl-stage-meta">${escapeHtml(res.staticInfo.detail)}</div>
            </div>
            <div class="rrl-stage-plus">+</div>
            <div class="rrl-stage-card is-runtime">
              <div class="rrl-stage-kicker">输入 B · 标准化 RuntimeEvidence</div>
              <div class="rrl-stage-title">${escapeHtml(res.runtimeInfo.short)}</div>
              <div class="rrl-stage-meta">窗口：${state.runtimeSignal === "NO_TELEMETRY" ? "N/A" : state.windowDays + " 天"} · 周期完备：${
          res.mature ? "是" : "否"
        }</div>
            </div>
            <div class="rrl-stage-plus">&rarr;</div>
            <div class="rrl-stage-card ${res.soundnessAlert || !res.vexAllowed ? "is-alert" : "is-safe"}">
              <div class="rrl-stage-kicker">输出 · 3D 融合仲裁门</div>
              <div class="rrl-stage-title">${escapeHtml(res.fusedStatus)}</div>
              <div class="rrl-stage-meta">${escapeHtml(res.gateNote)}</div>
            </div>
          </div>

          <div class="rrl-split-grid">
            <div class="rrl-card">
              <h4>架构师裁决剖析与防漏报护栏</h4>
              <p>${escapeHtml(res.summary)}</p>
              <p><strong>核心工程要点：</strong>永远把静态调用图当作「潜在风险边界」，把运行时观测当作「真实执行加权信号与反射补全器」——绝不允许用短期 <code>NOT_OBSERVED</code> 反向覆盖静态已证实可达的冷路径。</p>
            </div>
            <div class="rrl-card">
              <h4>Layer 2 IR 标准化 <code>RuntimeEvidence</code> 融合载荷</h4>
              <pre class="rrl-code-preview">${escapeHtml(res.payloadJson)}</pre>
            </div>
          </div>
        `;
      } else {
        const roi = evaluateRoi();
        const imgBtns = [
          { id: "standard", label: "常规 Debian/Ubuntu 镜像" },
          { id: "distroless-apko", label: "构建期最小化（Distroless / apko）" },
          { id: "mint-runtime", label: "运行期动态裁剪（MinToolkit）" },
        ];
        const telBtns = [
          { id: "none", label: "无探针" },
          { id: "os-ebpf", label: "OS eBPF（Kubescape）" },
          { id: "jvm-jfr", label: "JFR jdk.ClassLoad" },
          { id: "sampling-mon", label: "JFR + PEP 669 / V8" },
          { id: "full-bytecode", label: "全量插桩（反例）" },
        ];

        const maxOverheadScale = 16; // % CPU
        const slaMarkPct = ((3.0 / maxOverheadScale) * 100).toFixed(1);
        const cpuBarPct = Math.min(100, (roi.tel.cpuOverhead / maxOverheadScale) * 100).toFixed(1);
        const noiseKeepPct = Math.max(2, 100 - roi.cutPct).toFixed(1);

        bodyHtml = `
          <div class="rrl-controls-grid">
            <div class="rrl-ctrl-group">
              <span class="rrl-ctrl-label">容器裁剪路线：</span>
              <div class="rrl-pill-row">
                ${imgBtns
                  .map(
                    (b) =>
                      `<button type="button" class="rrl-pill-btn ${state.imageStrategy === b.id ? "active" : ""}" data-action="set-img" data-val="${escapeHtml(
                        b.id
                      )}">${escapeHtml(b.label)}</button>`
                  )
                  .join("")}
              </div>
            </div>
            <div class="rrl-ctrl-group">
              <span class="rrl-ctrl-label">运行时探针层级：</span>
              <div class="rrl-pill-row">
                ${telBtns
                  .map(
                    (b) =>
                      `<button type="button" class="rrl-pill-btn ${state.telemetryMode === b.id ? "active" : ""}" data-action="set-tel" data-val="${escapeHtml(
                        b.id
                      )}">${escapeHtml(b.label)}</button>`
                  )
                  .join("")}
              </div>
            </div>
          </div>

          <div class="rrl-slider-grid">
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rrl-os-cves">原始镜像 OS CVE 数</label>
                <span>${state.rawOsCves} 条</span>
              </div>
              <input id="rrl-os-cves" class="vlab-range" type="range" min="40" max="320" step="10" value="${state.rawOsCves}" data-action="slide" data-key="rawOsCves" />
              <div class="vlab-slider-hint">典型 Debian/Ubuntu 基础层约 120–240 条</div>
            </div>
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rrl-app-cves">原始应用层 CVE 数</label>
                <span>${state.rawAppCves} 条</span>
              </div>
              <input id="rrl-app-cves" class="vlab-range" type="range" min="20" max="120" step="5" value="${state.rawAppCves}" data-action="slide" data-key="rawAppCves" />
              <div class="vlab-slider-hint">Java / Python / Node.js 传递依赖告警</div>
            </div>
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rrl-cov">测试 / 流量分支覆盖率</label>
                <span>${state.coveragePct}%</span>
              </div>
              <input id="rrl-cov" class="vlab-range" type="range" min="20" max="95" step="5" value="${state.coveragePct}" data-action="slide" data-key="coveragePct" />
              <div class="vlab-slider-hint">决定动态删文件（Mint）误删冷路径概率</div>
            </div>
          </div>

          <div class="rrl-verdict-banner ${roi.verdictCls}">
            <div><strong>${escapeHtml(roi.verdictTitle)}</strong></div>
            <span class="badge ${roi.slaPass ? "badge-ok" : "badge-danger"}">
              ${roi.slaPass ? "符合 < 3% 生产 CPU SLA" : "违反 3% 生产 CPU SLA"}
            </span>
          </div>

          <div class="rrl-kpi-strip">
            <div class="vlab-kpi is-ok">
              <div class="vlab-kpi-label">需优先处理有效 CVE（降噪后）</div>
              <div class="vlab-kpi-num">${roi.totalRemaining} / ${roi.totalRaw} 条</div>
              <div class="vlab-kpi-sub">总体消噪率 <strong>${roi.cutPct}%</strong>（OS 留 ${roi.remainingOs} + 应用留 ${roi.remainingApp}）</div>
            </div>
            <div class="vlab-kpi ${roi.slaPass ? "is-blue" : "is-warn"}">
              <div class="vlab-kpi-label">生产探针 CPU 性能税</div>
              <div class="vlab-kpi-num">${roi.tel.cpuOverhead.toFixed(1)}%</div>
              <div class="vlab-kpi-sub">SLA 门限 &le; 3.0%（${roi.slaPass ? "生产可常驻开启" : "仅限压测或沙箱环境"}）</div>
            </div>
            <div class="vlab-kpi ${roi.riskCls}">
              <div class="vlab-kpi-label">冷路径误删 / 排障风险指数</div>
              <div class="vlab-kpi-num">${roi.crashOrFnRisk} / 100</div>
              <div class="vlab-kpi-sub">${escapeHtml(roi.riskLabel)} · 排障：${escapeHtml(roi.img.debugScore)}</div>
            </div>
          </div>

          <div class="rrl-bar-card">
            <div class="vlab-section-label">生产性能开销 vs 告警保留比例量化对比</div>
            <div class="rrl-bar-row">
              <div class="rrl-bar-head">
                <span>运行时探针 CPU 额外开销（标尺竖线 = 3.0% 生产准入上限）</span>
                <span style="font-family:var(--font-mono);">${roi.tel.cpuOverhead.toFixed(1)}% / 16.0%</span>
              </div>
              <div class="rrl-sla-ruler">
                <span class="rrl-sla-badge" style="left:${slaMarkPct}%;">3.0% 生产 SLA</span>
              </div>
              <div class="rrl-bar-track">
                <div class="rrl-sla-marker" style="left:${slaMarkPct}%;"></div>
                <div class="rrl-bar-fill ${roi.slaPass ? "is-fast" : "is-slow"}" style="width:${cpuBarPct}%;"></div>
              </div>
            </div>
            <div class="rrl-bar-row">
              <div class="rrl-bar-head">
                <span>裁剪 + 运行时过滤后仍需人工/修复关注的告警占比</span>
                <span style="font-family:var(--font-mono);">${roi.totalRemaining} 条 (${noiseKeepPct}%)</span>
              </div>
              <div class="rrl-bar-track">
                <div class="rrl-bar-fill ${Number(noiseKeepPct) <= 35 ? "is-fast" : "is-warn"}" style="width:${noiseKeepPct}%;"></div>
              </div>
            </div>
            <p class="rrl-bar-note">${escapeHtml(roi.verdictDesc)}</p>
          </div>
        `;
      }

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "动态运行时可达性与容器裁剪架构实验台")}</h3>
          <div class="widget-status">Layer 4 · Runtime Fusion &amp; Container Debloating</div>
        </div>
        ${config.intro ? `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.95rem;">${escapeHtml(config.intro)}</p>` : ""}

        <div class="rrl-tabs">
          <button type="button" class="rrl-tab ${state.activeTab === "fusion" ? "active" : ""}" data-action="set-tab" data-tab="fusion">
            <span class="vlab-tab-num">1</span>
            <span>静动态三维融合仲裁模拟器（Static &times; Runtime &times; Window）</span>
          </button>
          <button type="button" class="rrl-tab ${state.activeTab === "roi" ? "active" : ""}" data-action="set-tab" data-tab="roi">
            <span class="vlab-tab-num">2</span>
            <span>容器裁剪与探针性能税 / 误删风险 ROI 计算器</span>
          </button>
        </div>

        ${bodyHtml}
      `;

      // Bind listeners
      container.querySelectorAll('[data-action="set-tab"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTab = btn.dataset.tab;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-preset"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = PRESETS.find((p) => p.id === btn.dataset.id);
          if (found) {
            state.presetId = found.id;
            Object.assign(state, found.apply);
            render();
          }
        });
      });

      container.querySelectorAll('[data-action="set-static"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "custom";
          state.staticState = btn.dataset.val;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-runtime"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "custom";
          state.runtimeSignal = btn.dataset.val;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-window"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = "custom";
          state.windowDays = Number(btn.dataset.val);
          render();
        });
      });

      const batchEl = container.querySelector('[data-action="toggle-batch"]');
      if (batchEl) {
        batchEl.addEventListener("change", (e) => {
          state.presetId = "custom";
          state.batchCovered = e.target.checked;
          render();
        });
      }

      const exposedEl = container.querySelector('[data-action="toggle-exposed"]');
      if (exposedEl) {
        exposedEl.addEventListener("change", (e) => {
          state.presetId = "custom";
          state.internetExposed = e.target.checked;
          render();
        });
      }

      container.querySelectorAll('[data-action="set-img"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.imageStrategy = btn.dataset.val;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-tel"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.telemetryMode = btn.dataset.val;
          render();
        });
      });

      container.querySelectorAll('[data-action="slide"]').forEach((input) => {
        input.addEventListener("input", (e) => {
          state[e.target.dataset.key] = Number(e.target.value);
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="runtime-reachability-lab"]').forEach(initRuntimeReachabilityLab);
  });
})();
