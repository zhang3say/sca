/* ==========================================================================
   Reusable Interactive Component: Static Call Graph Reachability & Stitching Lab
   Zero-dependency vanilla JS for Lesson 0011+.
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

  function initReachabilityLab(container) {
    const dataEl = container.querySelector("script.reachability-cg-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const state = {
      activeTab: "scenarios", // "scenarios" | "calculator"
      presetId: "go-interface",
      // Scenario 1: Go Interface
      goAlgo: "VTA", // "CHA" | "RTA" | "VTA"
      goUnusedInstantiated: true,
      // Scenario 2: Java Spring DI + Deser
      javaSpringEntry: true,
      javaL3TriggerApi: true,
      // Scenario 3: JS/TS Callback & Side-effect
      jsLevel1SideEffect: true,
      jsIndirectionBounded: true,
      // Scenario 4: Python getattr() Guardrail
      pyUnknownGuardrail: true,
      // Tab 2: Calculator
      calcAlgo: "VTA", // "CHA" | "RTA" | "VTA" | "0-CFA"
      kloc: 60,
      transitivePkgs: 180,
      cacheHitRate: 90,
      rawCves: 160,
    };

    const PRESETS = [
      { id: "go-interface", label: "1. Go 接口派发消噪（CHA vs RTA vs VTA）" },
      { id: "java-spring-deser", label: "2. Java Spring DI + 多态反序列化盲区" },
      { id: "js-callback-sideeffect", label: "3. JS/TS 高阶回调与模块顶层副作用" },
      { id: "python-getattr-guard", label: "4. Python getattr() 反射与四态置信度护栏" },
    ];

    function evaluateScenario() {
      if (state.presetId === "go-interface") {
        const algo = state.goAlgo;
        const unusedNew = state.goUnusedInstantiated;

        let reachable = false;
        let verdictTone = "is-ok";
        let verdictBadge = "UNREACHABLE（精准消噪）";
        let verdictSummary = "";
        let edge2Label = "Type Flow";
        let edge2Cls = "is-pruned";
        let vulnNodeCls = "is-pruned";
        let reasoning = "";

        if (algo === "CHA") {
          reachable = true;
          verdictTone = "is-warn";
          verdictBadge = "REACHABLE（误报 FP）";
          verdictSummary =
            "CHA 仅看方法签名与接口实现关系：只要 VulnXMLParser 实现了 Parser.Parse，哪怕全工程从未实例化它，也必连入调用图并误报。";
          edge2Label = "签名匹配 (CHA)";
          edge2Cls = "is-fp";
          vulnNodeCls = "is-sink";
          reasoning =
            "CHA（Class Hierarchy Analysis）不追踪对象分配点（new / &T{}）。当多个结构体实现同一接口时，调用边呈扇形爆炸，产生大量不可执行假路径。";
        } else if (algo === "RTA") {
          if (unusedNew) {
            reachable = true;
            verdictTone = "is-warn";
            verdictBadge = "REACHABLE（误报 FP）";
            verdictSummary =
              "RTA 只维护“全程序已实例化类型全局集合”：测试/废弃函数里存在 &VulnXMLParser{}，RTA 就认为所有 Parser 接口变量都可能指向它！";
            edge2Label = "全局实例化集合 (RTA)";
            edge2Cls = "is-fp";
            vulnNodeCls = "is-sink";
            reasoning =
              "RTA（Rapid Type Analysis）比 CHA 进一步要求类型被实例化，但不区分实例流向了哪个变量；在微服务或大仓库中极易被死代码或测试分支污染。";
          } else {
            reachable = false;
            verdictTone = "is-ok";
            verdictBadge = "UNREACHABLE（RTA 暂消噪）";
            verdictSummary =
              "当前工程没有任何地方实例化 VulnXMLParser，RTA 得以剪掉该边；但一旦其他无关模块出现 new(VulnXMLParser)，RTA 立即退化误报。";
            edge2Label = "全局未实例化 (剪枝)";
            edge2Cls = "is-pruned";
            vulnNodeCls = "is-pruned";
            reasoning =
              "RTA 缺乏过程间变量数据流追踪，结果极易受无关测试模块或相邻包初始化代码影响，稳定性不足以支撑企业级门禁。";
          }
        } else {
          // VTA
          reachable = false;
          verdictTone = "is-ok";
          verdictBadge = "UNREACHABLE（VTA 精准消噪）";
          verdictSummary =
            "VTA 在 Go SSA 上构建变量级类型传播图，证明 handleWebhook(p Parser) 的参数变量 p 仅接收过 *SafeJSONParser，精准剪断至 VulnXMLParser 的虚调用边。";
          edge2Label = "VTA 剪枝（仅流向 SafeJSON）";
          edge2Cls = "is-pruned";
          vulnNodeCls = "is-pruned";
          reasoning =
            "这正是 Go 官方 govulncheck（golang.org/x/tools/go/callgraph/vta）的核心机制：逐变量传播类型集合，既防止全局污染又维持近线性扩展性能。";
        }

        const nodes = [
          { tag: "ENTRYPOINT", name: "cmd/api.main()", meta: "HTTP Server 启动入口", cls: "is-entry" },
          { tag: "1ST-PARTY", name: "handleWebhook(p Parser)", meta: "传入具体实参 &SafeJSONParser{}", cls: "is-mid" },
          { tag: "SAFE PATH", name: "SafeJSONParser.Parse()", meta: "唯一实际流经的变量具体类型", cls: "is-safe" },
          {
            tag: "CVE-202X SINK",
            name: "VulnXMLParser.Parse()",
            meta: unusedNew ? "虽在其他废弃模块被实例化，但未流入 handleWebhook" : "全工程未被任何变量路径触达",
            cls: vulnNodeCls,
          },
        ];

        const jsonPreview = reachable
          ? {
              analysis: {
                state: "affected_fp_risk",
                reachabilityConfidence: "REACHABLE",
                algorithm: algo,
              },
              evidence: {
                callstack: {
                  frames: [
                    { package: "cmd/api", function: "main" },
                    { package: "internal/webhook", function: "handleWebhook" },
                    { package: "github.com/acme/xmlparser", function: "VulnXMLParser.Parse" },
                  ],
                },
              },
            }
          : {
              bomRef: "pkg:golang/github.com/acme/xmlparser@1.4.2",
              vexAnalysis: {
                state: "not_affected",
                justification: "code_not_reachable",
                reachabilityConfidence: "UNREACHABLE",
                algorithm: algo,
                prunedEdge: "handleWebhook -> VulnXMLParser.Parse",
              },
            };

        return {
          verdictTone,
          verdictBadge,
          verdictSummary,
          reasoning,
          nodes,
          edges: [
            { label: "直接调用", cls: "is-reachable" },
            { label: "接口派发", cls: "is-pruned" },
            { label: edge2Label, cls: edge2Cls },
          ],
          jsonPreview,
          controlsHtml: `
            <div class="rcg-algo-pills">
              <span class="vlab-section-label" style="margin:0 0.35rem 0 0;">调用图算法:</span>
              ${["CHA", "RTA", "VTA"]
                .map(
                  (a) =>
                    `<button type="button" class="rcg-algo-btn ${state.goAlgo === a ? "active" : ""}" data-action="set-go-algo" data-val="${a}">${a}</button>`
                )
                .join("")}
            </div>
            <label class="rcg-toggle-label">
              <input type="checkbox" data-action="toggle-go-unused" ${state.goUnusedInstantiated ? "checked" : ""} />
              独立测试/废弃模块中存在 <code>new(VulnXMLParser)</code> 实例化
            </label>
          `,
        };
      }

      if (state.presetId === "java-spring-deser") {
        const hasSpring = state.javaSpringEntry;
        const hasTrigger = state.javaL3TriggerApi;

        let verdictTone = "is-ok";
        let verdictBadge = "REACHABLE（真阳命中 · 证据链完整）";
        let verdictSummary = "";
        let reasoning = "";
        let e1Cls = "is-reachable";
        let e2Cls = "is-reachable";
        let e3Cls = "is-reachable";
        let e1Lbl = "IoC 入口注入";
        let e2Lbl = "方法调用";
        let e3Lbl = "Trigger API 映射";
        let n1Cls = "is-entry";
        let n2Cls = "is-mid";
        let n3Cls = "is-mid";
        let n4Cls = "is-sink";

        if (!hasSpring) {
          verdictTone = "is-bad";
          verdictBadge = "UNREACHABLE（框架入口盲区导致致命漏报 FN！）";
          verdictSummary =
            "未建模 @RestController/@PostMapping 框架入口时，静态调用图只看到 main() -> SpringApplication.run()，OrderController.create() 成了不可达孤岛！";
          reasoning =
            "Reif et al. (ISSTA 2019 Judge) 指出：框架反转控制（IoC）、依赖注入与注解驱动路由是 Java 调用图最常见的 Unsoundness 漏报根源。必须为 Spring/Jakarta EE 建立合成入口点（Synthetic Entrypoints）。";
          e1Cls = "is-fn";
          e2Cls = "is-fn";
          e3Cls = "is-fn";
          e1Lbl = "缺失 DI 边 (FN)";
          e2Lbl = "孤岛断链";
          e3Lbl = "未触达";
          n1Cls = "is-blind";
          n2Cls = "is-pruned";
          n3Cls = "is-pruned";
          n4Cls = "is-pruned";
        } else if (!hasTrigger) {
          verdictTone = "is-bad";
          verdictBadge = "UNREACHABLE（反序列化 Sink 映射断裂导致漏报 FN！）";
          verdictSummary =
            "调用图虽到达 ObjectMapper.readValue()，但 L3 漏洞库只填了补丁修复的内部私有方法 Gadget.exec()；反射动态实例化无法静态连向该私有方法，导致危险反序列化被误判不可达！";
          reasoning =
            "对于反序列化/表达式注入/JNDI（如 Jackson、Log4Shell），漏洞在多态构造链或反射链内部触发。L3 符号映射管线必须把公开触发 API（Trigger API，如 readValue / logger.error）纳入 Sink 锚点。";
          e3Cls = "is-fn";
          e3Lbl = "反射断链 (FN)";
          n4Cls = "is-blind";
        } else {
          verdictTone = "is-bad";
          verdictBadge = "REACHABLE（Level 2 真阳命中 · P0 阻断）";
          verdictSummary =
            "Spring 入口模型补全 @PostMapping HTTP 入口，且 L3 漏洞库已将 ObjectMapper.readValue 标为反序列化 Trigger API，完整打通并输出 CycloneDX 调用栈证据！";
          reasoning =
            "通过「字节码框架入口合成 + L3 Trigger API 锚点」双管齐下，静态可达性在无需实际运行 JVM 的前提下精准捕获真阳路径，直接支撑 PR 门禁高置信度阻断。";
        }

        const nodes = [
          {
            tag: "SYNTHETIC ENTRY",
            name: "HTTP POST /api/orders",
            meta: hasSpring ? "Spring Web 框架入口模型已激活" : "仅见 main() -> SpringApplication.run()",
            cls: n1Cls,
          },
          {
            tag: "CONTROLLER",
            name: "OrderController.create()",
            meta: "@PostMapping 处理不可信 JSON 请求体",
            cls: n2Cls,
          },
          {
            tag: "TRIGGER API",
            name: "ObjectMapper.readValue()",
            meta: hasTrigger ? "已由 L3 漏洞库标为 Polymorphic Deser Trigger" : "未被标为 Trigger，静态继续往下追",
            cls: n3Cls,
          },
          {
            tag: "PATCHED METHOD",
            name: "GadgetClass.invoke()",
            meta: "官方补丁实际修改的深层多态/反射方法",
            cls: n4Cls,
          },
        ];

        const jsonPreview =
          hasSpring && hasTrigger
            ? {
                bomRef: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
                reachabilityConfidence: "REACHABLE",
                tier: "Level 2 (Function + Trigger API)",
                evidence: {
                  callstack: {
                    frames: [
                      { package: "com.acme.orders", module: "OrderController", function: "create" },
                      {
                        package: "com.fasterxml.jackson.databind",
                        module: "ObjectMapper",
                        function: "readValue",
                        parameters: ["jsonPayload", "OrderDTO.class"],
                      },
                    ],
                  },
                },
              }
            : {
                bomRef: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
                dangerWarning: "FALSE_NEGATIVE_TRAP",
                reportedStatus: "UNREACHABLE (误消警!)",
                missingLink: !hasSpring ? "Spring @PostMapping Synthetic Entrypoint" : "L3 Trigger API Tag on readValue()",
              };

        return {
          verdictTone,
          verdictBadge,
          verdictSummary,
          reasoning,
          nodes,
          edges: [
            { label: e1Lbl, cls: e1Cls },
            { label: e2Lbl, cls: e2Cls },
            { label: e3Lbl, cls: e3Cls },
          ],
          jsonPreview,
          controlsHtml: `
            <label class="rcg-toggle-label">
              <input type="checkbox" data-action="toggle-java-spring" ${state.javaSpringEntry ? "checked" : ""} />
              建模 Spring 框架入口（<code>@RestController</code> / <code>@PostMapping</code>）
            </label>
            <label class="rcg-toggle-label">
              <input type="checkbox" data-action="toggle-java-trigger" ${state.javaL3TriggerApi ? "checked" : ""} />
              L3 标注触发器入口 API（<code>ObjectMapper.readValue</code>）
            </label>
          `,
        };
      }

      if (state.presetId === "js-callback-sideeffect") {
        const hasSideEffect = state.jsLevel1SideEffect;
        const hasBounded = state.jsIndirectionBounded;

        let verdictTone = "is-bad";
        let verdictBadge = "";
        let verdictSummary = "";
        let reasoning = "";

        if (!hasSideEffect && !hasBounded) {
          verdictTone = "is-warn";
          verdictBadge = "UNREACHABLE（高阶回调 + 顶层副作用双重失明 FN！）";
          verdictSummary =
            "朴素 AST 既看不懂 app.use(verifyMiddleware) 传参高阶回调，又忽略了 require('evil-init') 导入瞬间的顶层副作用执行！";
          reasoning =
            "在 JavaScript / Node.js 中，大量库通过模块顶层语句直接修改全局原型或执行初始化代码，业务侧通过高阶函数注册回调。必须兼顾 Level 1 模块副作用与高阶流分析。";
        } else if (hasSideEffect && !hasBounded) {
          verdictTone = "is-warn";
          verdictBadge = "POTENTIALLY_REACHABLE（Level 1 命中顶层导入；回调仍断链）";
          verdictSummary =
            "Level 1 模块导入检测成功捕获 require('evil-init') 顶层副作用风险，但对 Express 中间件注册的 legacy-jwt.verify() 仍无法追出函数调用链。";
          reasoning =
            "当高阶函数与事件回调未建模时，开启 Level 1 至少能防止带顶层初始化/恶意投毒载荷的包被错杀为不可达，同时将动态回调降级为 POTENTIALLY_REACHABLE。";
        } else {
          verdictTone = "is-bad";
          verdictBadge = "REACHABLE（Level 2 + Indirection-Bounded 穿透高阶回调）";
          verdictSummary =
            "借鉴 Jelly（ISSTA 2021 / ECOOP 2024 Indirection-Bounded）模块化流分析，精准追踪 app.use 参数对象回调流向，输出 verifyMiddleware → legacy-jwt.verify() 调用栈" +
            (hasSideEffect ? "，同时标记 evil-init 模块顶层执行。" : "。");
          reasoning =
            "Nielsen 等（ISSTA 2021）与 Chakraborty/Møller（ECOOP 2024）证明：限定间接层数（Indirection-Bounded）的流不敏感分析可以在可控毫秒级开销内穿透 Node.js 模块边界与异步回调。";
        }

        const nodes = [
          { tag: "ENTRY MODULE", name: "src/server.ts", meta: "Node.js 服务主入口", cls: "is-entry" },
          {
            tag: "SIDE-EFFECT (L1)",
            name: "import 'evil-init'",
            meta: hasSideEffect ? "Level 1 捕获：模块加载即执行顶层语句" : "未检测顶层副作用（盲区）",
            cls: hasSideEffect ? "is-sink" : "is-blind",
          },
          {
            tag: "HIGHER-ORDER",
            name: "app.use(verifyMiddleware)",
            meta: hasBounded ? "Indirection-Bounded 解析回调注册流" : "仅视为普通传参，回调实体断开",
            cls: hasBounded ? "is-mid" : "is-blind",
          },
          {
            tag: "CVE SINK (L2)",
            name: "legacy-jwt.verify()",
            meta: hasBounded ? "成功连通回调内部危险验签函数" : "因回调断链而未能连接",
            cls: hasBounded ? "is-sink" : "is-pruned",
          },
        ];

        const jsonPreview = {
          ecosystem: "npm",
          reachabilityLevel: hasBounded ? "Level 2 (Function)" : hasSideEffect ? "Level 1 (Module Side-Effect)" : "Missed",
          confidence: hasBounded ? "REACHABLE" : hasSideEffect ? "POTENTIALLY_REACHABLE" : "UNREACHABLE_FN",
          topLevelImportSideEffects: hasSideEffect ? ["pkg:npm/evil-init@0.9.1 (index.js:1)"] : [],
          evidence: hasBounded
            ? {
                callstack: {
                  frames: [
                    { package: "acme-api", module: "src/server.ts", function: "<top-level>" },
                    { package: "acme-api", module: "src/auth.ts", function: "verifyMiddleware" },
                    { package: "legacy-jwt", module: "verify.js", function: "verify" },
                  ],
                },
              }
            : undefined,
        };

        return {
          verdictTone,
          verdictBadge,
          verdictSummary,
          reasoning,
          nodes,
          edges: [
            { label: hasSideEffect ? "顶层执行" : "被忽略", cls: hasSideEffect ? "is-reachable" : "is-fn" },
            { label: "回调注册", cls: hasBounded ? "is-reachable" : "is-fn" },
            { label: hasBounded ? "Bounded Flow" : "回调断链", cls: hasBounded ? "is-reachable" : "is-fn" },
          ],
          jsonPreview,
          controlsHtml: `
            <label class="rcg-toggle-label">
              <input type="checkbox" data-action="toggle-js-sideeffect" ${state.jsLevel1SideEffect ? "checked" : ""} />
              识别 Level 1 模块顶层导入副作用
            </label>
            <label class="rcg-toggle-label">
              <input type="checkbox" data-action="toggle-js-bounded" ${state.jsIndirectionBounded ? "checked" : ""} />
              启用 Indirection-Bounded 高阶函数分析（Jelly 范式）
            </label>
          `,
        };
      }

      // Scenario 4: python-getattr-guard
      const guardOn = state.pyUnknownGuardrail;
      const verdictTone = guardOn ? "is-info" : "is-bad";
      const verdictBadge = guardOn
        ? "POTENTIALLY_REACHABLE (UNKNOWN_DYNAMIC 护栏生效)"
        : "UNREACHABLE（严重错误：动态反射断链谎报安全！）";
      const verdictSummary = guardOn
        ? "静态调用图在 getattr(plugin_mod, user_action)() 处识别到无法静态解析的动态派发，且目标模块已导入高危 PyYAML；四态护栏自动降级为 POTENTIALLY_REACHABLE，严禁谎报不可达！"
        : "关闭四态护栏后，系统采用硬二元判决（连不通就当不可达）。views.py 中的 getattr() 导致调用链断裂，直接将真实可被攻击者触发的 yaml.unsafe_load 误消警！";
      const reasoning = guardOn
        ? "遵循 Soundiness 原则（Salis et al. ICSE 2021 PyCG 召回率约 69.9% 的现实边界）：静态分析面对 Python getattr / eval / importlib 必须具备自我认知能力，输出 UNKNOWN_DYNAMIC 并移交 Lesson 0012 运行时探针确认。"
        : "商业闭源 SCA 绝不可为了追求“降噪数字好看”而在动态语言上把断链一刀切标成 Not Affected——漏报 P0 远比误报更致命。";

      return {
        verdictTone,
        verdictBadge,
        verdictSummary,
        reasoning,
        nodes: [
          { tag: "ENTRYPOINT", name: "views.py:dispatch()", meta: "接收 HTTP 参数 user_action", cls: "is-entry" },
          {
            tag: "DYNAMIC DISPATCH",
            name: "getattr(plugin_mod, action)()",
            meta: "动态属性名派发，静态无法穷举目标",
            cls: "is-blind",
          },
          {
            tag: "GUARDRAIL",
            name: guardOn ? "Soundiness 断链探测" : "硬二元裁剪（危险！）",
            meta: guardOn ? "发现模块已 import yaml 且存在动态调用" : "静默丢弃未连通目标",
            cls: guardOn ? "is-entry" : "is-pruned",
          },
          {
            tag: "CVE SINK",
            name: "yaml.unsafe_load()",
            meta: "PyYAML 5.3.1 任意代码执行漏洞点",
            cls: guardOn ? "is-sink" : "is-pruned",
          },
        ],
        edges: [
          { label: "参数传入", cls: "is-unknown" },
          { label: guardOn ? "反射降级" : "静态断链", cls: guardOn ? "is-unknown" : "is-fn" },
          { label: guardOn ? "模块可达 (L1)" : "误判安全", cls: guardOn ? "is-unknown" : "is-fn" },
        ],
        jsonPreview: guardOn
          ? {
              bomRef: "pkg:pypi/pyyaml@5.3.1",
              reachabilityConfidence: "POTENTIALLY_REACHABLE",
              reasonCode: "UNKNOWN_DYNAMIC_DISPATCH",
              dynamicSite: "views.py:42 (getattr)",
              importedVulnerableModule: true,
              nextAction: "Route to Lesson 0012 Runtime Probe / Manual Review",
            }
          : {
              bomRef: "pkg:pypi/pyyaml@5.3.1",
              reachabilityConfidence: "UNREACHABLE",
              criticalBug: "SILENT_FALSE_NEGATIVE",
              warning: "在存在未解 getattr() 反射的动态语言中强行输出 not_affected 将引发 P0 安全漏报！",
            },
        controlsHtml: `
          <label class="rcg-toggle-label">
            <input type="checkbox" data-action="toggle-py-guardrail" ${state.pyUnknownGuardrail ? "checked" : ""} />
            启用四态置信度护栏（遇动态反射断链降级为 <code>POTENTIALLY_REACHABLE</code>，禁止谎报 <code>UNREACHABLE</code>）
          </label>
        `,
      };
    }

    function computeCalculatorMetrics() {
      const kloc = state.kloc;
      const pkgs = state.transitivePkgs;
      const hitRate = state.cacheHitRate / 100;
      const rawCves = state.rawCves;

      const algoSpec = {
        CHA: { mult: 0.45, fpRate: 0.48, unknownRate: 0.16, ramMult: 0.55, note: "最快但大量接口虚边误报（降噪率偏低）" },
        RTA: { mult: 0.72, fpRate: 0.31, unknownRate: 0.14, ramMult: 0.78, note: "受全局实例化集合污染，噪声仍偏高" },
        VTA: { mult: 1.15, fpRate: 0.16, unknownRate: 0.12, ramMult: 1.0, note: "Go/Java 甜点区：精确消噪且扩展性优异" },
        "0-CFA": { mult: 3.8, fpRate: 0.11, unknownRate: 0.10, ramMult: 2.6, note: "全程序指针分析在 PR 门禁极易超时爆内存" },
      }[state.calcAlgo];

      // Whole-program rebuild: must parse & analyze 1st-party + all transitive libs on every PR
      const wholeSec = +(
        (2.4 + kloc * 0.19 + pkgs * 0.46) *
        algoSpec.mult
      ).toFixed(1);
      const wholeRamGb = +(
        (0.55 + kloc * 0.008 + pkgs * 0.016) *
        algoSpec.ramMult
      ).toFixed(2);

      // Pre-computed summary + stitching: 1st-party analysis + miss penalty + tiny summary stitch
      const missPkgs = pkgs * (1 - hitRate);
      const stitchSec = +(
        1.1 +
        kloc * 0.095 * Math.min(algoSpec.mult, 1.55) +
        missPkgs * 0.42 * algoSpec.mult +
        pkgs * hitRate * 0.018
      ).toFixed(1);
      const stitchRamGb = +(
        0.35 +
        kloc * 0.006 * Math.min(algoSpec.ramMult, 1.4) +
        missPkgs * 0.015 * algoSpec.ramMult +
        pkgs * hitRate * 0.0012
      ).toFixed(2);

      const speedup = (wholeSec / Math.max(stitchSec, 0.1)).toFixed(1);
      const reachableCount = Math.max(1, Math.round(rawCves * algoSpec.fpRate));
      const potentialCount = Math.max(1, Math.round(rawCves * algoSpec.unknownRate));
      const unreachableCount = Math.max(0, rawCves - reachableCount - potentialCount);
      const suppressedPct = (((unreachableCount) / rawCves) * 100).toFixed(0);

      return {
        algoSpec,
        wholeSec,
        wholeRamGb,
        stitchSec,
        stitchRamGb,
        speedup,
        reachableCount,
        potentialCount,
        unreachableCount,
        suppressedPct,
      };
    }

    function render() {
      let bodyHtml = "";

      if (state.activeTab === "scenarios") {
        const res = evaluateScenario();
        bodyHtml = `
          <div class="rcg-preset-bar">
            ${PRESETS.map(
              (p) =>
                `<button type="button" class="rcg-preset-btn ${state.presetId === p.id ? "active" : ""}" data-action="set-preset" data-id="${p.id}">${escapeHtml(p.label)}</button>`
            ).join("")}
          </div>

          <div class="rcg-controls-bar">
            ${res.controlsHtml}
          </div>

          <div class="rcg-verdict-banner ${res.verdictTone}">
            <div>
              <strong>裁决结果：${escapeHtml(res.verdictBadge)}</strong>
              <div style="margin-top:0.2rem;">${escapeHtml(res.verdictSummary)}</div>
            </div>
          </div>

          <div class="rcg-graph-stage">
            <div class="vlab-section-label">调用路径与可达性剪枝拓扑（Entrypoint &rarr; Sink）</div>
            <div class="rcg-flow-row">
              ${res.nodes
                .map((n, i) => {
                  const edgeHtml =
                    i < res.edges.length
                      ? `<div class="rcg-edge ${res.edges[i].cls}">
                           <span>&rarr;</span>
                           <small>${escapeHtml(res.edges[i].label)}</small>
                         </div>`
                      : "";
                  return `
                    <div class="rcg-node ${n.cls}">
                      <div class="rcg-node-tag">${escapeHtml(n.tag)}</div>
                      <div class="rcg-node-name">${escapeHtml(n.name)}</div>
                      <div class="rcg-node-meta">${escapeHtml(n.meta)}</div>
                    </div>
                    ${edgeHtml}
                  `;
                })
                .join("")}
            </div>
          </div>

          <div class="rcg-split-grid">
            <div class="rcg-card">
              <h4>底层原理与 Soundiness 解析</h4>
              <p>${escapeHtml(res.reasoning)}</p>
              <p><strong>Layer 4 架构提示：</strong>永远把「算法本身的类型追踪精度」与「工程侧框架入口 / L3 符号映射 / 未知动态降级护栏」拆开度量，缺一不可。</p>
            </div>
            <div class="rcg-card">
              <h4>Layer 2 / CycloneDX 1.7 实时输出负载</h4>
              <pre class="rcg-code-preview">${escapeHtml(JSON.stringify(res.jsonPreview, null, 2))}</pre>
            </div>
          </div>
        `;
      } else {
        const m = computeCalculatorMetrics();
        const maxChartSec = Math.max(60, m.wholeSec * 1.08, m.stitchSec * 1.2);
        const slaPct = Math.min(96, (30 / maxChartSec) * 100).toFixed(1);
        const wholePct = Math.min(100, (m.wholeSec / maxChartSec) * 100).toFixed(1);
        const stitchPct = Math.min(100, (m.stitchSec / maxChartSec) * 100).toFixed(1);

        bodyHtml = `
          <div class="rcg-controls-bar">
            <div class="rcg-algo-pills">
              <span class="vlab-section-label" style="margin:0 0.35rem 0 0;">调用图求解算法:</span>
              ${["CHA", "RTA", "VTA", "0-CFA"]
                .map(
                  (a) =>
                    `<button type="button" class="rcg-algo-btn ${state.calcAlgo === a ? "active" : ""}" data-action="set-calc-algo" data-val="${a}">${a}</button>`
                )
                .join("")}
            </div>
            <span style="font-size:0.8rem;color:var(--ink-secondary);">${escapeHtml(m.algoSpec.note)}</span>
          </div>

          <div class="rcg-slider-grid">
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rcg-kloc">第一方代码规模</label>
                <span>${state.kloc} KLOC</span>
              </div>
              <input id="rcg-kloc" class="vlab-range" type="range" min="10" max="300" step="10" value="${state.kloc}" data-action="slide" data-key="kloc" />
              <div class="vlab-slider-hint">业务仓库自身代码量</div>
            </div>
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rcg-pkgs">传递依赖组件数</label>
                <span>${state.transitivePkgs} 个</span>
              </div>
              <input id="rcg-pkgs" class="vlab-range" type="range" min="20" max="400" step="10" value="${state.transitivePkgs}" data-action="slide" data-key="transitivePkgs" />
              <div class="vlab-slider-hint">Maven/npm/PyPI 传递树规模</div>
            </div>
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rcg-hit">云端库摘要缓存命中率</label>
                <span>${state.cacheHitRate}%</span>
              </div>
              <input id="rcg-hit" class="vlab-range" type="range" min="0" max="98" step="2" value="${state.cacheHitRate}" data-action="slide" data-key="cacheHitRate" />
              <div class="vlab-slider-hint">按 (PURL, Version) 预计算命中</div>
            </div>
            <div class="vlab-slider-field">
              <div class="vlab-slider-top">
                <label for="rcg-cves">原始 L3 CVE 告警</label>
                <span>${state.rawCves} 条</span>
              </div>
              <input id="rcg-cves" class="vlab-range" type="range" min="20" max="300" step="10" value="${state.rawCves}" data-action="slide" data-key="rawCves" />
              <div class="vlab-slider-hint">仅靠版本匹配的原始告警数</div>
            </div>
          </div>

          <div class="rcg-kpi-strip">
            <div class="vlab-kpi ${m.stitchSec <= 30 ? "is-ok" : "is-warn"}">
              <div class="vlab-kpi-label">拼接模式 PR 耗时</div>
              <div class="vlab-kpi-num">${m.stitchSec} s</div>
              <div class="vlab-kpi-sub">较全量重算提速 <strong>${m.speedup}&times;</strong>（${m.stitchSec <= 30 ? "满足 30s PR SLA" : "超出 30s 需提升缓存或降级"}）</div>
            </div>
            <div class="vlab-kpi is-blue">
              <div class="vlab-kpi-label">峰值内存降幅</div>
              <div class="vlab-kpi-num">${m.stitchRamGb} GB</div>
              <div class="vlab-kpi-sub">全量构图峰值需要 <strong>${m.wholeRamGb} GB</strong> RAM</div>
            </div>
            <div class="vlab-kpi is-ok">
              <div class="vlab-kpi-label">静态可达性降噪率</div>
              <div class="vlab-kpi-num">${m.suppressedPct}%</div>
              <div class="vlab-kpi-sub">从 ${state.rawCves} 条压至 ${m.reachableCount} 必修 + ${m.potentialCount} 待核</div>
            </div>
          </div>

          <div class="rcg-bar-card">
            <div class="vlab-section-label">CI / PR 门禁构建期延迟对比（黑色竖线 = 30s PR SLA 门限）</div>
            <div class="rcg-bar-row">
              <div class="rcg-bar-head">
                <span>朴素方案：每次 PR 对第一方 + 全部传递依赖全量重算调用图</span>
                <span style="font-family:var(--font-mono);">${m.wholeSec} s · ${m.wholeRamGb} GB RAM</span>
              </div>
              <div class="rcg-bar-track">
                <div class="rcg-sla-marker" style="left:${slaPct}%;"><span>30s SLA</span></div>
                <div class="rcg-bar-fill ${m.wholeSec > 30 ? "is-slow" : "is-fast"}" style="width:${wholePct}%;"></div>
              </div>
            </div>
            <div class="rcg-bar-row">
              <div class="rcg-bar-head">
                <span>商业级架构：云端预计算库摘要（${state.cacheHitRate}% 命中）+ 在线第一方图拼接（Stitching）</span>
                <span style="font-family:var(--font-mono);">${m.stitchSec} s · ${m.stitchRamGb} GB RAM</span>
              </div>
              <div class="rcg-bar-track">
                <div class="rcg-sla-marker" style="left:${slaPct}%;"></div>
                <div class="rcg-bar-fill ${m.stitchSec <= 30 ? "is-fast" : "is-warn"}" style="width:${stitchPct}%;"></div>
              </div>
            </div>
          </div>

          <div class="rcg-card">
            <h4>四态可达性置信度分流漏斗（原始 ${state.rawCves} 条 L3 告警）</h4>
            <div class="rcg-funnel-row">
              <div class="vlab-diff-card" style="border-left:4px solid var(--danger);background:#fff9f9;">
                <div class="vlab-diff-label">REACHABLE（阻断 P0）</div>
                <div class="vlab-diff-val">${m.reachableCount} 条</div>
                <div class="vlab-diff-sub">具备 Entrypoint &rarr; Sink 完整证据栈</div>
              </div>
              <div class="vlab-diff-card" style="border-left:4px solid var(--warn);background:#fffcf5;">
                <div class="vlab-diff-label">POTENTIALLY_REACHABLE</div>
                <div class="vlab-diff-val">${m.potentialCount} 条</div>
                <div class="vlab-diff-sub">因反射/动态派发/缺符号需移交 Lesson 0012 运行时</div>
              </div>
              <div class="vlab-diff-card" style="border-left:4px solid var(--ok);background:#f8fcf9;">
                <div class="vlab-diff-label">UNREACHABLE（自动消噪）</div>
                <div class="vlab-diff-val">${m.unreachableCount} 条</div>
                <div class="vlab-diff-sub">在 ${state.calcAlgo} 图上已证不可达，生成 VEX 降噪</div>
              </div>
            </div>
          </div>
        `;
      }

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "静态函数级可达性（Call Graph）交互实验台")}</h3>
          <div class="widget-status">Layer 4 · CHA / RTA / VTA &amp; Stitching Lab</div>
        </div>
        ${config.intro ? `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.95rem;">${escapeHtml(config.intro)}</p>` : ""}

        <div class="rcg-tabs">
          <button type="button" class="rcg-tab ${state.activeTab === "scenarios" ? "active" : ""}" data-action="set-tab" data-tab="scenarios">
            <span class="vlab-tab-num">1</span>
            <span>算法精度与跨语言断链实验（CHA / RTA / VTA / 四态护栏）</span>
          </button>
          <button type="button" class="rcg-tab ${state.activeTab === "calculator" ? "active" : ""}" data-action="set-tab" data-tab="calculator">
            <span class="vlab-tab-num">2</span>
            <span>生态预计算拼接（Stitching）vs 全量重算 PR 门禁计算器</span>
          </button>
        </div>

        ${bodyHtml}
      `;

      // Wire events
      container.querySelectorAll('[data-action="set-tab"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTab = btn.dataset.tab;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-preset"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.presetId = btn.dataset.id;
          render();
        });
      });

      container.querySelectorAll('[data-action="set-go-algo"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.goAlgo = btn.dataset.val;
          render();
        });
      });

      const goUnusedEl = container.querySelector('[data-action="toggle-go-unused"]');
      if (goUnusedEl) {
        goUnusedEl.addEventListener("change", (e) => {
          state.goUnusedInstantiated = e.target.checked;
          render();
        });
      }

      const javaSpringEl = container.querySelector('[data-action="toggle-java-spring"]');
      if (javaSpringEl) {
        javaSpringEl.addEventListener("change", (e) => {
          state.javaSpringEntry = e.target.checked;
          render();
        });
      }

      const javaTriggerEl = container.querySelector('[data-action="toggle-java-trigger"]');
      if (javaTriggerEl) {
        javaTriggerEl.addEventListener("change", (e) => {
          state.javaL3TriggerApi = e.target.checked;
          render();
        });
      }

      const jsSideEl = container.querySelector('[data-action="toggle-js-sideeffect"]');
      if (jsSideEl) {
        jsSideEl.addEventListener("change", (e) => {
          state.jsLevel1SideEffect = e.target.checked;
          render();
        });
      }

      const jsBoundEl = container.querySelector('[data-action="toggle-js-bounded"]');
      if (jsBoundEl) {
        jsBoundEl.addEventListener("change", (e) => {
          state.jsIndirectionBounded = e.target.checked;
          render();
        });
      }

      const pyGuardEl = container.querySelector('[data-action="toggle-py-guardrail"]');
      if (pyGuardEl) {
        pyGuardEl.addEventListener("change", (e) => {
          state.pyUnknownGuardrail = e.target.checked;
          render();
        });
      }

      container.querySelectorAll('[data-action="set-calc-algo"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.calcAlgo = btn.dataset.val;
          render();
        });
      });

      container.querySelectorAll('[data-action="slide"]').forEach((input) => {
        input.addEventListener("input", (e) => {
          const key = e.target.dataset.key;
          state[key] = Number(e.target.value);
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="reachability-cg-lab"]').forEach(initReachabilityLab);
  });
})();
