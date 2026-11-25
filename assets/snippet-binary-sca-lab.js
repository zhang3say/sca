/* ==========================================================================
   可复用交互组件：代码片段同源检测与无源码二进制 SCA 实验室（Lesson 0016+）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：无源码二进制三层特征金字塔 + CENTRIS 嵌套剪枝实战台
   模式二：Schleimer Winnowing 滑动窗口指纹实时提取与压缩率演示器
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

  // 轻量确定性 32-bit FNV-1a 哈希（仅用于浏览器内教学演示）
  function fnv1a32(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }

  // Type-1 / Type-2 词法 Token 化与可选标识符折叠
  function tokenizeSnippet(code, foldIdentifiers) {
    const clean = String(code || "")
      .replace(/\/\/[^\n]*/g, " ")
      .replace(/\/\*[\s\S]*?\*\//g, " ");

    const cKeywords = new Set([
      "uint32_t", "uint8_t", "size_t", "int", "return", "for", "while", "if", "else", "const", "unsigned", "void"
    ]);
    const rawTokens = clean.match(/[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|[0-9]+|[{}();,+\-*/%&|^~<>!=[\]]/g) || [];
    if (!foldIdentifiers) return rawTokens;

    return rawTokens.map((tok) => {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok) && !cKeywords.has(tok)) {
        return "ID";
      }
      return tok;
    });
  }

  // Schleimer et al. (SIGMOD 2003) 经典 Winnowing：在每个窗口 w 内选择最右最小哈希
  function computeWinnowing(tokens, k, w) {
    if (tokens.length < k) {
      return { gramsCount: 0, fingerprints: [] };
    }
    const hashes = [];
    for (let i = 0; i <= tokens.length - k; i++) {
      const gram = tokens.slice(i, i + k).join(" ");
      hashes.push({ pos: i, hash: fnv1a32(gram), gram });
    }
    if (hashes.length <= w) {
      let minIdx = 0;
      for (let i = 1; i < hashes.length; i++) {
        if (hashes[i].hash <= hashes[minIdx].hash) minIdx = i;
      }
      return { gramsCount: hashes.length, fingerprints: [hashes[minIdx]] };
    }

    const selected = [];
    let lastPickedPos = -1;
    for (let start = 0; start <= hashes.length - w; start++) {
      let minIdx = start;
      for (let j = start + 1; j < start + w; j++) {
        // <= 保证并列最小时取最右端，满足 Winnowing 密度与局部性证明
        if (hashes[j].hash <= hashes[minIdx].hash) {
          minIdx = j;
        }
      }
      if (hashes[minIdx].pos !== lastPickedPos) {
        lastPickedPos = hashes[minIdx].pos;
        selected.push(hashes[minIdx]);
      }
    }
    return { gramsCount: hashes.length, fingerprints: selected };
  }

  function initSnippetBinaryLab(container) {
    const dataEl = container.querySelector("script.snippet-binary-sca-lab-data");
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
        id: "unstripped-openssl",
        label: "1. 未剥离动态库 (libcrypto.so.1.1)",
        desc: "常规 Linux 动态共享库：保留了 .dynsym 导出符号（EVP_CipherInit_ex）及 .rodata 版本横幅 \"OpenSSL 1.1.1k\"。三层特征均可见，Layer A 毫秒级直接精准定版。",
        artifact: "pkg:generic/libcrypto.so.1.1 (x86_64 ELF)",
        layerA: ["ELF .dynsym: EVP_CipherInit_ex, ASN1_item_d2i", "Banner: OpenSSL 1.1.1k  25 Mar 2021"],
        layerB: ["High-IDF Strings: \"tls_process_client_hello\", \"crypto/evp/e_aes.c\""],
        layerC: ["ACFG 函数图匹配: aes_gcm_cipher (cosSim=0.99)"],
        resolvedByA: true,
        resolvedByB: true,
        resolvedByC: true,
        isNested: false,
        detectedComponent: "pkg:generic/openssl@1.1.1k (confidence: 0.99)",
        naiveSymbolHit: true,
        apply: { useLayerB: true, useCentris: true, useLayerC: false, payloadMode: "ir" },
      },
      {
        id: "stripped-static-zlib",
        label: "2. 静态链接 + strip -s 剥离 (gateway-bin)",
        desc: "生产级 C 网关程序：静态编入 zlib 1.2.11 并执行 strip -s 抹除符号表。Layer A 仅能看到主程序外壳完全失明；启用 Layer B（TF-IDF 高区分度错误串 + CRC32 魔数表）后，秒级精准锁定静态嵌入的 zlib 1.2.11（含 CVE-2022-37434）。",
        artifact: "gateway-bin (x86_64 ELF · stripped · static)",
        layerA: [".symtab / .strtab 已被 strip -s 完全清空", "无版本横幅或包管理清单文件"],
        layerB: ["IDF=9.4: \"invalid literal/lengths set\", \"incorrect header check\"", "Magic Constant: zlib CRC32 table (0x77073096...)"],
        layerC: ["ACFG 辅助确认: inflate_fast() 控制流图匹配度 0.94"],
        resolvedByA: false,
        resolvedByB: true,
        resolvedByC: true,
        isNested: false,
        detectedComponent: "pkg:generic/zlib@1.2.11 (CVE-2022-37434, confidence: 0.94)",
        naiveSymbolHit: false,
        apply: { useLayerB: true, useCentris: true, useLayerC: false, payloadMode: "ir" },
      },
      {
        id: "nested-oss-reuse",
        label: "3. 嵌套拷贝 + 15% 魔改 (CENTRIS)",
        desc: "客户仓库复制了开源项目 B（libmedia）的源码，而项目 B 内部早已 Vendoring 嵌套了开源库 A（zlib）且本地修改了 15% 代码。普通文件哈希 0 命中；简单函数匹配同时误报 A+B 甚至把源头归错给拷贝者；启用 CENTRIS 冗余消除与最早提交溯源后精准还原归属。",
        artifact: "vendor/media_codec.c (Modified Type-3 Clone)",
        layerA: ["无 package.json / CMakeLists 依赖声明", "整文件 SHA256 在全网库 0 命中（已修改 15% 语句）"],
        layerB: ["函数级 TLSH 局部敏感哈希命中 14 个公共函数", "冲突候选：zlib@1.2.8 (2013) vs libmedia@2.0 (2019)"],
        layerC: ["CENTRIS 冗余消除 + 最早提交时间戳：zlib 为真实源头，libmedia 为宿主"],
        resolvedByA: false,
        resolvedByB: true,
        resolvedByC: true,
        isNested: true,
        detectedComponent: "宿主 pkg:github/acme/libmedia@2.0 + 嵌套源头 zlib@1.2.8",
        naiveSymbolHit: false,
        apply: { useLayerB: true, useCentris: true, useLayerC: false, payloadMode: "index" },
      },
      {
        id: "cross-arch-mips-stripped",
        label: "4. MIPS 嵌入式固件 + 字符串混淆",
        desc: "通过 Binwalk v3 解包路由器固件得到 mipsel 无符号 ELF，且厂商对错误日志字符串做了 XOR 混淆。Layer A 与 Layer B 均失明，必须按需路由至 Tier 3 沙箱调用 Ghidra Headless 提取跨架构 ACFG 控制流图向量（Gemini 范式）匹配底层脆弱函数。",
        artifact: "squashfs-root/bin/httpd (mipsel ELF · stripped · obfuscated)",
        layerA: ["mipsel 架构无动态符号与版本字符串"],
        layerB: ["关键字符串被 XOR 混淆：TF-IDF 仅捕获少量通用 libc 字面量"],
        layerC: ["Ghidra Headless P-Code -> ACFG Embedding 跨架构命中 curl@7.68.0 parse_url()"],
        resolvedByA: false,
        resolvedByB: false,
        resolvedByC: true,
        isNested: false,
        detectedComponent: "pkg:generic/curl@7.68.0 (ACFG cross-arch confidence: 0.86)",
        naiveSymbolHit: false,
        apply: { useLayerB: true, useCentris: true, useLayerC: true, payloadMode: "ir" },
      },
    ];

    const BASE_CODE = `uint32_t calc_crc32(const uint8_t *buf, size_t len) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= buf[i];
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}`;

    const SNIPPET_SAMPLES = [
      {
        id: "exact",
        label: "原版 C 函数",
        code: BASE_CODE,
      },
      {
        id: "type1",
        label: "Type-1 改空白与注释",
        code: `// Vendored helper copied from upstream
uint32_t calc_crc32( const uint8_t *buf,   size_t len ) {
  uint32_t crc = 0xFFFFFFFF; /* init */
  for(size_t i=0;i<len;i++){
    crc ^= buf[i];
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}`,
      },
      {
        id: "type2",
        label: "Type-2 改全部变量名",
        code: `uint32_t fast_checksum(const uint8_t *data_ptr, size_t nbytes) {
  uint32_t acc = 0xFFFFFFFF;
  for (size_t idx = 0; idx < nbytes; idx++) {
    acc ^= data_ptr[idx];
    for (int k = 0; k < 8; k++) {
      acc = (acc >> 1) ^ (0xEDB88320 & -(acc & 1));
    }
  }
  return ~acc;
}`,
      },
      {
        id: "type3",
        label: "Type-3 删改两行 (部分重合)",
        code: `uint32_t fast_checksum(const uint8_t *data_ptr, size_t nbytes) {
  uint32_t acc = 0x00000000;
  for (size_t idx = 0; idx < nbytes; idx++) {
    acc ^= data_ptr[idx];
    for (int k = 0; k < 8; k++) {
      acc = (acc >> 1) ^ (0xEDB88320 & -(acc & 1));
    }
  }
  return acc;
}`,
      },
    ];

    const state = {
      activeTab: "pyramid", // "pyramid" | "winnowing"
      presetId: "stripped-static-zlib",
      useLayerB: true,
      useCentris: true,
      useLayerC: false,
      payloadMode: "ir", // "ir" | "index"
      // 模式二
      sampleId: "type2",
      userCode: SNIPPET_SAMPLES[2].code,
      kGram: 5,
      windowW: 4,
      foldTokens: true,
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function getEngineStatus(preset) {
      // 反例 A：传统 Manifest / 全文件 SHA256 SCA
      const legacySca = {
        tone: "is-bad",
        verdict: "0 命中 · 黑盒盲区漏报",
        meta: "无锁文件且文件哈希不一致",
        desc:
          preset.id === "unstripped-openssl"
            ? "若客户未提供构建期 manifest，仅扫锁文件与整包 SHA256 的传统 SCA 对独立 .so 同样束手无策。"
            : "面对静态链接、strip 剥离符号、15% 魔改或跨架构固件，文件级精确哈希与清单解析彻底失效。",
      };

      // 反例 B：简单导出符号 + 裸字符串正则
      let naiveExtractor;
      if (preset.id === "unstripped-openssl") {
        naiveExtractor = {
          tone: "is-ok",
          verdict: "命中导出符号与版本串",
          meta: "仅未剥离动态库可用",
          desc: "未 strip 的共享库保留了明文版本横幅，常规正则即可快速识别。",
        };
      } else if (preset.id === "nested-oss-reuse") {
        naiveExtractor = {
          tone: "is-warn",
          verdict: "嵌套冲突 · 源头归属错位",
          meta: "重复告警 A+B / 错认拷贝者为原作者",
          desc: "缺少冗余消除与诞生时间溯源时，只要某仓库拷贝过 zlib 就会在索引里引发几十个伪组件冲突。",
        };
      } else {
        naiveExtractor = {
          tone: "is-bad",
          verdict: "符号已剥离 · 匹配全面失明",
          meta: "无 .symtab 且缺 IDF 过滤高误报",
          desc: "strip -s 抹除符号后，简单符号扫描归零；裸正则匹配短字符串又会把 printf/error 等通用串误报成几十个库。",
        };
      }

      // 推荐：三层金字塔 + CENTRIS 引擎（严格随开关联动）
      let thirdGen;
      if (preset.id === "unstripped-openssl") {
        thirdGen = {
          tone: "is-ok",
          verdict: "Layer A 毫秒级精确命中",
          meta: "符号 + 版本横幅直接收敛",
          desc: "无需启动高成本的 Layer C 反编译，在最轻量的 Layer A 即完成高置信度定版并投影至 Layer 2 IR。",
        };
      } else if (preset.id === "stripped-static-zlib") {
        if (state.useLayerB || state.useLayerC) {
          thirdGen = {
            tone: "is-ok",
            verdict: state.useLayerB ? "Layer B 高 IDF 字符串秒级破局" : "兜底走高成本 Layer C 匹配",
            meta: state.useLayerB ? "唯一错误串 + CRC32 常量命中" : "建议开启 Layer B 节省 95% 算力",
            desc: state.useLayerB
              ? "B2SFinder/OSSPolice 范式利用高区分度字面量与魔数常量池，穿透 strip -s 精准识别静态链接的 zlib 1.2.11。"
              : "虽然关闭 Layer B 后仍可依靠 Layer C 控制流图找回，但全量跑反编译会严重拖慢扫描 SLA。",
          };
        } else {
          thirdGen = {
            tone: "is-bad",
            verdict: "未开 Layer B/C · 漏报静态 zlib",
            meta: "仅 Layer A 无法穿透 strip -s",
            desc: "同时关闭字符串 IDF 与控制流图后，引擎退化为简单符号匹配，完全漏报静态链接进来的 CVE-2022-37434。",
          };
        }
      } else if (preset.id === "nested-oss-reuse") {
        if (state.useLayerB && state.useCentris) {
          thirdGen = {
            tone: "is-ok",
            verdict: "CENTRIS 精准剪枝并追溯源头",
            meta: "TLSH 容忍魔改 + 最早提交定主",
            desc: "先用函数级 TLSH 捕获 15% 魔改复用，再通过冗余消除剥离嵌套公共函数并按最早 commit 锁定 zlib 源头。",
          };
        } else if (state.useLayerB && !state.useCentris) {
          thirdGen = {
            tone: "is-warn",
            verdict: "检出复用但触发嵌套组件误报",
            meta: "CENTRIS 剪枝关闭 · 源头归属混乱",
            desc: "能通过函数指纹抓出复用，但同时把所有历史拷贝过 zlib 的第三方项目一并报出，制造大量合规误报。",
          };
        } else {
          thirdGen = {
            tone: "is-bad",
            verdict: "未开特征层 · 魔改拷贝零命中",
            meta: "整文件哈希无法匹配 15% 修改",
            desc: "关闭特征池后，修改了 15% 代码的 Copy-Paste 片段彻底逃脱检测。",
          };
        }
      } else {
        // cross-arch-mips-stripped
        if (state.useLayerC) {
          thirdGen = {
            tone: "is-ok",
            verdict: "Tier 3 ACFG 跨架构成功召回",
            meta: "Ghidra P-Code + Gemini 控制流向量",
            desc: "Layer A/B 在混淆 MIPS 固件上失效后，按需进入隔离 Tier 3 沙箱提取跨架构 ACFG 嵌入，命中底层 curl 漏洞函数。",
          };
        } else {
          thirdGen = {
            tone: "is-warn",
            verdict: "Layer A/B 均失明 · 须启用 Layer C",
            meta: "字符串已被混淆且非 x86 常见符号",
            desc: "针对剥离符号且混淆字符串的跨架构固件，只有开启按需 Layer C 控制流图向量匹配才能破局。",
          };
        }
      }

      return { legacySca, naiveExtractor, thirdGen };
    }

    function isDetectedByCurrentConfig(preset) {
      if (preset.id === "unstripped-openssl") return true;
      if (preset.id === "stripped-static-zlib") return state.useLayerB || state.useLayerC;
      if (preset.id === "nested-oss-reuse") return state.useLayerB || state.useLayerC;
      return state.useLayerC;
    }

    function buildPayload(preset) {
      const detected = isDetectedByCurrentConfig(preset);

      if (state.payloadMode === "ir") {
        const obj = {
          layer2_ir_component: {
            target_artifact: preset.artifact,
            detected: detected,
            matched_component: detected ? preset.detectedComponent : "UNKNOWN (需启用更高层特征金字塔)",
            cyclonedx_1_7_evidence: {
              identity: {
                field: "purl",
                confidence: !detected
                  ? 0.0
                  : preset.id === "unstripped-openssl"
                    ? 0.99
                    : preset.id === "stripped-static-zlib"
                      ? 0.94
                      : preset.id === "nested-oss-reuse"
                        ? state.useCentris ? 0.92 : 0.58
                        : 0.86,
                methods: [
                  {
                    technique: preset.id === "unstripped-openssl"
                      ? "binary-symbol-banner"
                      : preset.id === "cross-arch-mips-stripped"
                        ? "acfg-graph-embedding"
                        : "source-fingerprint-and-tfidf",
                    value: detected ? "matched_by_enabled_layers" : "unmatched_under_current_toggles",
                  },
                ],
              },
            },
            centris_attribution_applied: preset.isNested ? state.useCentris : "N/A",
          },
        };
        return JSON.stringify(obj, null, 2);
      }

      // 指纹索引查询载荷
      if (preset.id === "nested-oss-reuse") {
        return [
          `# [Zero-Source-Upload Fingerprint Query] 本地提取单向指纹，不上传源码明文`,
          `snippet_id: vendor/media_codec.c::calc_crc32`,
          `winnowing_wfp: v1,crc32c,gram=30,win=64 -> [0x1a9f4c22, 0x88b01e7a, 0x04d299c1]`,
          `tlsh_hash: T18F229B368A12C4E7F192D30482A11C774B23`,
          ``,
          state.useLayerB
            ? state.useCentris
              ? `[CENTRIS 归属裁决] 命中 14 个共享函数 -> 剪除嵌套公共函数后归属源头: zlib@1.2.8 (earliest_commit: 2013-04-28)`
              : `[警告·未开 CENTRIS] 同时命中 17 个历史曾拷贝 zlib 的仓，产生嵌套误报与归属冲突！`
            : `[MISS] 未启用特征指纹层，15% 魔改后精确文件哈希无法命中。`,
        ].join("\n");
      }

      return [
        `# [Binary Feature Pyramid Query] ${preset.artifact}`,
        `Layer A (Symbol/Banner): ${preset.resolvedByA ? "HIT -> " + preset.layerA[0] : "BLIND (stripped/missing)"}`,
        `Layer B (String TF-IDF + Constants): ${
          state.useLayerB
            ? preset.resolvedByB
              ? "HIT -> " + preset.layerB[0]
              : "BLIND (strings obfuscated)"
            : "DISABLED"
        }`,
        `Layer C (Ghidra ACFG Tier-3): ${
          state.useLayerC
            ? preset.resolvedByC
              ? "HIT -> " + preset.layerC[0]
              : "SKIPPED"
            : "DISABLED"
        }`,
        `Final Match: ${detected ? preset.detectedComponent : "UNRESOLVED"}`,
      ].join("\n");
    }

    function renderPyramidTab() {
      const preset = getCurrentPreset();
      const res = getEngineStatus(preset);
      const detected = isDetectedByCurrentConfig(preset);
      const payload = buildPayload(preset);

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
              <span class="grl-control-label">1. 开关二进制与同源特征金字塔层级</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="layerB" ${state.useLayerB ? "checked" : ""} />
                <span>启用 <strong>Layer B：TF-IDF 唯一字符串 + 魔数常量 / TLSH 函数指纹</strong>（穿透 <code>strip -s</code>）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="centris" ${state.useCentris ? "checked" : ""} />
                <span>启用 <strong>CENTRIS 嵌套剪枝与最早诞生时间溯源</strong>（消除 Vendoring 伪冲突与归属倒置）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="layerC" ${state.useLayerC ? "checked" : ""} />
                <span>启用 <strong>Layer C：Ghidra Headless + ACFG 跨架构控制流嵌入</strong>（Tier 3 按需深度解析）</span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 切换输出视图（Layer 2 IR 证据 vs 指纹索引查询）</span>
              <div class="grl-pill-group">
                <button type="button" class="grl-pill is-accent ${state.payloadMode === "ir" ? "active" : ""}" data-payload="ir">
                  CycloneDX 1.7 IR 证据
                </button>
                <button type="button" class="grl-pill is-accent ${state.payloadMode === "index" ? "active" : ""}" data-payload="index">
                  指纹索引查询追踪
                </button>
              </div>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">3. 三层可观测特征提取状态</span>
              <div style="font-size:0.77rem;line-height:1.55;color:var(--ink-secondary);">
                <div>&bull; <strong>Layer A：</strong>${escapeHtml(preset.layerA.join("；"))}</div>
                <div>&bull; <strong>Layer B：</strong>${escapeHtml(preset.layerB.join("；"))}</div>
                <div>&bull; <strong>Layer C：</strong>${escapeHtml(preset.layerC.join("；"))}</div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid">
              <div class="grl-card ${res.legacySca.tone}">
                <div class="grl-card-kicker">反例 A · 传统 Manifest / 文件哈希</div>
                <div class="grl-card-title">${escapeHtml(res.legacySca.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.legacySca.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.legacySca.desc)}</p>
              </div>

              <div class="grl-card ${res.naiveExtractor.tone}">
                <div class="grl-card-kicker">反例 B · 简单符号 / 裸正则匹配</div>
                <div class="grl-card-title">${escapeHtml(res.naiveExtractor.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.naiveExtractor.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.naiveExtractor.desc)}</p>
              </div>

              <div class="grl-card ${res.thirdGen.tone}">
                <div class="grl-card-kicker">推荐 · 三层金字塔 + CENTRIS</div>
                <div class="grl-card-title">${escapeHtml(res.thirdGen.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.thirdGen.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.thirdGen.desc)}</p>
              </div>
            </div>

            <div class="grl-graph-grid">
              <div class="grl-dep-node ${preset.resolvedByA ? "is-safe" : ""}">
                <div class="grl-dep-role">Layer A · 毫秒级符号/横幅</div>
                <div class="grl-dep-name">${preset.resolvedByA ? "直接命中" : "无符号/无清单"}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.layerA[0])}</div>
              </div>
              <div class="grl-dep-node ${!state.useLayerB ? "" : preset.resolvedByB ? "is-safe" : "is-conflict"}">
                <div class="grl-dep-role">Layer B · 字符串 IDF + 指纹</div>
                <div class="grl-dep-name">${!state.useLayerB ? "已关闭" : preset.resolvedByB ? "成功破局命中" : "字面量已混淆"}</div>
                <div class="grl-dep-ver">${!state.useLayerB ? "未启用 Layer B" : escapeHtml(preset.layerB[0])}</div>
              </div>
              <div class="grl-dep-node ${!state.useLayerC ? "" : preset.resolvedByC ? "is-upgraded" : ""}">
                <div class="grl-dep-role">Layer C · 跨架构 ACFG (Tier 3)</div>
                <div class="grl-dep-name">${!state.useLayerC ? "按需待命 (未开启)" : "ACFG 向量召回"}</div>
                <div class="grl-dep-ver">${!state.useLayerC ? "仅在 A/B 均失明时启用" : escapeHtml(preset.layerC[0])}</div>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">${
                  state.payloadMode === "ir"
                    ? "输出 1：Layer 2 统一 IR 组件与 CycloneDX 1.7 置信度证据"
                    : "输出 2：Zero-Source-Upload 指纹与二进制特征查询轨迹"
                }</span>
                <span class="badge ${detected ? (preset.isNested && !state.useCentris ? "badge-warn" : "badge-ok") : "badge-danger"}">${
                  detected ? (preset.isNested && !state.useCentris ? "MATCHED · 存在嵌套冲突" : "MATCHED · 已投影 IR") : "UNRESOLVED · 漏报"
                }</span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(payload)}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function renderWinnowingOutput() {
      const k = state.kGram;
      const w = state.windowW;
      const t = w + k - 1;

      const baseTokens = tokenizeSnippet(BASE_CODE, state.foldTokens);
      const candTokens = tokenizeSnippet(state.userCode, state.foldTokens);

      const baseWin = computeWinnowing(baseTokens, k, w);
      const candWin = computeWinnowing(candTokens, k, w);

      const baseSet = new Set(baseWin.fingerprints.map((f) => f.hash));
      const candSet = new Set(candWin.fingerprints.map((f) => f.hash));

      let hitCount = 0;
      candSet.forEach((h) => {
        if (baseSet.has(h)) hitCount++;
      });

      const unionSize = new Set([...baseSet, ...candSet]).size;
      const jaccardPct = unionSize > 0 ? Math.round((hitCount / unionSize) * 100) : 0;
      const containmentPct = candSet.size > 0 ? Math.round((hitCount / candSet.size) * 100) : 0;
      const compressPct = candWin.gramsCount > 0
        ? Math.round((1 - candWin.fingerprints.length / candWin.gramsCount) * 100)
        : 0;

      const samplePreview = candWin.fingerprints.slice(0, 8).map((f) => {
        const isHit = baseSet.has(f.hash);
        const hex = "0x" + f.hash.toString(16).padStart(8, "0");
        return `<span class="badge ${isHit ? "badge-ok" : "badge-blue"}" style="margin:0.15rem;">${hex} ${isHit ? "(命中)" : "(独有)"}</span>`;
      }).join("");

      return `
        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">数学保证检出阈值 (t = w+k-1)</div>
            <div class="grl-kpi-val">${t} Tokens</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">待测片段指纹包含率</div>
            <div class="grl-kpi-val" style="color:${containmentPct >= 60 ? "var(--ok)" : "var(--warn)"};">${containmentPct}%</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Jaccard 双向相似度</div>
            <div class="grl-kpi-val">${jaccardPct}%</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">Winnowing 索引压缩率</div>
            <div class="grl-kpi-val" style="color:var(--accent-blue);">${compressPct}% (${candWin.fingerprints.length}/${candWin.gramsCount})</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div class="grl-bar-row">
            <div class="grl-bar-head">
              <span>共享片段指纹包含率（命中 ${hitCount} / 待测独立指纹 ${candSet.size} · ${state.foldTokens ? "已折叠变量名为 ID" : "原始变量名"}）</span>
              <span>${containmentPct}%</span>
            </div>
            <div class="grl-bar-track">
              <div class="grl-bar-fill ${containmentPct >= 60 ? "is-ok" : containmentPct >= 25 ? "is-warn" : "is-bad"}" style="width:${containmentPct}%;"></div>
            </div>
          </div>
          <div style="margin-top:0.65rem;font-size:0.78rem;color:var(--ink-secondary);">
            <strong>本地提取出的 Winnowing 指纹样本（仅上传此类单向哈希，绝不上传源码）：</strong>
            <div style="margin-top:0.3rem;display:flex;flex-wrap:wrap;">${samplePreview || "<span>Token 数不足 k，请补充代码片段。</span>"}</div>
          </div>
        </div>
      `;
    }

    function updateWinnowingOutput() {
      const out = container.querySelector(".grl-winnow-output");
      if (out) out.innerHTML = renderWinnowingOutput();
    }

    function renderWinnowingTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div style="display:grid;grid-template-columns:1.15fr 0.85fr;gap:0.95rem;align-items:start;">
            <div>
              <span class="grl-control-label">1. 选择或编辑待检测 C 代码片段（对比上游开源库 CRC32 函数）</span>
              <div class="grl-pill-group" style="margin:0.4rem 0;">
                ${SNIPPET_SAMPLES.map(
                  (s) => `
                    <button type="button" class="grl-pill ${state.sampleId === s.id ? "active" : ""}" data-sample="${s.id}">
                      ${escapeHtml(s.label)}
                    </button>
                  `
                ).join("")}
              </div>
              <textarea data-input="usercode" rows="8"
                style="width:100%;padding:0.55rem 0.7rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.76rem;line-height:1.45;background:var(--surface);color:var(--ink);resize:vertical;">${escapeHtml(state.userCode)}</textarea>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.7rem;">
              <div>
                <div class="grl-slider-head">
                  <span class="grl-control-label">2. k-gram 切片长度 (k)</span>
                  <strong data-readout="kgram">${state.kGram} tokens</strong>
                </div>
                <input type="range" class="grl-slider" data-slider="kgram" min="3" max="8" step="1" value="${state.kGram}" />
              </div>

              <div>
                <div class="grl-slider-head">
                  <span class="grl-control-label">3. Winnowing 滑动窗口 (w)</span>
                  <strong data-readout="windoww">${state.windowW} hashes</strong>
                </div>
                <input type="range" class="grl-slider" data-slider="windoww" min="3" max="8" step="1" value="${state.windowW}" />
              </div>

              <label class="grl-toggle">
                <input type="checkbox" data-toggle="foldtokens" ${state.foldTokens ? "checked" : ""} />
                <span>开启 <strong>Type-2 词法 Token 归一化</strong>（去注释空白 + 变量/函数名统一折叠为 <code>ID</code>，测试对重命名的抵抗力）</span>
              </label>

              <div style="font-size:0.76rem;line-height:1.5;color:var(--ink-muted);padding:0.5rem 0.65rem;background:var(--surface);border:1px solid var(--rule);border-radius:4px;">
                <strong>算法公式（Schleimer SIGMOD 2003）：</strong>任何连续共享长度 &ge; <code>w + k - 1</code> 的 Token 片段，在数学上<strong>100% 保证</strong>至少落入一个共同最小指纹中，同时把索引体积压缩约 <code>(w+1)/2</code> 倍。
              </div>
            </div>
          </div>
        </div>

        <div class="grl-winnow-output">${renderWinnowingOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：三层二进制特征金字塔与 Winnowing 同源指纹模拟器";
      const intro =
        config.intro ||
        "切换无符号静态库、嵌套魔改与跨架构固件场景验证特征金字塔能力，并在模式二实时运行 Winnowing 指纹提取算法。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0016 · Snippet &amp; Binary SCA Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "pyramid" ? "active" : ""}" data-tab="pyramid">
            <span class="grl-tab-num">1</span>
            模式一：无源码二进制三层特征金字塔与 CENTRIS 剪枝
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "winnowing" ? "active" : ""}" data-tab="winnowing">
            <span class="grl-tab-num">2</span>
            模式二：源码片段 Winnowing 指纹提取与 Type-2 归一化实验
          </button>
        </div>

        ${state.activeTab === "pyramid" ? renderPyramidTab() : renderWinnowingTab()}
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

      container.querySelectorAll("[data-payload]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.payloadMode = btn.dataset.payload;
          render();
        });
      });

      container.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          if (cb.dataset.toggle === "layerB") state.useLayerB = cb.checked;
          if (cb.dataset.toggle === "centris") state.useCentris = cb.checked;
          if (cb.dataset.toggle === "layerC") state.useLayerC = cb.checked;
          if (cb.dataset.toggle === "foldtokens") state.foldTokens = cb.checked;
          if (state.activeTab === "winnowing") updateWinnowingOutput();
          else render();
        });
      });

      container.querySelectorAll("[data-sample]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = SNIPPET_SAMPLES.find((s) => s.id === btn.dataset.sample);
          if (!found) return;
          state.sampleId = found.id;
          state.userCode = found.code;
          render();
        });
      });

      const codeArea = container.querySelector('[data-input="usercode"]');
      if (codeArea) {
        codeArea.addEventListener("input", (e) => {
          state.userCode = e.target.value;
          state.sampleId = "custom";
          container.querySelectorAll("[data-sample]").forEach((b) => b.classList.remove("active"));
          updateWinnowingOutput();
        });
      }

      const kSlider = container.querySelector('[data-slider="kgram"]');
      if (kSlider) {
        kSlider.addEventListener("input", (e) => {
          state.kGram = Number(e.target.value);
          const readout = container.querySelector('[data-readout="kgram"]');
          if (readout) readout.textContent = `${state.kGram} tokens`;
          updateWinnowingOutput();
        });
      }

      const wSlider = container.querySelector('[data-slider="windoww"]');
      if (wSlider) {
        wSlider.addEventListener("input", (e) => {
          state.windowW = Number(e.target.value);
          const readout = container.querySelector('[data-readout="windoww"]');
          if (readout) readout.textContent = `${state.windowW} hashes`;
          updateWinnowingOutput();
        });
      }
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="snippet-binary-sca-lab"]')
      .forEach(initSnippetBinaryLab);
  });
})();
