/* ==========================================================================
   可复用交互组件：AI-BOM 血缘图谱与非 OSI 模型合规实验台（Lesson 0017+）
   零依赖原生 JS，完全复用 tufte-course.css 中 .grl-* 样式。
   模式一：AI-BOM 四层血缘图谱与 CycloneDX 1.7 / SPDX 3.0.1 双向投影裁决台
   模式二：pkg:huggingface (ECMA-427) 规范化与模型许可/EU AI Act 合规检查器
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

  function buildHfPurl(ns, name, ver, repoUrl) {
    // ECMA-427 pkg:huggingface 规范：namespace 与 name 区分大小写；version commit hash 必须统一小写
    const cleanNs = String(ns || "").trim();
    const cleanName = String(name || "").trim();
    const cleanVer = String(ver || "").trim().toLowerCase();
    const cleanRepo = String(repoUrl || "").trim();

    if (!cleanNs || !cleanName) return "pkg:huggingface/<missing-namespace>/<missing-name>";
    let base = `pkg:huggingface/${cleanNs}/${cleanName}`;
    if (cleanVer) base += `@${cleanVer}`;
    if (cleanRepo && cleanRepo !== "https://huggingface.co") {
      base += `?repository_url=${encodeURIComponent(cleanRepo)}`;
    }
    return base;
  }

  function isHexSha40(v) {
    return /^[0-9a-f]{40}$/i.test(String(v || "").trim());
  }

  function initAIBOMLineageLab(container) {
    const dataEl = container.querySelector("script.aibom-lineage-lab-data");
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
        id: "apache-clean-stack",
        label: "1. 纯宽松商用栈 (Qwen2.5 + vLLM)",
        desc: "基座模型 Qwen/Qwen2.5-7B-Instruct（Apache-2.0）通过 40 位 Commit SHA 锁定，内部脱敏数据集与 vLLM（Apache-2.0）推理栈血缘完整且无非商业传染条款，可无损导出 CycloneDX 1.7 与 SPDX 3.0.1。",
        baseModel: {
          name: "Qwen/Qwen2.5-7B-Instruct",
          purl: "pkg:huggingface/Qwen/Qwen2.5-7B-Instruct@a09a35458c702b33eeacc393d103063234e8bc28",
          license: "Apache-2.0 (OSI 宽松)",
          pinnedSha: true,
        },
        adapter: {
          name: "无外挂社区 LoRA（全量自研微调）",
          declaredLic: "Apache-2.0",
          inheritedLic: "Apache-2.0",
        },
        dataset: {
          name: "internal-ops-qa-v2 (自有脱敏语料)",
          license: "Proprietary-Internal",
          euSummaryReady: true,
          taintedNC: false,
        },
        runtime: "vllm==0.6.4 (Apache-2.0) + safetensors",
        hasOpenRAILRestriction: false,
        hasLlamaRestriction: false,
        apply: { useLoraTrace: true, useDatasetGate: true, enforceShaPin: true, formatMode: "cdx" },
      },
      {
        id: "llama-lora-inheritance",
        label: "2. Llama 3.1 + LoRA 许可隐性继承",
        desc: "算法团队下载了一个声称 MIT 协议的客服 LoRA 适配器，但只读解析 adapter_config.json 后发现其 base_model_name_or_path 指向 meta-llama/Llama-3.1-8B-Instruct；合并权重依法强制继承 Llama 3 Community License。",
        baseModel: {
          name: "meta-llama/Llama-3.1-8B-Instruct",
          purl: "pkg:huggingface/meta-llama/Llama-3.1-8B-Instruct@0e9e39f249a16976918f6564b8830bc894c89659",
          license: "Llama-3.1 Community (非 OSI)",
          pinnedSha: true,
        },
        adapter: {
          name: "acme/cs-lora-v1 (宣称 MIT，实测绑定 Llama)",
          declaredLic: "MIT",
          inheritedLic: "Llama-3.1 Community (700M MAU / Built with Llama)",
        },
        dataset: {
          name: "customer-ticket-clean (自有合规脱敏)",
          license: "Proprietary-Internal",
          euSummaryReady: true,
          taintedNC: false,
        },
        runtime: "llama.cpp GGUF (general.license=llama3.1)",
        hasOpenRAILRestriction: false,
        hasLlamaRestriction: true,
        apply: { useLoraTrace: true, useDatasetGate: true, enforceShaPin: true, formatMode: "spdx" },
      },
      {
        id: "cc-by-nc-dataset-taint",
        label: "3. Apache 基座被 CC-BY-NC 数据集污染",
        desc: "表面看基座模型与推理框架全部是 Apache-2.0，但训练血缘 trainedOn 链路中混入了一个 CC-BY-NC-4.0（禁止商业用途）社区微调语料，且缺少 EU AI Act Art. 53(1)(d) 训练数据摘要。",
        baseModel: {
          name: "mistralai/Mistral-7B-v0.3",
          purl: "pkg:huggingface/mistralai/Mistral-7B-v0.3@e0bc86c23ce5aae1db576c8cca6f06f1f73af2db",
          license: "Apache-2.0 (OSI 宽松)",
          pinnedSha: true,
        },
        adapter: {
          name: "fin-qa-lora (训练配置引入三方数据集)",
          declaredLic: "Apache-2.0",
          inheritedLic: "商业禁区 · 受 CC-BY-NC-4.0 数据污染",
        },
        dataset: {
          name: "community/fin-alpaca-zh (CC-BY-NC-4.0)",
          license: "CC-BY-NC-4.0 (禁商用!)",
          euSummaryReady: false,
          taintedNC: true,
        },
        runtime: "PyTorch + Transformers (Apache-2.0)",
        hasOpenRAILRestriction: false,
        hasLlamaRestriction: false,
        apply: { useLoraTrace: true, useDatasetGate: true, enforceShaPin: true, formatMode: "spdx" },
      },
      {
        id: "mutable-main-and-openrail",
        label: "4. @main 可变引用漂移 + OpenRAIL 禁令",
        desc: "推理服务代码直接写 from_pretrained('org/guard-vision', revision='main') 未钉死 40 位 Commit SHA，上游若被接管即可静默替换权重；且该模型受 OpenRAIL-M 条款禁止用于监控/生物识别场景。",
        baseModel: {
          name: "org/guard-vision@main (可变分支!)",
          purl: "pkg:huggingface/org/guard-vision@main",
          license: "OpenRAIL-M (领域禁用条款)",
          pinnedSha: false,
        },
        adapter: {
          name: "security-cam-adapter (继承 OpenRAIL)",
          declaredLic: "OpenRAIL-M",
          inheritedLic: "OpenRAIL-M (禁止生物识别与大规模监控)",
        },
        dataset: {
          name: "open-street-faces (含合规风险语料)",
          license: "OpenRAIL-Dataset",
          euSummaryReady: false,
          taintedNC: false,
        },
        runtime: "ONNX Runtime (MIT)",
        hasOpenRAILRestriction: true,
        hasLlamaRestriction: false,
        apply: { useLoraTrace: true, useDatasetGate: true, enforceShaPin: true, formatMode: "cdx" },
      },
    ];

    const PURL_EXAMPLES = [
      {
        label: "Qwen2.5 (40位SHA)",
        ns: "Qwen",
        name: "Qwen2.5-7B-Instruct",
        ver: "A09A35458C702B33EEACC393D103063234E8BC28",
        repo: "https://huggingface.co",
        lic: "apache-mit",
      },
      {
        label: "Llama 3.1 (社区许可)",
        ns: "meta-llama",
        name: "Llama-3.1-8B-Instruct",
        ver: "0e9e39f249a16976918f6564b8830bc894c89659",
        repo: "https://huggingface.co",
        lic: "llama3",
      },
      {
        label: "可变 @main 分支风险",
        ns: "org",
        name: "guard-vision",
        ver: "main",
        repo: "https://hub-ci.huggingface.co",
        lic: "openrail",
      },
    ];

    const state = {
      activeTab: "lineage", // "lineage" | "purl"
      presetId: "llama-lora-inheritance",
      useLoraTrace: true,
      useDatasetGate: true,
      enforceShaPin: true,
      formatMode: "cdx", // "cdx" | "spdx"
      // 模式二
      hfNamespace: "meta-llama",
      hfName: "Llama-3.1-8B-Instruct",
      hfVersion: "0E9E39F249A16976918F6564B8830BC894C89659",
      hfRepo: "https://huggingface.co",
      licenseFamily: "llama3", // "apache-mit" | "llama3" | "openrail" | "cc-by-nc"
      mauOver700M: false,
      euGpaiService: true,
    };

    function getCurrentPreset() {
      return PRESETS.find((p) => p.id === state.presetId) || PRESETS[0];
    }

    function evaluateLineage(preset) {
      const legacySbom = {
        tone: "is-bad",
        verdict: "仅见 Python 包 · 模型血缘全盲",
        meta: "缺失 Model / LoRA / Dataset 节点",
        desc:
          preset.id === "apache-clean-stack"
            ? "传统代码 SBOM 只能扫出 requirements.txt 里的 torch 和 vllm，完全记录不到模型权重与训练数据集血缘。"
            : "在代码 SBOM 里一切看似全是 MIT/Apache-2.0，对 Llama 传染、CC-BY-NC 数据集污染与 @main 权重漂移全面失明。",
      };

      let naiveAiScan;
      if (preset.id === "apache-clean-stack") {
        naiveAiScan = {
          tone: "is-ok",
          verdict: "基础模型单点可见（无数据血缘）",
          meta: "仅记录 Qwen2.5 单个权重文件",
          desc: "如果仅登记主模型文件而不追溯数据集与框架血缘，遇到合规审计或 EU AI Act 摘要核验时仍缺关键链路。",
        };
      } else if (preset.id === "llama-lora-inheritance") {
        naiveAiScan = {
          tone: "is-bad",
          verdict: "轻信 LoRA 声明 MIT · 漏报 Llama 传染",
          meta: "未解析 adapter_config.json",
          desc: "仅看 LoRA 仓库 README 写着 MIT 就放行上线，遗漏了其绑定 meta-llama 基座带来的 700M MAU 与命名/署名义务。",
        };
      } else if (preset.id === "cc-by-nc-dataset-taint") {
        naiveAiScan = {
          tone: "is-bad",
          verdict: "误判 100% 商用合规 · 漏报 NC 污染",
          meta: "只看基座权重不查 trainedOn 数据集",
          desc: "Mistral 基座确为 Apache-2.0，但未关联上游微调数据集的 CC-BY-NC-4.0 非商用限制，埋下重大版权违约雷。",
        };
      } else {
        naiveAiScan = {
          tone: "is-warn",
          verdict: "允许 @main 浮动拉取 · 缺防篡改钉死",
          meta: "未强制 40 位 Commit Hash 校验",
          desc: "虽看到了 OpenRAIL-M 标签，但未拦截可变的 @main 分支引用，上游权重随时可能被静默篡改。",
        };
      }

      // 推荐：统一 Layer 2 AI-BOM 血缘引擎（完全严格随 3 个开关联动）
      const missedLora = preset.hasLlamaRestriction && !state.useLoraTrace;
      const missedDataset = (preset.dataset.taintedNC || !preset.dataset.euSummaryReady) && !state.useDatasetGate;
      const missedSha = !preset.baseModel.pinnedSha && !state.enforceShaPin;

      let modernEngine;
      if (preset.id === "apache-clean-stack") {
        modernEngine = {
          tone: "is-ok",
          verdict: "全血缘校验通过 · 无损导出双标准",
          meta: "SHA 锁定 · 许可纯宽松 · 摘要齐全",
          desc: "Layer 2 图谱完整串联权重、自有数据与 vLLM，一键投影 CycloneDX 1.7 ML-BOM 与 SPDX 3.0.1 JSON-LD。",
        };
      } else if (missedLora || missedDataset || missedSha) {
        const missingList = [];
        if (missedLora) missingList.push("LoRA 基座追溯");
        if (missedDataset) missingList.push("数据集/EU 摘要门禁");
        if (missedSha) missingList.push("40位 SHA 强制钉死");
        modernEngine = {
          tone: "is-bad",
          verdict: `门禁盲区 · 漏放高危风险`,
          meta: `已关闭：${missingList.join(" + ")}`,
          desc: `由于关闭了「${missingList.join("、")}」，引擎未能截获该场景隐藏的真实合规/防篡改违规，请打开对应核验开关。`,
        };
      } else if (preset.id === "llama-lora-inheritance") {
        modernEngine = {
          tone: "is-warn",
          verdict: "阻断误标 MIT · 强制继承 Llama 履约",
          meta: "已解析 base_model_name_or_path",
          desc: "识别出 LoRA 绑定 Llama-3.1 基座：放行前强制校验 MAU < 700M、UI 加注 \"Built with Llama\" 且衍生名称以 Llama 开头。",
        };
      } else if (preset.id === "cc-by-nc-dataset-taint") {
        modernEngine = {
          tone: "is-ok",
          verdict: "精准拦截 CC-BY-NC 商用污染与缺摘要",
          meta: "trainedOn 边阻断 + Art. 53 告警",
          desc: "沿模型 -> 微调任务 -> 数据集血缘反向追踪，在上线前拦截了非商业语料污染，并提示补齐 EU AI Act 训练数据摘要。",
        };
      } else {
        modernEngine = {
          tone: "is-ok",
          verdict: "拦截 @main 漂移 + 阻断 OpenRAIL 越界",
          meta: "OWASP LLM03 阻断 · 必须钉死 SHA",
          desc: "拒绝可变分支 @main 下载并强制改写为 40 位 Commit SHA，同时针对 OpenRAIL-M 使用限制要求业务场景审批豁免。",
        };
      }

      return { legacySbom, naiveAiScan, modernEngine, missedLora, missedDataset, missedSha };
    }

    function buildExportPayload(preset, evalRes) {
      if (state.formatMode === "cdx") {
        const effectiveLic =
          preset.id === "llama-lora-inheritance" && !state.useLoraTrace
            ? preset.adapter.declaredLic + " (UNVERIFIED - 漏追溯基座!)"
            : preset.adapter.inheritedLic;

        const cdxObj = {
          "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
          bomFormat: "CycloneDX",
          specVersion: "1.7",
          components: [
            {
              "bom-ref": "model-base",
              type: "machine-learning-model",
              name: preset.baseModel.name,
              purl: preset.baseModel.purl,
              licenses: [{ license: { name: preset.baseModel.license } }],
              modelCard: {
                modelParameters: {
                  approach: { type: "supervised" },
                  task: "text-generation",
                  architectureFamily: "transformer",
                  datasets: state.useDatasetGate
                    ? [{ "bom-ref": "dataset-train", type: "data", name: preset.dataset.name }]
                    : [],
                },
                considerations: {
                  limitations: [
                    preset.baseModel.pinnedSha || !state.enforceShaPin
                      ? `有效继承许可: ${effectiveLic}`
                      : "BLOCKED: 必须将 @main 钉死为 40 位 Commit SHA",
                  ],
                },
              },
            },
            {
              "bom-ref": "dataset-train",
              type: "data",
              name: preset.dataset.name,
              data: [{ type: "dataset", contents: { properties: [{ name: "license", value: preset.dataset.license }] } }],
            },
          ],
          dependencies: [
            {
              ref: "model-base",
              dependsOn: state.useLoraTrace ? ["dataset-train"] : [],
            },
          ],
          _policyVerdict: evalRes.modernEngine.verdict,
        };
        return JSON.stringify(cdxObj, null, 2);
      }

      // SPDX 3.0.1 JSON-LD 导出视图
      const spdxObj = {
        "@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld",
        "@graph": [
          {
            type: "ai_AIPackage",
            spdxId: "urn:spdx:ai-model-1",
            name: preset.baseModel.name,
            externalIdentifier: [{ externalIdentifierType: "purl", identifier: preset.baseModel.purl }],
            ai_limitation: state.useLoraTrace ? preset.adapter.inheritedLic : "未开启 LoRA 继承溯源",
          },
          {
            type: "dataset_DatasetPackage",
            spdxId: "urn:spdx:dataset-1",
            name: preset.dataset.name,
            dataset_datasetType: "text",
            dataset_dataCollectionProcess: state.useDatasetGate && preset.dataset.euSummaryReady
              ? "EU AI Act Art. 53(1)(d) Summary Recorded"
              : "MISSING_OR_GATE_DISABLED",
          },
          {
            type: "Core_Relationship",
            spdxId: "urn:spdx:rel-trained-on",
            from: "urn:spdx:ai-model-1",
            relationshipType: "trainedOn",
            to: state.useDatasetGate ? ["urn:spdx:dataset-1"] : [],
          },
        ],
      };
      return JSON.stringify(spdxObj, null, 2);
    }

    function renderLineageTab() {
      const preset = getCurrentPreset();
      const res = evaluateLineage(preset);
      const payload = buildExportPayload(preset, res);

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
              <span class="grl-control-label">1. AI-BOM 血缘分析与合规门禁开关</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="loratrace" ${state.useLoraTrace ? "checked" : ""} />
                <span>启用 <strong>LoRA / GGUF 头部血缘递归追溯</strong>（读取 <code>base_model_name_or_path</code> 继承基座许可）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="datasetgate" ${state.useDatasetGate ? "checked" : ""} />
                <span>启用 <strong><code>trainedOn</code> 数据集商用污染 &amp; EU AI Act Art. 53</strong> 摘要校验</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="shapin" ${state.enforceShaPin ? "checked" : ""} />
                <span>强制 <strong><code>pkg:huggingface</code> 40 位 Commit SHA 钉死</strong>（禁止 <code>@main</code> 可变引用）</span>
              </label>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">2. 切换双向标准无损投影输出</span>
              <div class="grl-pill-group">
                <button type="button" class="grl-pill is-accent ${state.formatMode === "cdx" ? "active" : ""}" data-fmt="cdx">
                  CycloneDX 1.7 ML-BOM (modelCard)
                </button>
                <button type="button" class="grl-pill is-accent ${state.formatMode === "spdx" ? "active" : ""}" data-fmt="spdx">
                  SPDX 3.0.1 JSON-LD (AI/Dataset)
                </button>
              </div>
            </div>

            <div class="grl-control-group">
              <span class="grl-control-label">3. 推理栈与无加载采集声明</span>
              <div style="font-size:0.77rem;line-height:1.55;color:var(--ink-secondary);">
                <div>&bull; <strong>推理栈：</strong><code>${escapeHtml(preset.runtime)}</code></div>
                <div>&bull; <strong>采集方式：</strong>只读解析 JSON / GGUF Header / Safetensors 头（<strong>严禁 <code>torch.load()</code> 执行反序列化</strong>）</div>
              </div>
            </div>
          </div>

          <div>
            <div class="grl-compare-grid">
              <div class="grl-card ${res.legacySbom.tone}">
                <div class="grl-card-kicker">反例 A · 传统代码 SBOM</div>
                <div class="grl-card-title">${escapeHtml(res.legacySbom.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.legacySbom.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.legacySbom.desc)}</p>
              </div>

              <div class="grl-card ${res.naiveAiScan.tone}">
                <div class="grl-card-kicker">反例 B · 仅登记单模型清单</div>
                <div class="grl-card-title">${escapeHtml(res.naiveAiScan.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.naiveAiScan.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.naiveAiScan.desc)}</p>
              </div>

              <div class="grl-card ${res.modernEngine.tone}">
                <div class="grl-card-kicker">推荐 · 统一 Layer 2 AI-BOM</div>
                <div class="grl-card-title">${escapeHtml(res.modernEngine.verdict)}</div>
                <div class="grl-card-meta">${escapeHtml(res.modernEngine.meta)}</div>
                <p class="grl-card-desc">${escapeHtml(res.modernEngine.desc)}</p>
              </div>
            </div>

            <div class="grl-graph-grid">
              <div class="grl-dep-node ${!preset.baseModel.pinnedSha && state.enforceShaPin ? "is-conflict" : "is-upgraded"}">
                <div class="grl-dep-role">1. 基座模型 (Base Model)</div>
                <div class="grl-dep-name">${escapeHtml(preset.baseModel.name)}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.baseModel.license)}</div>
                <div class="grl-dep-note">${preset.baseModel.pinnedSha ? "40位 SHA 已锁定" : state.enforceShaPin ? "拦截：可变 @main 引用!" : "警告：SHA 校验已关闭"}</div>
              </div>

              <div class="grl-dep-node ${preset.hasLlamaRestriction || preset.hasOpenRAILRestriction ? "is-warn" : "is-safe"}">
                <div class="grl-dep-role">2. 适配器 / 合并链路 (LoRA)</div>
                <div class="grl-dep-name">${escapeHtml(preset.adapter.name)}</div>
                <div class="grl-dep-ver">有效许可：${escapeHtml(state.useLoraTrace ? preset.adapter.inheritedLic : preset.adapter.declaredLic + " (未追溯)")}</div>
              </div>

              <div class="grl-dep-node ${!state.useDatasetGate ? "" : preset.dataset.taintedNC || !preset.dataset.euSummaryReady ? "is-conflict" : "is-safe"}">
                <div class="grl-dep-role">3. 训练数据 (trainedOn)</div>
                <div class="grl-dep-name">${escapeHtml(preset.dataset.name)}</div>
                <div class="grl-dep-ver">${escapeHtml(preset.dataset.license)}</div>
                <div class="grl-dep-note">EU Art.53 摘要：${preset.dataset.euSummaryReady ? "完整" : "缺失"}</div>
              </div>
            </div>

            <div class="grl-payload-box">
              <div class="grl-payload-head">
                <span class="grl-payload-title">${
                  state.formatMode === "cdx"
                    ? "双向投影 1：CycloneDX 1.7 ML-BOM（modelCard + data 组件）"
                    : "双向投影 2：SPDX 3.0.1 JSON-LD（ai_AIPackage --trainedOn--> dataset_DatasetPackage）"
                }</span>
                <span class="badge ${res.modernEngine.tone === "is-ok" ? "badge-ok" : res.modernEngine.tone === "is-warn" ? "badge-warn" : "badge-danger"}">
                  ${escapeHtml(res.modernEngine.verdict)}
                </span>
              </div>
              <pre class="grl-payload-pre"><code>${escapeHtml(payload)}</code></pre>
            </div>
          </div>
        </div>
      `;
    }

    function evaluatePurlAndPolicy() {
      const purl = buildHfPurl(state.hfNamespace, state.hfName, state.hfVersion, state.hfRepo);
      const shaOk = isHexSha40(state.hfVersion);
      const hasUpperCaseHash = /[A-F]/.test(String(state.hfVersion || ""));

      let isOsi = false;
      let commercialVerdict = "禁商业发布";
      let badgeCls = "badge-danger";
      const obligations = [];

      if (state.licenseFamily === "apache-mit") {
        isOsi = true;
        commercialVerdict = shaOk ? "允许商用发布" : "须先钉死 40 位 SHA";
        badgeCls = shaOk ? "badge-ok" : "badge-warn";
        obligations.push("保留原作者版权声明与 NOTICE（Apache-2.0 / MIT 标准义务）");
      } else if (state.licenseFamily === "llama3") {
        isOsi = false;
        if (state.mauOver700M) {
          commercialVerdict = "阻断 · 超 700M MAU 需向 Meta 另签商业授权";
          badgeCls = "badge-danger";
        } else {
          commercialVerdict = shaOk ? "条件放行 · 须强制履约" : "阻断 · 缺 SHA 锁定且需履约";
          badgeCls = "badge-warn";
        }
        obligations.push("UI/文档显著位置必须标注 \"Built with Llama\"");
        obligations.push("衍生微调模型名称必须以 \"Llama\" 开头，且禁止用于训练其他大模型");
      } else if (state.licenseFamily === "openrail") {
        isOsi = false;
        commercialVerdict = "人工法务审批 · 受使用领域限制";
        badgeCls = "badge-warn";
        obligations.push("OpenRAIL-M 属行为限制非 OSI 协议：严禁用于监控/生物识别/高危禁用领域，衍生下游须同步继承限制条款");
      } else {
        isOsi = false;
        commercialVerdict = "红线拦截 · CC-BY-NC 禁止商业交付";
        badgeCls = "badge-danger";
        obligations.push("含非商业（Non-Commercial）限制，严禁用于商业闭源产品或商业微调训练集");
      }

      if (state.euGpaiService) {
        obligations.push("EU AI Act Art. 53(1)(d)（2025-08-02 已生效）：必须公开 GPAI 训练数据充分摘要并履行版权 TDM 退出政策披露");
      }
      if (!shaOk) {
        obligations.push("安全门禁阻断：当前 revision 非 40 位十六进制 Commit Hash，存在上游静默篡改权重风险");
      } else if (hasUpperCaseHash) {
        obligations.push("ECMA-427 归一化提示：已自动将大写 Commit Hash 折叠为标准小写，同时保持 namespace/name 大小写敏感");
      }

      return { purl, shaOk, isOsi, commercialVerdict, badgeCls, obligations };
    }

    function renderPurlOutput() {
      const r = evaluatePurlAndPolicy();
      return `
        <div class="grl-impact-panel" style="margin-bottom:0.85rem;">
          <div class="grl-impact-head">
            <span>ECMA-427 <code>pkg:huggingface</code> 规范化与防篡改结果</span>
            <span class="badge ${r.badgeCls}">${escapeHtml(r.commercialVerdict)}</span>
          </div>
          <div class="grl-impact-list">
            <div class="grl-impact-item ${r.shaOk ? "is-clear" : "is-hit"}">
              <strong>Canonical PURL：</strong><code>${escapeHtml(r.purl)}</code>
            </div>
          </div>
        </div>

        <div class="grl-kpi-grid">
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">版本不可变性 (40位 SHA)</div>
            <div class="grl-kpi-val" style="color:${r.shaOk ? "var(--ok)" : "var(--danger)"};">${r.shaOk ? "已锁定 SHA" : "可变分支风险"}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">OSI 开源属性</div>
            <div class="grl-kpi-val">${r.isOsi ? "是 (宽松商用)" : "否 (自定义/限制)"}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">EU AI Act Art. 53</div>
            <div class="grl-kpi-val" style="color:${state.euGpaiService ? "var(--accent-blue)" : "var(--ink-muted)"};">${state.euGpaiService ? "须公开训练摘要" : "未面向 EU 市场"}</div>
          </div>
          <div class="grl-kpi-card">
            <div class="grl-kpi-label">待履约 / 阻断项数</div>
            <div class="grl-kpi-val">${r.obligations.length} 条</div>
          </div>
        </div>

        <div class="grl-bar-card">
          <div style="font-size:0.82rem;font-weight:700;color:var(--ink);margin-bottom:0.45rem;">AI-BOM 政策引擎自动生成的履约与拦截清单：</div>
          <ul style="margin:0;padding-left:1.1rem;font-size:0.8rem;line-height:1.58;color:var(--ink-secondary);">
            ${r.obligations.map((o) => `<li>${escapeHtml(o)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    function updatePurlOutput() {
      const out = container.querySelector(".grl-aibom-purl-out");
      if (out) out.innerHTML = renderPurlOutput();
    }

    function renderPurlTab() {
      return `
        <div class="grl-controls" style="margin-bottom:0.9rem;">
          <div class="grl-preset-bar" style="margin-bottom:0.45rem;">
            ${PURL_EXAMPLES.map(
              (ex, idx) => `
                <button type="button" class="grl-pill" data-purlex="${idx}">
                  填入样例：${escapeHtml(ex.label)}
                </button>
              `
            ).join("")}
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0.75rem;">
            <div>
              <span class="grl-control-label">Namespace（区分大小写）</span>
              <input type="text" data-hf="ns" value="${escapeHtml(state.hfNamespace)}"
                style="width:100%;margin-top:0.3rem;padding:0.4rem 0.6rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.8rem;background:var(--surface);color:var(--ink);" />
            </div>
            <div>
              <span class="grl-control-label">Model Name（区分大小写）</span>
              <input type="text" data-hf="name" value="${escapeHtml(state.hfName)}"
                style="width:100%;margin-top:0.3rem;padding:0.4rem 0.6rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.8rem;background:var(--surface);color:var(--ink);" />
            </div>
            <div>
              <span class="grl-control-label">Commit Hash（自动转小写）</span>
              <input type="text" data-hf="ver" value="${escapeHtml(state.hfVersion)}"
                style="width:100%;margin-top:0.3rem;padding:0.4rem 0.6rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.8rem;background:var(--surface);color:var(--ink);" />
            </div>
            <div>
              <span class="grl-control-label">Repository URL（默认 HF 省略）</span>
              <input type="text" data-hf="repo" value="${escapeHtml(state.hfRepo)}"
                style="width:100%;margin-top:0.3rem;padding:0.4rem 0.6rem;border:1px solid var(--rule);border-radius:4px;font-family:var(--font-mono);font-size:0.8rem;background:var(--surface);color:var(--ink);" />
            </div>
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0.75rem;padding-top:0.45rem;border-top:1px dashed var(--rule);">
            <div>
              <span class="grl-control-label">选择模型 / 数据集许可族</span>
              <div class="grl-pill-group" style="margin-top:0.35rem;">
                <button type="button" class="grl-pill ${state.licenseFamily === "apache-mit" ? "active" : ""}" data-licfam="apache-mit">Apache-2.0 / MIT</button>
                <button type="button" class="grl-pill ${state.licenseFamily === "llama3" ? "active" : ""}" data-licfam="llama3">Llama 3 Community</button>
                <button type="button" class="grl-pill ${state.licenseFamily === "openrail" ? "active" : ""}" data-licfam="openrail">OpenRAIL-M</button>
                <button type="button" class="grl-pill ${state.licenseFamily === "cc-by-nc" ? "active" : ""}" data-licfam="cc-by-nc">CC-BY-NC-4.0</button>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:0.45rem;">
              <span class="grl-control-label">业务部署与法规约束参数</span>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="mau700" ${state.mauOver700M ? "checked" : ""} />
                <span>企业服务月活用户（MAU）超过 <strong>700 Million</strong>（触发 Llama 商业阈值）</span>
              </label>
              <label class="grl-toggle">
                <input type="checkbox" data-toggle="eugpai" ${state.euGpaiService ? "checked" : ""} />
                <span>向欧盟市场提供通用 AI（GPAI）服务（触发 <strong>EU AI Act Art. 53</strong>）</span>
              </label>
            </div>
          </div>
        </div>

        <div class="grl-aibom-purl-out">${renderPurlOutput()}</div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：AI-BOM 血缘投影与非 OSI 模型合规模拟";
      const intro =
        config.intro ||
        "切换 LoRA 继承、数据集污染与 @main 漂移场景，实时导出 CycloneDX 1.7 / SPDX 3.0.1 视图，并核验 pkg:huggingface 与合规条款。";

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">Lesson 0017 · AI-BOM Lineage Lab</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>

        <div class="grl-tabs">
          <button type="button" class="grl-tab-btn ${state.activeTab === "lineage" ? "active" : ""}" data-tab="lineage">
            <span class="grl-tab-num">1</span>
            模式一：四维血缘图谱、许可传染与双标准投影
          </button>
          <button type="button" class="grl-tab-btn ${state.activeTab === "purl" ? "active" : ""}" data-tab="purl">
            <span class="grl-tab-num">2</span>
            模式二：pkg:huggingface (ECMA-427) 与非 OSI/EU 合规检验
          </button>
        </div>

        ${state.activeTab === "lineage" ? renderLineageTab() : renderPurlTab()}
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

      container.querySelectorAll("[data-fmt]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.formatMode = btn.dataset.fmt;
          render();
        });
      });

      container.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => {
          if (cb.dataset.toggle === "loratrace") state.useLoraTrace = cb.checked;
          if (cb.dataset.toggle === "datasetgate") state.useDatasetGate = cb.checked;
          if (cb.dataset.toggle === "shapin") state.enforceShaPin = cb.checked;
          if (cb.dataset.toggle === "mau700") state.mauOver700M = cb.checked;
          if (cb.dataset.toggle === "eugpai") state.euGpaiService = cb.checked;
          if (state.activeTab === "purl") updatePurlOutput();
          else render();
        });
      });

      container.querySelectorAll("[data-purlex]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ex = PURL_EXAMPLES[Number(btn.dataset.purlex)];
          if (!ex) return;
          state.hfNamespace = ex.ns;
          state.hfName = ex.name;
          state.hfVersion = ex.ver;
          state.hfRepo = ex.repo;
          state.licenseFamily = ex.lic;
          render();
        });
      });

      container.querySelectorAll("[data-licfam]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.licenseFamily = btn.dataset.licfam;
          render();
        });
      });

      container.querySelectorAll("[data-hf]").forEach((inp) => {
        inp.addEventListener("input", (e) => {
          const field = inp.dataset.hf;
          if (field === "ns") state.hfNamespace = e.target.value;
          if (field === "name") state.hfName = e.target.value;
          if (field === "ver") state.hfVersion = e.target.value;
          if (field === "repo") state.hfRepo = e.target.value;
          updatePurlOutput();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll('[data-widget="aibom-lineage-lab"]')
      .forEach(initAIBOMLineageLab);
  });
})();
