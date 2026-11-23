/* ==========================================================================
   Reusable ECMA-427 PURL Parser, Normalizer & Pitfall Lab Widget
   Zero-dependency vanilla JS shared across Layer 2 / Layer 3 lessons.
   Usage:
     <section class="widget-panel" data-widget="purl-lab">
       <script type="application/json" class="purl-lab-data">{ ... }</script>
     </section>
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

  function safeDecode(str) {
    try {
      return decodeURIComponent(str);
    } catch (_) {
      return str;
    }
  }

  function encodePurlSegment(str) {
    return encodeURIComponent(str).replace(/%3A/gi, ":");
  }

  function encodeQualifierVal(str) {
    return encodeURIComponent(str).replace(/%2F/gi, "/").replace(/%3A/gi, ":");
  }

  const MATCH_RELEVANT_QUALIFIERS = {
    deb: ["distro", "arch", "epoch", "upstream"],
    rpm: ["distro", "arch", "epoch", "upstream"],
    apk: ["distro", "arch", "upstream"],
    maven: ["classifier", "type", "packaging"],
    oci: ["arch", "os"],
  };

  function parseAndNormalizePurl(rawInput) {
    const input = (rawInput || "").trim();
    const diags = [];

    if (!input) {
      return { valid: false, error: "请输入一个 PURL 字符串，或点击上方预设案例体验解析。", diags };
    }

    let rest = input;

    // 1. Scheme
    const colonIdx = rest.indexOf(":");
    if (colonIdx === -1) {
      return { valid: false, error: "缺少 scheme 分隔符 ':'（合规 PURL 必须以 'pkg:' 开头）。", diags };
    }
    const rawScheme = rest.slice(0, colonIdx);
    const scheme = rawScheme.toLowerCase();
    if (scheme !== "pkg") {
      return { valid: false, error: `非法 scheme '${rawScheme}'：ECMA-427 规定 scheme 必须恒为 'pkg'。`, diags };
    }
    if (rawScheme !== "pkg") {
      diags.push({ level: "warn", text: `Scheme '${rawScheme}' 已强制规范化为小写 'pkg'。` });
    }
    rest = rest.slice(colonIdx + 1).replace(/^\/+/, "");

    // 2. Subpath (# from right)
    let rawSubpath = "";
    let subpath = "";
    const hashIdx = rest.lastIndexOf("#");
    if (hashIdx !== -1) {
      rawSubpath = rest.slice(hashIdx + 1);
      rest = rest.slice(0, hashIdx);
      const cleanSegs = rawSubpath
        .split("/")
        .map((s) => safeDecode(s).trim())
        .filter((s) => s !== "" && s !== "." && s !== "..");
      subpath = cleanSegs.join("/");
      if (rawSubpath !== subpath && rawSubpath !== "") {
        diags.push({ level: "warn", text: `Subpath 已清洗冗余路径片段（移除前导斜杠、'.' 或 '..'）：#${subpath || "(已清空)"}。` });
      }
    }

    // 3. Qualifiers (? from right)
    let rawQualStr = "";
    const qualifiers = [];
    const qIdx = rest.lastIndexOf("?");
    if (qIdx !== -1) {
      rawQualStr = rest.slice(qIdx + 1);
      rest = rest.slice(0, qIdx);
      const pairs = rawQualStr.split("&").filter((p) => p.length > 0);
      const rawKeys = [];
      const seenKeys = new Map();

      pairs.forEach((pair) => {
        const eqIdx = pair.indexOf("=");
        if (eqIdx === -1) {
          diags.push({ level: "warn", text: `忽略无效 qualifier 片段 '${pair}'（缺少 '='）。` });
          return;
        }
        const rawK = pair.slice(0, eqIdx).trim();
        const k = rawK.toLowerCase();
        const v = safeDecode(pair.slice(eqIdx + 1).trim());
        if (rawK !== k) {
          diags.push({ level: "warn", text: `Qualifier 键 '${rawK}' 已规范化为小写 '${k}'。` });
        }
        if (!v) {
          diags.push({ level: "warn", text: `Qualifier '${k}' 值为空，按 ECMA-427 规范已剔除。` });
          return;
        }
        rawKeys.push(k);
        if (seenKeys.has(k)) {
          diags.push({ level: "warn", text: `检测到重复 Qualifier 键 '${k}'，已保留后者并告警去重。` });
        }
        seenKeys.set(k, v);
      });

      const sortedKeys = Array.from(seenKeys.keys()).sort();
      if (rawKeys.length > 1 && rawKeys.join(",") !== sortedKeys.join(",")) {
        diags.push({ level: "warn", text: `Qualifiers 未按字典序排列（原序：${rawKeys.join(" → ")}），已重排为：${sortedKeys.join(" → ")}，防止哈希主键不一致。` });
      }
      sortedKeys.forEach((k) => qualifiers.push([k, seenKeys.get(k)]));
    }

    // 4. Type (first slash)
    const firstSlash = rest.indexOf("/");
    if (firstSlash === -1) {
      return { valid: false, error: "缺少 type 与 name 分隔符 '/'（格式应为 pkg:<type>/[namespace/]<name>）。", diags };
    }
    const rawType = rest.slice(0, firstSlash);
    const type = rawType.toLowerCase();
    if (!type || !/^[a-z][a-z0-9.+-]*$/.test(type)) {
      return { valid: false, error: `非法 type '${rawType}'：必须以 ASCII 字母开头，仅含字母/数字/./+/-。`, diags };
    }
    if (rawType !== type) {
      diags.push({ level: "warn", text: `生态类型 type '${rawType}' 已规范化为小写 '${type}'。` });
    }
    rest = rest.slice(firstSlash + 1).replace(/^\/+/, "");

    // 5. Version (@ from right, carefully handling unencoded npm @scope)
    let rawVersion = "";
    let version = "";
    const lastAt = rest.lastIndexOf("@");
    if (lastAt !== -1) {
      const afterAt = rest.slice(lastAt + 1);
      if (afterAt.includes("/")) {
        // Unencoded @scope without version, e.g. npm/@angular/core
        diags.push({
          level: "warn",
          text: "检测到路径段中出现未编码的 '@'（例如 npm scope '@org'）。按 ECMA-427 规范必须百分比编码为 '%40'，避免与版本分隔符 '@' 冲突。",
        });
      } else {
        rawVersion = afterAt;
        version = safeDecode(rawVersion);
        rest = rest.slice(0, lastAt);
      }
    }

    // Check if remaining path still has unencoded @
    if (rest.includes("@")) {
      diags.push({
        level: "warn",
        text: "Namespace/Name 中包含未百分比编码的 '@'，规范化输出已自动转义为 '%40'。",
      });
    }

    // 6. Split Namespace & Name
    rest = rest.replace(/\/+$/, "");
    if (!rest) {
      return { valid: false, error: "缺少组件名称 <name>。", diags };
    }
    const lastSlash = rest.lastIndexOf("/");
    let rawNamespace = "";
    let rawName = rest;
    if (lastSlash !== -1) {
      rawNamespace = rest.slice(0, lastSlash);
      rawName = rest.slice(lastSlash + 1);
    }

    let nsSegments = rawNamespace
      ? rawNamespace.split("/").filter(Boolean).map((s) => safeDecode(s))
      : [];
    let name = safeDecode(rawName);

    // 7. Ecosystem-specific canonicalization rules (ECMA-427 / purl-spec)
    if (type === "pypi") {
      if (nsSegments.length > 0) {
        diags.push({ level: "warn", text: "PyPI 生态不使用 namespace，请确认是否误填了组织前缀。" });
      }
      const pep503 = name.toLowerCase().replace(/[-_.]+/g, "-");
      if (pep503 !== name) {
        diags.push({
          level: "warn",
          text: `PyPI (PEP 503) 规范化：'${name}' → '${pep503}'（小写且将 '_' / '.' / 连续 '-' 折叠为单个 '-'）。不做此归一会导致跨工具去重失败与漏报。`,
        });
        name = pep503;
      } else {
        diags.push({ level: "ok", text: "符合 PyPI (PEP 503) 命名规范，可直接作为跨源漏洞匹配主键。" });
      }
    } else if (type === "npm") {
      const lowerName = name.toLowerCase();
      if (lowerName !== name) {
        diags.push({ level: "warn", text: `npm 包名已规范化为小写：'${name}' → '${lowerName}'。` });
        name = lowerName;
      }
      nsSegments = nsSegments.map((seg) => {
        const low = seg.toLowerCase();
        if (low !== seg) {
          diags.push({ level: "warn", text: `npm scope 已规范化为小写：'${seg}' → '${low}'。` });
        }
        return low;
      });
    } else if (type === "maven") {
      if (nsSegments.length === 0) {
        diags.push({ level: "error", text: "Maven 生态必须提供 namespace（即 groupId，例如 org.apache.logging.log4j），缺失将导致无法匹配坐标。" });
      } else {
        diags.push({ level: "ok", text: "Maven groupId 与 artifactId 大小写敏感且原样保留；若存在 classifier/type 限定符，须在构件级保留区分。" });
      }
    } else if (type === "golang") {
      let hadUpper = false;
      nsSegments = nsSegments.map((seg) => {
        if (seg !== seg.toLowerCase()) hadUpper = true;
        return seg.toLowerCase();
      });
      if (name !== name.toLowerCase()) {
        hadUpper = true;
        name = name.toLowerCase();
      }
      if (hadUpper) {
        diags.push({
          level: "warn",
          text: "Golang 规范暗坑（purl-spec #308）：ECMA-427 要求 namespace/name 统一小写，但 #subpath 保留大小写。工程落地时建议同时在 IR 中保留原始 raw_module_path 以兼容大小写敏感的 Go 仓库/代理。",
        });
      } else {
        diags.push({ level: "ok", text: "Golang 模块路径已按规范小写化，#subpath 保持大小写敏感用于定位子包。" });
      }
    } else if (type === "deb" || type === "rpm" || type === "apk") {
      nsSegments = nsSegments.map((s) => s.toLowerCase());
      if (type === "deb" || type === "apk") {
        name = name.toLowerCase();
      } else if (name !== name.toLowerCase()) {
        diags.push({
          level: "ok",
          text: `RPM 包名大小写敏感（已原样保留 '${name}'），发行商 namespace 已规范化为小写。`,
        });
      }
      const qMap = new Map(qualifiers);
      if (!qMap.has("distro")) {
        diags.push({
          level: "warn",
          text: `OS 发行版包 (${type}) 缺少 'distro' 限定符！缺少发行版上下文会导致 Layer 3 无法识别 Debian/RHEL 安全回溯补丁（Backport），从而产生大量误报。`,
        });
      } else {
        diags.push({
          level: "ok",
          text: `已捕获发行版限定符 distro=${qMap.get("distro")}：Layer 3 匹配引擎将据此定位发行版安全公告（如 Debian DSA / Red Hat RHSA），规避上游版本号误报。`,
        });
      }
    } else if (type === "huggingface") {
      if (version && version !== version.toLowerCase()) {
        diags.push({
          level: "warn",
          text: `Hugging Face 模型 revision (Git commit hash) 按规范须全小写：'${version}' → '${version.toLowerCase()}'。`,
        });
        version = version.toLowerCase();
      }
      diags.push({
        level: "ok",
        text: "AI-BOM 统一主键示范：通过 pkg:huggingface/<org>/<model>@<commit-sha>，模型权重与传统软件包共享同一 Layer 2 IR 主键体系。",
      });
    }

    // 8. Reassemble canonical strings
    const encodedNs = nsSegments.map(encodePurlSegment).join("/");
    const encodedName = encodePurlSegment(name);
    const encodedVer = version ? encodePurlSegment(version) : "";
    const encodedSubpath = subpath ? subpath.split("/").map(encodePurlSegment).join("/") : "";

    const basePurl = `pkg:${type}/${encodedNs ? encodedNs + "/" : ""}${encodedName}`;
    let canonical = basePurl;
    if (encodedVer) canonical += `@${encodedVer}`;
    if (qualifiers.length > 0) {
      canonical += "?" + qualifiers.map(([k, v]) => `${k}=${encodeQualifierVal(v)}`).join("&");
    }
    if (encodedSubpath) {
      canonical += `#${encodedSubpath}`;
    }

    // Layer 3 match key (keeps version + match-relevant qualifiers, strips download_url/repository_url/checksum/subpath)
    const relevantKeys = MATCH_RELEVANT_QUALIFIERS[type] || [];
    const matchQuals = qualifiers.filter(([k]) => relevantKeys.includes(k));
    let matchKey = basePurl + (encodedVer ? `@${encodedVer}` : "");
    if (matchQuals.length > 0) {
      matchKey += "?" + matchQuals.map(([k, v]) => `${k}=${encodeQualifierVal(v)}`).join("&");
    }

    if (diags.length === 0) {
      diags.push({ level: "ok", text: "输入已完全符合 ECMA-427 规范化格式，无需额外改写。" });
    }

    return {
      valid: true,
      parts: {
        scheme,
        type,
        namespace: encodedNs,
        name: encodedName,
        version: encodedVer,
        qualifiers,
        subpath: encodedSubpath,
      },
      basePurl,
      matchKey,
      canonical,
      changed: canonical !== input,
      diags,
    };
  }

  function initPurlLab(container) {
    const dataEl = container.querySelector("script.purl-lab-data");
    if (!dataEl) return;

    let config;
    try {
      config = JSON.parse(dataEl.textContent);
    } catch (_) {
      container.innerHTML = "<p>PURL 实验台配置解析失败。</p>";
      return;
    }

    const presets = config.presets || [];
    const state = {
      activePreset: 0,
      input: presets[0] ? presets[0].purl : "pkg:pypi/Django_Rest.Framework@3.14.0",
    };

    function renderResultOnly(resEl) {
      const res = parseAndNormalizePurl(state.input);
      if (!res.valid) {
        resEl.innerHTML = `<div class="purl-diag-item error"><strong>解析错误：</strong>${escapeHtml(res.error)}</div>`;
        return;
      }

      const p = res.parts;
      let segHtml = `<span class="pseg pseg-scheme">${escapeHtml(p.scheme)}</span><span class="pseg-sep">:</span>`;
      segHtml += `<span class="pseg pseg-type">${escapeHtml(p.type)}</span><span class="pseg-sep">/</span>`;
      if (p.namespace) {
        segHtml += `<span class="pseg pseg-namespace">${escapeHtml(p.namespace)}</span><span class="pseg-sep">/</span>`;
      }
      segHtml += `<span class="pseg pseg-name">${escapeHtml(p.name)}</span>`;
      if (p.version) {
        segHtml += `<span class="pseg-sep">@</span><span class="pseg pseg-version">${escapeHtml(p.version)}</span>`;
      }
      if (p.qualifiers.length > 0) {
        const qStr = p.qualifiers.map(([k, v]) => `${k}=${encodeQualifierVal(v)}`).join("&");
        segHtml += `<span class="pseg-sep">?</span><span class="pseg pseg-qual">${escapeHtml(qStr)}</span>`;
      }
      if (p.subpath) {
        segHtml += `<span class="pseg-sep">#</span><span class="pseg pseg-subpath">${escapeHtml(p.subpath)}</span>`;
      }

      const diagItems = res.diags
        .map((d) => `<li class="purl-diag-item ${escapeHtml(d.level)}">${escapeHtml(d.text)}</li>`)
        .join("");

      resEl.innerHTML = `
        <div class="purl-string-display" aria-label="规范化结构解剖">${segHtml}</div>
        <div class="purl-output-grid">
          <div class="purl-out-box highlight">
            <div class="purl-out-label">Canonical PURL（规范完整标识）${res.changed ? " · 已修正差异" : " · 已规范"}</div>
            <div class="purl-out-val">${escapeHtml(res.canonical)}</div>
          </div>
          <div class="purl-out-box">
            <div class="purl-out-label">Base PURL（L2/L3 倒排索引前缀键）</div>
            <div class="purl-out-val">${escapeHtml(res.basePurl)}</div>
          </div>
          <div class="purl-out-box">
            <div class="purl-out-label">L3 Match Key（保留匹配语义限定符，剥离下载源/子路径）</div>
            <div class="purl-out-val">${escapeHtml(res.matchKey)}</div>
          </div>
          <div class="purl-out-box">
            <div class="purl-out-label">结构化拆解字段</div>
            <div class="purl-out-val">type=<strong>${escapeHtml(p.type)}</strong> | ns=${escapeHtml(p.namespace || "∅")} | name=<strong>${escapeHtml(p.name)}</strong> | ver=${escapeHtml(p.version || "∅")}</div>
          </div>
        </div>
        <ul class="purl-diag-list">${diagItems}</ul>
      `;
    }

    function renderShell() {
      const presetBtns = presets
        .map(
          (pr, idx) =>
            `<button type="button" class="purl-preset-btn ${idx === state.activePreset ? "active" : ""}" data-pidx="${idx}">${escapeHtml(pr.label)}</button>`
        )
        .join("");

      container.innerHTML = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "ECMA-427 PURL 规范化与解剖实验台")}</h3>
          <div class="widget-status">实时解析 · 检验多工具归一化一致性</div>
        </div>
        ${config.intro ? `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(config.intro)}</p>` : ""}
        <div class="purl-presets">${presetBtns}</div>
        <div class="purl-input-wrap">
          <input type="text" class="purl-input" data-role="purl-input" value="${escapeHtml(state.input)}" placeholder="输入任意 PURL，例如 pkg:pypi/Django_Rest@3.14.0" spellcheck="false" />
        </div>
        <div data-role="purl-result"></div>
      `;

      const inputEl = container.querySelector('[data-role="purl-input"]');
      const resEl = container.querySelector('[data-role="purl-result"]');

      renderResultOnly(resEl);

      inputEl.addEventListener("input", () => {
        state.input = inputEl.value;
        state.activePreset = -1;
        container.querySelectorAll(".purl-preset-btn").forEach((b) => b.classList.remove("active"));
        renderResultOnly(resEl);
      });

      container.querySelectorAll(".purl-preset-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const idx = Number(btn.dataset.pidx);
          state.activePreset = idx;
          state.input = presets[idx].purl;
          inputEl.value = state.input;
          container.querySelectorAll(".purl-preset-btn").forEach((b, i) => b.classList.toggle("active", i === idx));
          renderResultOnly(resEl);
        });
      });
    }

    renderShell();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="purl-lab"]').forEach(initPurlLab);
  });
})();
