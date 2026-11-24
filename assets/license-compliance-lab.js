/* ==========================================================================
   Reusable Interactive Component: SPDX AST & License Contagion Reasoner Lab
   Zero-dependency vanilla JS for Lesson 0010+.
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

  /* ------------------------------------------------------------------------
     1. License Knowledge Base & Exception Semantics
     ------------------------------------------------------------------------ */
  const LICENSES = {
    "MIT": {
      tier: "Permissive",
      rank: 0,
      noticeRequired: true,
      patentClause: false,
      note: "极低风险宽松许可：保留版权声明与 MIT 许可全文即可商业闭源交付。",
    },
    "BSD-2-Clause": {
      tier: "Permissive",
      rank: 0,
      noticeRequired: true,
      patentClause: false,
      note: "宽松许可：二进制与源码分发均须保留版权与免责声明。",
    },
    "BSD-3-Clause": {
      tier: "Permissive",
      rank: 0,
      noticeRequired: true,
      patentClause: false,
      note: "宽松许可：含禁止未经授权使用贡献者名称背书条款；商业闭源友好。",
    },
    "ISC": {
      tier: "Permissive",
      rank: 0,
      noticeRequired: true,
      patentClause: false,
      note: "与简化 BSD/MIT 等价的宽松许可。",
    },
    "0BSD": {
      tier: "Permissive",
      rank: 0,
      noticeRequired: false,
      patentClause: false,
      note: "零条件类公有领域宽松许可，无需强制随二进制附带声明。",
    },
    "Apache-2.0": {
      tier: "Permissive + Patent",
      rank: 1,
      noticeRequired: true,
      patentClause: true,
      requiresUpstreamNoticeFile: true,
      gpl2Incompatible: true,
      note: "商业极友好，含明确专利授权与专利报复条款；须透传上游 NOTICE 文件，且与 GPL-2.0-only 互不兼容。",
    },
    "MPL-2.0": {
      tier: "Weak Copyleft (File)",
      rank: 2,
      fileCopyleft: true,
      noticeRequired: true,
      note: "文件级弱传染：仅对修改或扩充的 MPL-2.0 源码文件要求继续以 MPL-2.0 开源，可与其他闭源/商业文件合法静态或动态混合编译。",
    },
    "EPL-2.0": {
      tier: "Weak Copyleft (File/Module)",
      rank: 2,
      fileCopyleft: true,
      noticeRequired: true,
      gpl2Incompatible: true,
      note: "Eclipse 文件级弱传染：独立商业模块通过接口调用通常不触发传染，修改 EPL 文件本身须回馈源码；与 GPL-2.0 互不兼容（除非双许可带 Classpath）。",
    },
    "CDDL-1.0": {
      tier: "Weak Copyleft (File)",
      rank: 2,
      fileCopyleft: true,
      noticeRequired: true,
      gpl2Incompatible: true,
      note: "文件级弱传染；注意与 GPL-2.0-only 互不兼容。",
    },
    "LGPL-2.1-only": {
      tier: "Weak Copyleft (Library)",
      rank: 3,
      libraryCopyleft: true,
      noticeRequired: true,
      gpl2Upgradeable: false,
      note: "库级弱传染（§6）：动态链接可与闭源主程序共存；若静态链接（如 Go/Rust/Webpack 打包），须向用户提供闭源部分的目标文件(.o)以支持重链接！",
    },
    "LGPL-2.1-or-later": {
      tier: "Weak Copyleft (Library)",
      rank: 3,
      libraryCopyleft: true,
      noticeRequired: true,
      note: "库级弱传染：动态链接安全；静态链接仍触发目标文件重链接义务。",
    },
    "LGPL-3.0-only": {
      tier: "Weak Copyleft (Library)",
      rank: 3,
      libraryCopyleft: true,
      noticeRequired: true,
      gpl2Incompatible: true,
      note: "库级弱传染（§4(d)）：静态链接且不可替换时须提供重链接目标文件与安装信息；含反 Tivoization 硬件约束。",
    },
    "LGPL-3.0-or-later": {
      tier: "Weak Copyleft (Library)",
      rank: 3,
      libraryCopyleft: true,
      noticeRequired: true,
      gpl2Incompatible: true,
      note: "同 LGPL-3.0-only：静态链接触发重链接义务。",
    },
    "GPL-2.0-only": {
      tier: "Strong Copyleft",
      rank: 4,
      strongCopyleft: true,
      noticeRequired: true,
      note: "强传染（Copyleft）：同一进程静态或动态链接即触发整体衍生作品义务，分发时须全部以 GPL-2.0 开源（除非带有 WITH Classpath-exception-2.0 等链接例外）。",
    },
    "GPL-2.0-or-later": {
      tier: "Strong Copyleft",
      rank: 4,
      strongCopyleft: true,
      orLater: true,
      noticeRequired: true,
      note: "强传染且允许按 GPL-3.0 条款升级重新分发（可因此兼容 Apache-2.0）。",
    },
    "GPL-3.0-only": {
      tier: "Strong Copyleft",
      rank: 4,
      strongCopyleft: true,
      noticeRequired: true,
      note: "强传染且附带反 Tivoization / 专利条款；分发性商业闭源禁止链接（除非存在 WITH 例外或独立进程隔离）。",
    },
    "GPL-3.0-or-later": {
      tier: "Strong Copyleft",
      rank: 4,
      strongCopyleft: true,
      orLater: true,
      noticeRequired: true,
      note: "强传染；可通过 §13 与 AGPL-3.0 联合组合成整体 AGPL-3.0 作品。",
    },
    "AGPL-3.0-only": {
      tier: "Network Copyleft (§13)",
      rank: 5,
      networkCopyleft: true,
      strongCopyleft: true,
      noticeRequired: true,
      note: "网络强传染（§13）：即使不对外分发二进制、仅在云端 SaaS 提供网络交互服务，修改或链接后的整体网络服务源码也必须向交互用户提供！",
    },
    "AGPL-3.0-or-later": {
      tier: "Network Copyleft (§13)",
      rank: 5,
      networkCopyleft: true,
      strongCopyleft: true,
      orLater: true,
      noticeRequired: true,
      note: "网络强传染（§13）：SaaS 场景照样触发明示源码下载义务。",
    },
    "SSPL-1.0": {
      tier: "Non-OSI Source-Available",
      rank: 5,
      nonOsiRestricted: true,
      networkCopyleft: true,
      noticeRequired: true,
      note: "非 OSI 认证（MongoDB SSPL §13）：若作为服务对外提供，须将支撑该服务的全栈管理/编排软件全部按 SSPL 开源，绝大多数企业法务一票否决。",
    },
    "BSL-1.1": {
      tier: "Non-OSI Source-Available",
      rank: 5,
      nonOsiRestricted: true,
      noticeRequired: true,
      note: "Business Source License：非开源许可，通常禁止将其直接包装为竞品商业生产服务（直到约定 Change Date 才转为开源）。",
    },
    "Elastic-2.0": {
      tier: "Non-OSI Source-Available",
      rank: 5,
      nonOsiRestricted: true,
      noticeRequired: true,
      note: "Elastic License 2.0：禁止将软件作为托管服务（Managed Service）向第三方商业提供。",
    },
    "CC-BY-NC-4.0": {
      tier: "Non-Commercial Data/Content",
      rank: 5,
      nonOsiRestricted: true,
      noticeRequired: true,
      note: "明确禁止任何商业用途（Non-Commercial），严禁集成入商业闭源产品或 SaaS。",
    },
    "CC-BY-NC-ND-4.0": {
      tier: "Non-Commercial & No-Deriv",
      rank: 5,
      nonOsiRestricted: true,
      noticeRequired: true,
      note: "禁止商业用途且禁止衍生改编，商业闭源绝对红线。",
    },
  };

  const LINKING_EXCEPTIONS = {
    "Classpath-exception-2.0": "免除将库与独立模块组合/链接时的 GPL 传染要求，仅对修改该库本身保留 Copyleft（典型：OpenJDK / Jakarta EE）。",
    "GCC-exception-3.1": "GCC 运行时库例外：允许用 GCC 编译生成闭源商业目标文件，不因链接 libgcc 触发 GPL-3.0 传染。",
    "LLVM-exception": "Apache-2.0 WITH LLVM-exception：免除在特定运行时链接场景下的二进制 NOTICE 附带冲突，增强与 GPL-2.0 软件的兼容桥接能力。",
    "Autoconf-exception-2.0": "允许基于 Autoconf 生成的 configure 脚本在非 GPL 项目中自由分发。",
  };

  const PRESETS = [
    {
      id: "precedence-trap",
      label: "1. 优先级暗坑：LGPL-2.1-only OR BSD-3-Clause AND MIT",
      expr: "LGPL-2.1-only OR BSD-3-Clause AND MIT",
      distribution: "binary",
      linking: "static",
      scope: "runtime",
    },
    {
      id: "with-classpath",
      label: "2. WITH 例外消解：GPL-2.0-only WITH Classpath-exception-2.0",
      expr: "GPL-2.0-only WITH Classpath-exception-2.0",
      distribution: "binary",
      linking: "static",
      scope: "runtime",
    },
    {
      id: "apache-gpl2-conflict",
      label: "3. 双向互斥冲突：Apache-2.0 AND GPL-2.0-only",
      expr: "Apache-2.0 AND GPL-2.0-only",
      distribution: "oss_gpl2",
      linking: "static",
      scope: "runtime",
    },
    {
      id: "jakarta-dual",
      label: "4. 复杂组合：EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0",
      expr: "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0",
      distribution: "binary",
      linking: "dynamic",
      scope: "runtime",
    },
    {
      id: "lgpl-static-go",
      label: "5. 静态链接雷区：LGPL-3.0-only (Go/Rust 单文件)",
      expr: "LGPL-3.0-only",
      distribution: "binary",
      linking: "static",
      scope: "runtime",
    },
    {
      id: "agpl-saas",
      label: "6. SaaS 网络传染：AGPL-3.0-only",
      expr: "AGPL-3.0-only",
      distribution: "saas",
      linking: "dynamic",
      scope: "runtime",
    },
  ];

  const DRIFT_CASES = [
    {
      id: "manifest-lie",
      label: "1. Manifest 谎报 (MIT vs 夹带 GPL-2.0-only)",
      pkg: "pkg:npm/fast-media-helper@1.4.2",
      declared: "MIT (package.json)",
      observed: "MIT (LICENSE) + GPL-2.0-only (src/native/codec_fft.c 文件头)",
      concluded: "MIT AND GPL-2.0-only",
      severity: "danger",
      badgeText: "Observed 纠偏阻断",
      steps: [
        { cls: "warn", title: "Tier 1 快扫误判风险", detail: "若只信 package.json 的 declared: MIT，合规引擎会误放行进入闭源安装包。" },
        { cls: "bad", title: "Tier 2 文件级扫描（ScanCode / licensecheck）", detail: "异步深度扫描发现 C 扩展源码头部声明 GPL-2.0-only，属于典型上游“抄代码忘报”漂移。" },
        { cls: "ok", title: "生成 Concluded 与 PR 门禁动作", detail: "IR 保留 declared=MIT 与 evidence.licenses，同时落库 concluded=MIT AND GPL-2.0-only 并触发商业发布阻断。" },
      ],
    },
    {
      id: "apache-notice-missing",
      label: "2. Apache-2.0 NOTICE 缺失违约",
      pkg: "pkg:maven/org.example/cloud-sdk@2.1.0",
      declared: "Apache-2.0 (pom.xml)",
      observed: "Apache-2.0 (META-INF/LICENSE.txt) + 上游版权清单 (META-INF/NOTICE.txt)",
      concluded: "Apache-2.0",
      severity: "warn",
      badgeText: "Notice 交付不完整",
      steps: [
        { cls: "ok", title: "许可兼容通过", detail: "Apache-2.0 允许商业闭源静态/动态打包分发。" },
        { cls: "bad", title: "常见工程漏项（Apache-2.0 §4(d)）", detail: "许多简易脚本只拷贝了通用 Apache-2.0 文本，却漏掉了 JAR 包内的 META-INF/NOTICE.txt（上游原作者的归属与致谢声明）。" },
        { cls: "ok", title: "合规引擎自动化修复", detail: "Layer 1/3 提取阶段自动抓取压缩包内 NOTICE* 文件指纹入库，在生成 THIRD-PARTY-NOTICES 时原样透传。" },
      ],
    },
    {
      id: "noassertion-curation",
      label: "3. NOASSERTION / 非标声明靠 ClearlyDefined 救回",
      pkg: "pkg:pypi/legacy-xml-parser@0.9.8",
      declared: "NOASSERTION (METADATA 写了 'See LICENSE file')",
      observed: "ClearlyDefined (CC0-1.0 库) 人工审校 + google/licensecheck LRE 99.4% 匹配 BSD-3-Clause",
      concluded: "BSD-3-Clause",
      severity: "ok",
      badgeText: "自动富化收口",
      steps: [
        { cls: "warn", title: "原始声明不可机器求值", detail: "大量老 PyPI/NPM 包只写了非标准字符串，简单正则引擎只能报 UNKNOWN 造成大量人工工单。" },
        { cls: "ok", title: "ClearlyDefined (CC0-1.0) + 本地 LRE 识别", detail: "优先查询 CC0 协议的 ClearlyDefined 社区校准数据，并由纯 Go google/licensecheck 验证包内 LICENSE 文件。" },
        { cls: "ok", title: "Curation 规则库沉淀", detail: "确认无误后在自研 curations.yml 为该 PURL 绑定 concluded=BSD-3-Clause 并附带证据出处（citations）。" },
      ],
    },
    {
      id: "or-notice-pruning",
      label: "4. OR 双许可 Notice 精确裁剪 (MIT OR Apache-2.0)",
      pkg: "pkg:cargo/serde_json@1.0.132",
      declared: "MIT OR Apache-2.0 (Cargo.toml)",
      observed: "MIT + Apache-2.0",
      concluded: "MIT (Policy Elected from MIT OR Apache-2.0)",
      severity: "ok",
      badgeText: "最优分支裁剪",
      steps: [
        { cls: "ok", title: "Rust 生态典型双许可", detail: "Cargo 生态绝大多数核心包以 MIT OR Apache-2.0 发布。" },
        { cls: "ok", title: "策略择优选择 MIT 分支", detail: "针对商业闭源场景，策略引擎在 AST OR 节点上显式选定 MIT 分支（避免额外引入 Apache 专利报复条款与冗长 NOTICE）。" },
        { cls: "ok", title: "下游 Notice 与 CycloneDX 投影", detail: "仅向 THIRD-PARTY-NOTICES 输出 MIT 版权与全文，并在 CycloneDX 1.7 保留 declared 原始表达式与 concluded 选定结论。" },
      ],
    },
  ];

  const ENGINE_BENCHMARKS = [
    {
      id: "go-spdx",
      name: "github/go-spdx & spdx/tools-golang",
      codeLicense: "MIT / Apache-2.0",
      dataLicense: "SPDX License List (CC0-1.0)",
      role: "Go Core 内核 · SPDX 语法树解析与 ID 校验",
      verdictClass: "badge-ok",
      verdictText: "强烈推荐 · 零传染嵌入",
      details: "纯 Go 零 CGO，毫秒级解析复杂 AND/OR/WITH 表达式并校验官方 SPDX 标识合法性，适合直接内置于 Single Go Core 本地 MCP 与云端策略引擎。",
    },
    {
      id: "licensecheck",
      name: "google/licensecheck",
      codeLicense: "BSD-3-Clause",
      dataLicense: "内置 LRE 正则规则（BSD-3-Clause）",
      role: "Go Core 内核 · 亚毫秒级 LICENSE 文件文本识别",
      verdictClass: "badge-ok",
      verdictText: "强烈推荐 · Go 原生快扫",
      details: "Google 开源的纯 Go 许可证文本分类器（基于 LRE 规则），覆盖主流 SPDX 协议与百分比覆盖率评分，可直接嵌入式运行而不必拉起 Python 进程。",
    },
    {
      id: "clearlydefined-osadl",
      name: "ClearlyDefined & OSADL Compatibility Matrix",
      codeLicense: "MIT (ClearlyDefined)",
      dataLicense: "ClearlyDefined: CC0-1.0 ｜ OSADL Matrix: CC-BY-4.0",
      role: "知识底座 · 社区校准真值 + 协议兼容性矩阵",
      verdictClass: "badge-ok",
      verdictText: "商用合规 · 需履行 OSADL 署名",
      details: "ClearlyDefined 社区校准数据采用 CC0-1.0（零署名门槛）用于救回 NOASSERTION 组件；OSADL 官方机器可读兼容性矩阵 JSON/CSV 为 CC-BY-4.0，商业集成须保留 OSADL 署名。",
    },
    {
      id: "scancode-ort",
      name: "ScanCode-Toolkit & OSS Review Toolkit (ORT)",
      codeLicense: "Apache-2.0（代码全部安全）",
      dataLicense: "ScanCode LicenseDB: CC-BY-4.0",
      role: "Tier 2 深度容器 · 逐文件源码/版权扫描与 Notice 工程化",
      verdictClass: "badge-ok",
      verdictText: "异步容器封装 · 注意 CC-BY 署名",
      details: "ScanCode-Toolkit（Python）提供业界最高精度逐文件版权/许可证扫描（LicenseDB 为 CC-BY-4.0 需署名）；ORT（Kotlin）提供 Evaluator、curations.yml 与 PlainTextTemplate Notice 生成蓝本，两者均建议通过独立 Worker 容器/子进程异步调度。",
    },
    {
      id: "fossology",
      name: "FOSSology (Linux Foundation)",
      codeLicense: "GPL-2.0-only（代码强传染！）",
      dataLicense: "GPL-2.0-only",
      role: "传统开源许可证工作台（Nomos / Monk）",
      verdictClass: "badge-danger",
      verdictText: "商业闭源红线 · 严禁嵌入主产品",
      details: "虽然在纯开源治理圈名气极大，但其本体代码为强传染 GPL-2.0-only（且恰好与 Apache-2.0 互不兼容！）。商业闭源 SCA 产品严禁将其代码库嵌入或与闭源核心耦合发布。",
    },
  ];

  /* ------------------------------------------------------------------------
     2. Recursive-Descent SPDX License Expression Parser
     Precedence (SPDX v3.0.1 Annex B): +  >  WITH  >  AND  >  OR
     ------------------------------------------------------------------------ */
  function tokenizeSpdx(input) {
    const tokens = [];
    const warnings = [];
    let i = 0;
    const s = String(input || "").trim();

    while (i < s.length) {
      const ch = s[i];
      if (/\s/.test(ch)) {
        i++;
        continue;
      }
      if (ch === "(") {
        tokens.push({ type: "LPAREN", val: "(" });
        i++;
        continue;
      }
      if (ch === ")") {
        tokens.push({ type: "RPAREN", val: ")" });
        i++;
        continue;
      }
      let j = i;
      while (j < s.length && !/[\s()]/.test(s[j])) {
        j++;
      }
      const raw = s.slice(i, j);
      if (raw === "AND" || raw === "OR" || raw === "WITH") {
        tokens.push({ type: raw, val: raw });
      } else if (/^(and|or|with)$/i.test(raw)) {
        warnings.push(`SPDX 规范强制运算符全大写（检测到 "${raw}"，已按 "${raw.toUpperCase()}" 容错解析并建议规范化）。`);
        tokens.push({ type: raw.toUpperCase(), val: raw.toUpperCase() });
      } else {
        tokens.push({ type: "ID", val: raw });
      }
      i = j;
    }
    return { tokens, warnings };
  }

  function parseSpdxExpression(input) {
    const { tokens, warnings } = tokenizeSpdx(input);
    if (tokens.length === 0) {
      return { ast: null, error: "请输入有效的 SPDX 许可证表达式（如 MIT OR Apache-2.0）。", warnings };
    }
    let pos = 0;

    function peek() {
      return tokens[pos] || null;
    }

    function consume() {
      return tokens[pos++];
    }

    function parseOr() {
      let left = parseAnd();
      while (peek() && peek().type === "OR") {
        consume();
        const right = parseAnd();
        left = { type: "OR", left, right };
      }
      return left;
    }

    function parseAnd() {
      let left = parseWith();
      while (peek() && peek().type === "AND") {
        consume();
        const right = parseWith();
        left = { type: "AND", left, right };
      }
      return left;
    }

    function parseWith() {
      const base = parseAtom();
      if (peek() && peek().type === "WITH") {
        consume();
        const excTok = peek();
        if (!excTok || excTok.type !== "ID") {
          throw new Error("WITH 运算符右侧必须紧跟合法的 Exception ID（例如 Classpath-exception-2.0）。");
        }
        consume();
        if (base.type !== "LICENSE") {
          throw new Error("SPDX 规范规定 WITH 只能直接修饰单个简单许可证标识，不能跨括号修饰复合表达式。");
        }
        return { type: "WITH", base, exception: excTok.val };
      }
      return base;
    }

    function parseAtom() {
      const tok = peek();
      if (!tok) {
        throw new Error("表达式意外结束，缺少许可证标识或右括号。");
      }
      if (tok.type === "LPAREN") {
        consume();
        const expr = parseOr();
        const close = peek();
        if (!close || close.type !== "RPAREN") {
          throw new Error("括号未闭合：缺少右括号 ')'。");
        }
        consume();
        return expr;
      }
      if (tok.type === "ID") {
        consume();
        let rawId = tok.val;
        let orLater = false;
        if (rawId.endsWith("+")) {
          orLater = true;
          rawId = rawId.slice(0, -1);
          warnings.push(`检测到旧版 "+" 后缀（${tok.val}）：SPDX 3.0 推荐归一化为显式 "-or-later" 标识。`);
        }
        return { type: "LICENSE", id: rawId, orLater };
      }
      throw new Error(`意外的符号 "${tok.val}"，此处期望许可证 ID 或 "("。`);
    }

    try {
      const ast = parseOr();
      if (pos < tokens.length) {
        throw new Error(`存在无法消费的多余符号 "${tokens[pos].val}"（请检查是否遗漏 AND/OR 或括号不匹配）。`);
      }
      return { ast, error: null, warnings };
    } catch (err) {
      return { ast: null, error: err.message || "语法解析失败", warnings };
    }
  }

  function formatNormalized(node, parentPrec = 0) {
    if (!node) return "";
    if (node.type === "LICENSE") {
      return node.orLater ? `${node.id}+` : node.id;
    }
    if (node.type === "WITH") {
      return `${formatNormalized(node.base, 3)} WITH ${node.exception}`;
    }
    if (node.type === "AND") {
      const s = `${formatNormalized(node.left, 2)} AND ${formatNormalized(node.right, 2)}`;
      return parentPrec > 2 ? `(${s})` : s;
    }
    if (node.type === "OR") {
      const s = `${formatNormalized(node.left, 1)} OR ${formatNormalized(node.right, 1)}`;
      return parentPrec > 1 ? `(${s})` : s;
    }
    return "";
  }

  /* ------------------------------------------------------------------------
     3. 3D Context Contagion & Compatibility Evaluator
     ------------------------------------------------------------------------ */
  function resolveLicenseInfo(id, orLater) {
    if (id === "NOASSERTION" || id === "NONE") {
      return {
        id,
        tier: "Missing / Unverified",
        rank: 3,
        isSpecial: true,
        note: "未声明有效许可，必须送入 Tier 2 ScanCode 文件级扫描或 ClearlyDefined 校准。",
      };
    }
    if (id.startsWith("LicenseRef-") || id.startsWith("DocumentRef-")) {
      return {
        id,
        tier: "Custom LicenseRef",
        rank: 3,
        isCustom: true,
        note: "自定义或专有许可引用（LicenseRef），无法自动推断传染性，须由法务规则库显式映射。",
      };
    }
    const exact = LICENSES[id];
    if (exact) {
      return Object.assign({ id, orLater: Boolean(orLater || exact.orLater) }, exact);
    }
    // Check if -or-later or + variant
    if (orLater && LICENSES[`${id}-or-later`]) {
      return Object.assign({ id: `${id}-or-later`, orLater: true }, LICENSES[`${id}-or-later`]);
    }
    if (orLater && LICENSES[`${id}-only`]) {
      return Object.assign({ id: `${id}+`, orLater: true }, LICENSES[`${id}-only`]);
    }
    return {
      id,
      tier: "Unknown SPDX ID",
      rank: 3,
      isUnknown: true,
      note: "未收录进内置轻量白名单的 SPDX ID，自动转入策略人工复核队列。",
    };
  }

  function evaluateLeaf(id, exception, orLater, ctx) {
    const info = resolveLicenseInfo(id, orLater);
    const obligations = [];
    const reasons = [];
    let status = "PASS"; // PASS | WARN | BLOCK
    let effectiveRank = info.rank;

    if (info.isSpecial || info.isCustom || info.isUnknown) {
      status = "WARN";
      obligations.push(`人工/Tier 2 核验 ${id} 真实文本与权利边界`);
      reasons.push(`${id}：${info.note}`);
      return {
        status,
        score: 50,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: exception ? `${id} WITH ${exception}` : id,
      };
    }

    // 1. Scope pruning: dev / test / build-tool
    if (ctx.scope === "dev") {
      if (info.nonOsiRestricted) {
        status = "WARN";
        obligations.push(`复核 ${id} 是否限制企业内部商业研发用途（如 CC-BY-NC）`);
        reasons.push(`虽为 dev/test 构建期依赖（不随制品分发），但 ${id} 属于非 OSI 限制条款，需确认允许企业内部使用。`);
      } else {
        status = "PASS";
        reasons.push(`Scope = dev/test（仅开发构建期使用，不进入最终分发二进制/镜像），${id} 的分发传染条款被安全剪枝。`);
      }
      return {
        status,
        score: status === "PASS" ? 0 : 40,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: exception ? `${id} WITH ${exception}` : id,
      };
    }

    // 2. Non-OSI restricted licenses
    if (info.nonOsiRestricted) {
      status = "BLOCK";
      obligations.push(`禁止将 ${id} 组件合入商业产品/托管服务，需替换开源替代品或采购商业授权`);
      reasons.push(`${id}（${info.tier}）：${info.note}`);
      return {
        status,
        score: 100,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: id,
      };
    }

    // 3. Network Copyleft (AGPL-3.0)
    if (info.networkCopyleft) {
      if (ctx.linking === "ipc") {
        status = "WARN";
        obligations.push(`保持 ${id} 作为独立微服务的完整网络源码披露入口，并严禁闭源核心与之同进程耦合`);
        reasons.push(`${id} 在独立进程（IPC/HTTP）边界下可尝试隔离，但服务端本身一旦被外部用户通过网络交互仍须按 AGPL §13 提供对应服务源码。`);
      } else {
        status = "BLOCK";
        obligations.push(`触发 AGPL-3.0 §13 网络交互传染：${ctx.distribution === "saas" ? "即便仅在云端 SaaS 运行不分发二进制" : "商业分发"}也必须开放整体链接软件源码`);
        reasons.push(`命中 AGPL-3.0 §13 红线：云端 SaaS 不能豁免 AGPL 网络传染，与闭源商业交付完全互斥。`);
      }
      return {
        status,
        score: status === "BLOCK" ? 95 : 55,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: id,
      };
    }

    // 4. Strong Copyleft (GPL) + WITH Exception check
    if (info.strongCopyleft) {
      if (exception && LINKING_EXCEPTIONS[exception] && ctx.linking !== "modified") {
        status = "PASS";
        effectiveRank = 1;
        obligations.push(`保留 ${id} WITH ${exception} 原版权声明；严禁直接修改该受例外保护库自身源码`);
        reasons.push(`WITH 例外生效：${exception} 显式免除链接传染（${LINKING_EXCEPTIONS[exception]}）。`);
      } else if (ctx.distribution === "saas") {
        status = "PASS";
        obligations.push(`保留内部合规台账（当前仅云端 SaaS 运行未对外分发二进制，不触发 GPL-2/3 分发传染；若未来私有化交付将立即升级为 BLOCK！）`);
        reasons.push(`Distribution = SaaS_ONLY：传统 GPLv2/v3 的 Copyleft 义务以“对外分发（Distribute/Convey）”为前提，纯后端自研运行暂不触发；但一旦出私有化一体机或二进制 SDK 立即变红。`);
      } else if (ctx.linking === "ipc") {
        status = "WARN";
        obligations.push(`确保进程边界完全独立（命令行/Socket 调用且不共享专有数据结构），并单独随包提供该 GPL 组件源码`);
        reasons.push(`Linking = IPC 独立进程：按 FSF 聚合（Aggregate）而非衍生作品原则通常不传染主程序，但须严格审计进程边界与命令行耦合度。`);
      } else if (ctx.distribution === "oss_gpl2" && (id === "GPL-2.0-only" || id === "GPL-2.0-or-later")) {
        status = "PASS";
        obligations.push(`按 GPL-2.0 整体开源对外发布对应源码与构建脚本`);
        reasons.push(`出站产品本身即以 GPL-2.0 开源发布，与入站 ${id} 兼容。`);
      } else {
        status = "BLOCK";
        obligations.push(`商业闭源/不兼容分发禁止静态或动态链接 ${id}${ctx.linking === "modified" ? "（且修改源码会使链接例外失效）" : ""}，须替换或拆出独立进程`);
        reasons.push(`${id} 在「${ctx.distribution === "binary" ? "商业闭源分发" : "不兼容出站许可"} + ${ctx.linking}」下触发强传染红线：整个链接作品必须全部开源。`);
      }
      return {
        status,
        score: status === "BLOCK" ? 90 : status === "WARN" ? 45 : 10 + effectiveRank,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: exception ? `${id} WITH ${exception}` : id,
      };
    }

    // 5. Library Weak Copyleft (LGPL)
    if (info.libraryCopyleft) {
      if (ctx.distribution === "saas" || ctx.linking === "ipc") {
        status = "PASS";
        obligations.push(`保留 ${id} 版权声明与源码出处链接`);
        reasons.push(`${ctx.distribution === "saas" ? "纯云端 SaaS 不触发分发义务" : "IPC 独立进程隔离不构成链接衍生"}，安全放行。`);
      } else if (ctx.linking === "dynamic") {
        status = "WARN";
        obligations.push(`确保用户可自由替换该动态链接库（.so/.dll/.jar），随发行包附带 ${id} 全文与源码获取书面要约（Written Offer）`);
        reasons.push(`动态链接 ${id} 商业闭源可用，但须满足库可替换性与源码附带/书面要约合规义务。`);
      } else if (ctx.linking === "static") {
        status = "BLOCK";
        obligations.push(`静态链接（含 Go/Rust/Webpack 单包）触发 ${id} 重链接义务：须向客户交付闭源程序目标文件(.o/.a)或改用动态链接/替代包！`);
        reasons.push(`常见工程暗坑：在 Go/Rust 单文件或静态编译二进制中引入 ${id}，无法满足库替换条件，默认拦截（除非产品法务明确接受交付重链接目标文件）。`);
      } else {
        // modified
        status = "BLOCK";
        obligations.push(`修改了 ${id} 库自身源码，须将修改后的库源码以 ${id} 开源并提供重链接支持`);
        reasons.push(`修改 LGPL 库自身源码必须回馈该库的完整修改源码。`);
      }
      return {
        status,
        score: status === "BLOCK" ? 80 : status === "WARN" ? 35 : 8,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: id,
      };
    }

    // 6. File Weak Copyleft (MPL-2.0 / EPL-2.0 / CDDL-1.0)
    if (info.fileCopyleft) {
      if (ctx.linking === "modified") {
        status = "WARN";
        obligations.push(`将对 ${id} 原文件所做的修改以 ${id} 单独发布源码，其余商业闭源独立文件不受传染`);
        reasons.push(`文件级弱传染（${id}）：仅需开源你修改的那几个源文件，商业闭源核心逻辑安全隔离。`);
      } else {
        status = "PASS";
        obligations.push(`保留 ${id} 许可文本、版权声明及原始源码获取链接（Notice）；EPL/CDDL 注意勿与 GPL-2.0-only 混编`);
        reasons.push(`文件级弱传染（${id}）：未修改原文件且不与 GPLv2 混编时，可合法用于商业闭源产品或 SaaS。`);
      }
      return {
        status,
        score: status === "WARN" ? 25 : 5,
        obligations,
        reasons,
        leaves: [{ id, exception, orLater, info }],
        electedExpr: id,
      };
    }

    // 7. Permissive (MIT / BSD / Apache-2.0 / ISC / 0BSD)
    if (info.requiresUpstreamNoticeFile) {
      obligations.push(`保留 ${id} 许可全文、所有上游版权行，并强制提取透传包内 NOTICE 文件（Apache-2.0 §4(d)）`);
    } else if (info.noticeRequired) {
      obligations.push(`在 THIRD-PARTY-NOTICES 中保留 ${id} 版权声明与许可文本`);
    }
    reasons.push(`${id} 属于商业友好型宽松许可，在所有分发与链接形态下均不触发源码传染。`);
    return {
      status: "PASS",
      score: info.rank,
      obligations,
      reasons,
      leaves: [{ id, exception, orLater, info }],
      electedExpr: id,
    };
  }

  function checkPairwiseCompatibility(leaves, ctx) {
    const conflicts = [];
    const warnings = [];
    if (ctx.scope === "dev") {
      return { conflicts, warnings };
    }

    // Check outbound GPL-2.0-only distribution vs inbound leaves
    const allItems = leaves.slice();
    if (ctx.distribution === "oss_gpl2") {
      allItems.push({ id: "GPL-2.0-only", exception: null, info: LICENSES["GPL-2.0-only"], isOutbound: true });
    } else if (ctx.distribution === "oss_apache2") {
      allItems.push({ id: "Apache-2.0", exception: null, info: LICENSES["Apache-2.0"], isOutbound: true });
    }

    for (let i = 0; i < allItems.length; i++) {
      for (let j = i + 1; j < allItems.length; j++) {
        const a = allItems[i];
        const b = allItems[j];
        if (a.isOutbound && b.isOutbound) continue;

        const ids = [a.id, b.id];
        const has = (x) => ids.includes(x);
        const other = (x) => (a.id === x ? b : a);

        // 1. Apache-2.0 vs GPL-2.0-only
        if (has("Apache-2.0") && has("GPL-2.0-only")) {
          const gplNode = other("Apache-2.0");
          if (!gplNode.exception) {
            conflicts.push(
              `FSF 双向协议冲突（死锁）：Apache-2.0（含专利报复条款）与 GPL-2.0-only 互不兼容！无法同时满足两者要求（除非改用 GPL-2.0-or-later 升级至 GPL-3.0，或移除其中一方）。`
            );
          }
        }
        // 2. EPL-2.0 / CDDL-1.0 / LGPL-3.0-only vs GPL-2.0-only
        if (has("GPL-2.0-only") && (has("EPL-2.0") || has("CDDL-1.0") || has("LGPL-3.0-only"))) {
          const gplNode = a.id === "GPL-2.0-only" ? a : b;
          if (!gplNode.exception) {
            const partner = a.id === "GPL-2.0-only" ? b.id : a.id;
            conflicts.push(`协议不兼容：${partner} 与 GPL-2.0-only 存在条款冲突，禁止在同一链接作品中通过 AND 合并。`);
          }
        }
        // 3. GPL-2.0-only vs GPL-3.0-only
        if (has("GPL-2.0-only") && (has("GPL-3.0-only") || has("GPL-3.0-or-later"))) {
          conflicts.push(`版本死锁：GPL-2.0-only 与 GPL-3.0 互不兼容（注意必须写成 GPL-2.0-or-later 才允许向上升级兼容 GPLv3）。`);
        }
        // 4. GPL-3.0 + AGPL-3.0 (§13 Bridge)
        if ((has("GPL-3.0-only") || has("GPL-3.0-or-later")) && (has("AGPL-3.0-only") || has("AGPL-3.0-or-later"))) {
          warnings.push(`GPLv3 §13 特别桥接生效：GPL-3.0 与 AGPL-3.0 组合后，整体联合作品按 §13 必须履行 AGPL-3.0 网络源码披露义务。`);
        }
        // 5. Outbound Apache-2.0 pulling in Copyleft
        if ((a.isOutbound && a.id === "Apache-2.0" && (b.info.strongCopyleft || b.info.libraryCopyleft)) ||
            (b.isOutbound && b.id === "Apache-2.0" && (a.info.strongCopyleft || a.info.libraryCopyleft))) {
          const inbound = a.isOutbound ? b : a;
          if (!inbound.exception && ctx.linking !== "ipc") {
            conflicts.push(`出站协议倒挂冲突：对外声明 Apache-2.0 的开源库不可直接静态/动态依赖强/库级传染协议 ${inbound.id}（仅 Apache-2.0 兼容入站单向进 GPL-3.0，反之不成立）。`);
          }
        }
      }
    }
    return { conflicts, warnings };
  }

  function evaluateAst(node, ctx) {
    if (!node) return null;
    if (node.type === "LICENSE") {
      const res = evaluateLeaf(node.id, null, node.orLater, ctx);
      node._eval = res;
      return res;
    }
    if (node.type === "WITH") {
      const res = evaluateLeaf(node.base.id, node.exception, node.base.orLater, ctx);
      node._eval = res;
      return res;
    }
    if (node.type === "OR") {
      const leftRes = evaluateAst(node.left, ctx);
      const rightRes = evaluateAst(node.right, ctx);
      const rankOrder = { PASS: 0, WARN: 1, BLOCK: 2 };
      const lRank = rankOrder[leftRes.status];
      const rRank = rankOrder[rightRes.status];
      const pickLeft = lRank < rRank || (lRank === rRank && leftRes.score <= rightRes.score);
      const chosen = pickLeft ? leftRes : rightRes;
      const pruned = pickLeft ? rightRes : leftRes;
      node.left._branchClass = pickLeft ? "is-elected" : "is-pruned";
      node.right._branchClass = pickLeft ? "is-pruned" : "is-elected";
      node.left._branchTag = pickLeft ? "已选定最优分支" : "已剪枝跳过";
      node.right._branchTag = pickLeft ? "已剪枝跳过" : "已选定最优分支";

      const res = {
        status: chosen.status,
        score: chosen.score,
        obligations: chosen.obligations.slice(),
        reasons: [
          `OR 择优裁决：左支（${leftRes.electedExpr} → ${leftRes.status}）vs 右支（${rightRes.electedExpr} → ${rightRes.status}），策略自动选定风险更低的「${chosen.electedExpr}」并剪枝另一分支（避免扁平字符串误报）。`,
          ...chosen.reasons,
        ],
        leaves: chosen.leaves.slice(),
        electedExpr: chosen.electedExpr,
        prunedExpr: pruned.electedExpr,
      };
      node._eval = res;
      return res;
    }
    if (node.type === "AND") {
      const leftRes = evaluateAst(node.left, ctx);
      const rightRes = evaluateAst(node.right, ctx);
      const allLeaves = [...leftRes.leaves, ...rightRes.leaves];
      const pairCheck = checkPairwiseCompatibility(allLeaves, ctx);

      const rankOrder = { PASS: 0, WARN: 1, BLOCK: 2 };
      let status = rankOrder[leftRes.status] >= rankOrder[rightRes.status] ? leftRes.status : rightRes.status;
      if (pairCheck.conflicts.length > 0) {
        status = "BLOCK";
        node.left._branchClass = "is-conflict";
        node.right._branchClass = "is-conflict";
        node.left._branchTag = "条款冲突";
        node.right._branchTag = "条款冲突";
      } else if (pairCheck.warnings.length > 0 && status === "PASS") {
        status = "WARN";
      }

      const obligations = Array.from(new Set([...leftRes.obligations, ...rightRes.obligations]));
      const reasons = [
        `AND 合取必须同时履行左右两侧所有条款（${leftRes.electedExpr} + ${rightRes.electedExpr}），并执行跨协议双向兼容性校验。`,
        ...pairCheck.conflicts,
        ...pairCheck.warnings,
        ...leftRes.reasons,
        ...rightRes.reasons,
      ];

      const res = {
        status,
        score: Math.max(leftRes.score, rightRes.score) + (pairCheck.conflicts.length > 0 ? 50 : 0),
        obligations,
        reasons: Array.from(new Set(reasons)),
        leaves: allLeaves,
        electedExpr: `${leftRes.electedExpr} AND ${rightRes.electedExpr}`,
      };
      node._eval = res;
      return res;
    }
    return null;
  }

  function renderAstHtml(node, isRoot = true) {
    if (!node) return "";
    const branchCls = !isRoot && node._branchClass ? ` ${node._branchClass}` : "";
    const branchTag = !isRoot && node._branchTag
      ? `<span class="badge ${node._branchClass === "is-elected" ? "badge-ok" : node._branchClass === "is-conflict" ? "badge-danger" : "badge-blue"}">${escapeHtml(node._branchTag)}</span>`
      : "";

    let badge = "";
    if (node.type === "OR") badge = `<span class="lic-ast-op op-or">OR (择优单选)</span>`;
    else if (node.type === "AND") badge = `<span class="lic-ast-op op-and">AND (合取全履约+互斥检查)</span>`;
    else if (node.type === "WITH") badge = `<span class="lic-ast-op op-with">WITH (${escapeHtml(node.base.id)} + ${escapeHtml(node.exception)})</span>`;
    else badge = `<span class="lic-ast-op op-id">${escapeHtml(node.orLater ? node.id + "+" : node.id)}</span>`;

    const verdictBadge = node._eval
      ? `<span class="badge ${node._eval.status === "PASS" ? "badge-ok" : node._eval.status === "WARN" ? "badge-warn" : "badge-danger"}">${node._eval.status}</span>`
      : "";

    let childrenHtml = "";
    if (node.type === "OR" || node.type === "AND") {
      childrenHtml = renderAstHtml(node.left, false) + renderAstHtml(node.right, false);
    }

    const wrapStart = isRoot ? "" : `<div class="lic-ast-branch${branchCls}">`;
    const wrapEnd = isRoot ? "" : `</div>`;

    return `${wrapStart}<div class="lic-ast-node">${badge}${verdictBadge}${branchTag}</div>${childrenHtml}${wrapEnd}`;
  }

  /* ------------------------------------------------------------------------
     4. Widget Initialization
     ------------------------------------------------------------------------ */
  function initLicenseComplianceLab(container) {
    let config = {};
    const dataEl = container.querySelector("script.license-compliance-lab-data");
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        config = {};
      }
    }

    const state = {
      activeTab: "ast",
      presetId: PRESETS[0].id,
      expr: PRESETS[0].expr,
      distribution: PRESETS[0].distribution,
      linking: PRESETS[0].linking,
      scope: PRESETS[0].scope,
      driftId: DRIFT_CASES[0].id,
      engineId: ENGINE_BENCHMARKS[0].id,
    };

    function renderAstTab() {
      const ctx = {
        distribution: state.distribution,
        linking: state.linking,
        scope: state.scope,
      };
      const parsed = parseSpdxExpression(state.expr);
      let evalRes = null;
      let normalizedExpr = "";
      let astHtml = "";

      if (parsed.ast) {
        evalRes = evaluateAst(parsed.ast, ctx);
        // Re-check top-level single/pairwise outbound conflicts even if root is LICENSE/WITH
        const topPair = checkPairwiseCompatibility(evalRes.leaves, ctx);
        if (topPair.conflicts.length > 0) {
          evalRes.status = "BLOCK";
          evalRes.reasons = [...topPair.conflicts, ...evalRes.reasons];
        }
        normalizedExpr = formatNormalized(parsed.ast, 0);
        astHtml = renderAstHtml(parsed.ast, true);
      }

      const statusClass = !evalRes
        ? "badge-danger"
        : evalRes.status === "PASS"
        ? "badge-ok"
        : evalRes.status === "WARN"
        ? "badge-warn"
        : "badge-danger";

      const noticePreview = evalRes
        ? [
            `# THIRD-PARTY-NOTICES (Preview · Concluded: ${evalRes.electedExpr})`,
            `# Context: Distribution=${state.distribution} | Linking=${state.linking} | Scope=${state.scope}`,
            evalRes.status === "BLOCK"
              ? "[GATE BLOCKED] 存在高危传染或双向条款冲突，拒绝打包发布！"
              : state.scope === "dev"
              ? "[PRUNED] 仅用于 dev/test 构建测试，不写入最终产品外部交付 Notice。"
              : evalRes.obligations.map((o, idx) => `${idx + 1}. ${o}`).join("\n"),
          ].join("\n")
        : "表达式存在语法错误，请修正后生成合规交付预览。";

      return `
        <div class="purl-presets">
          ${PRESETS.map(
            (p) =>
              `<button type="button" class="purl-preset-btn ${p.id === state.presetId ? "active" : ""}" data-action="pick-preset" data-id="${escapeHtml(p.id)}">${escapeHtml(p.label)}</button>`
          ).join("")}
        </div>

        <div class="lic-expr-row">
          <input type="text" class="lic-input" data-role="expr-input" value="${escapeHtml(state.expr)}" placeholder="输入任意 SPDX 表达式，如 (Apache-2.0 OR MIT) AND MPL-2.0" aria-label="SPDX 许可证表达式" />
        </div>

        <div class="lic-ctx-grid">
          <div class="ver-field">
            <label for="lic-dist-sel">1. 分发形态 (Distribution)</label>
            <select id="lic-dist-sel" class="ver-select" data-ctx="distribution">
              <option value="binary" ${state.distribution === "binary" ? "selected" : ""}>商业闭源分发 (私有化 / 客户端 / 镜像)</option>
              <option value="saas" ${state.distribution === "saas" ? "selected" : ""}>纯云端 SaaS (不对外交付二进制)</option>
              <option value="oss_apache2" ${state.distribution === "oss_apache2" ? "selected" : ""}>出站开源库 (以 Apache-2.0 发布)</option>
              <option value="oss_gpl2" ${state.distribution === "oss_gpl2" ? "selected" : ""}>出站开源项目 (以 GPL-2.0-only 发布)</option>
            </select>
          </div>

          <div class="ver-field">
            <label for="lic-link-sel">2. 链接与修改方式 (Linking)</label>
            <select id="lic-link-sel" class="ver-select" data-ctx="linking">
              <option value="static" ${state.linking === "static" ? "selected" : ""}>静态链接 / Go·Rust·Webpack 单文件打包</option>
              <option value="dynamic" ${state.linking === "dynamic" ? "selected" : ""}>动态链接 (.so / .dll / 可替换 .jar)</option>
              <option value="ipc" ${state.linking === "ipc" ? "selected" : ""}>独立进程隔离 (CLI / HTTP / gRPC)</option>
              <option value="modified" ${state.linking === "modified" ? "selected" : ""}>修改了该开源组件本身源码</option>
            </select>
          </div>

          <div class="ver-field">
            <label for="lic-scope-sel">3. 依赖作用域 (IR Scope)</label>
            <select id="lic-scope-sel" class="ver-select" data-ctx="scope">
              <option value="runtime" ${state.scope === "runtime" ? "selected" : ""}>runtime / required (随最终制品交付)</option>
              <option value="dev" ${state.scope === "dev" ? "selected" : ""}>dev / test / build-tool (仅构建测试期)</option>
            </select>
          </div>
        </div>

        ${
          parsed.error
            ? `<div class="idx-step-item bad"><strong>SPDX 解析错误：</strong>${escapeHtml(parsed.error)}</div>`
            : `
          <div class="idx-grid-2">
            <div class="idx-card">
              <div class="idx-card-head">
                <span>SPDX 语法树（+ &gt; WITH &gt; AND &gt; OR）</span>
                <span class="badge badge-blue">规范化：${escapeHtml(normalizedExpr)}</span>
              </div>
              <div class="lic-ast-tree">${astHtml}</div>
              ${
                parsed.warnings.length > 0
                  ? `<ul class="idx-step-list">${parsed.warnings.map((w) => `<li class="idx-step-item warn">${escapeHtml(w)}</li>`).join("")}</ul>`
                  : ""
              }
            </div>

            <div class="idx-card">
              <div class="idx-card-head">
                <span>三维传染性裁决与兼容性推理</span>
                <span class="badge ${statusClass}">裁决：${escapeHtml(evalRes.status)}</span>
              </div>
              <div class="idx-metric-row"><span>选定有效路径 (Concluded)</span><span class="idx-metric-val">${escapeHtml(evalRes.electedExpr)}</span></div>
              <ul class="idx-step-list">
                ${evalRes.reasons
                  .map(
                    (r, idx) =>
                      `<li class="idx-step-item ${
                        evalRes.status === "BLOCK" && idx === 0
                          ? "bad"
                          : evalRes.status === "WARN" && idx === 0
                          ? "warn"
                          : "ok"
                      }">${escapeHtml(r)}</li>`
                  )
                  .join("")}
              </ul>
              <pre class="lic-notice-box">${escapeHtml(noticePreview)}</pre>
            </div>
          </div>
        `
        }
      `;
    }

    function renderDriftTab() {
      const drift = DRIFT_CASES.find((d) => d.id === state.driftId) || DRIFT_CASES[0];
      const engine = ENGINE_BENCHMARKS.find((e) => e.id === state.engineId) || ENGINE_BENCHMARKS[0];

      return `
        <div class="idx-grid-2">
          <div>
            <div class="oci-lab-col-head">A. Declared vs Observed 漂移纠偏实景（点击切换）</div>
            <div class="purl-presets">
              ${DRIFT_CASES.map(
                (d) =>
                  `<button type="button" class="purl-preset-btn ${d.id === state.driftId ? "active" : ""}" data-action="pick-drift" data-id="${escapeHtml(d.id)}">${escapeHtml(d.label)}</button>`
              ).join("")}
            </div>
            <div class="idx-card">
              <div class="idx-card-head">
                <span>${escapeHtml(drift.pkg)}</span>
                <span class="badge badge-${drift.severity === "ok" ? "ok" : drift.severity === "warn" ? "warn" : "danger"}">${escapeHtml(drift.badgeText)}</span>
              </div>
              <div class="idx-metric-row"><span>Declared（清单声明）</span><span class="idx-metric-val">${escapeHtml(drift.declared)}</span></div>
              <div class="idx-metric-row"><span>Observed（文件扫描）</span><span class="idx-metric-val">${escapeHtml(drift.observed)}</span></div>
              <div class="idx-metric-row"><span>Concluded（最终裁定）</span><span class="idx-metric-val">${escapeHtml(drift.concluded)}</span></div>
              <ul class="idx-step-list">
                ${drift.steps
                  .map((s) => `<li class="idx-step-item ${escapeHtml(s.cls)}"><strong>${escapeHtml(s.title)}：</strong>${escapeHtml(s.detail)}</li>`)
                  .join("")}
              </ul>
            </div>
          </div>

          <div>
            <div class="oci-lab-col-head">B. 商用闭源许可证底座与数据集许可边界对比</div>
            <div class="purl-presets">
              ${ENGINE_BENCHMARKS.map(
                (e) =>
                  `<button type="button" class="purl-preset-btn ${e.id === state.engineId ? "active" : ""}" data-action="pick-engine" data-id="${escapeHtml(e.id)}">${escapeHtml(e.name)}</button>`
              ).join("")}
            </div>
            <div class="idx-card">
              <div class="idx-card-head">
                <span>${escapeHtml(engine.name)}</span>
                <span class="badge ${escapeHtml(engine.verdictClass)}">${escapeHtml(engine.verdictText)}</span>
              </div>
              <div class="idx-metric-row"><span>程序代码许可</span><span class="idx-metric-val">${escapeHtml(engine.codeLicense)}</span></div>
              <div class="idx-metric-row"><span>规则/知识库数据许可</span><span class="idx-metric-val">${escapeHtml(engine.dataLicense)}</span></div>
              <div class="idx-metric-row"><span>平台架构定位</span><span class="idx-metric-val">${escapeHtml(engine.role)}</span></div>
              <p style="margin:0.65rem 0 0;font-size:0.82rem;color:var(--ink-secondary);line-height:1.58;">
                ${escapeHtml(engine.details)}
              </p>
            </div>
          </div>
        </div>
      `;
    }

    function render() {
      const title = config.title || "交互实验台：SPDX 表达式 AST 求值器与三维传染性推理沙盘";
      const intro =
        config.intro ||
        "切换双工作台：在模式一手动编辑或点选 SPDX 表达式并调节「分发 × 链接 × 作用域」验证 AST 择优与互斥冲突；在模式二对比 Declared/Observed 漂移纠偏与商用合规开源底座。";

      const html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">${state.activeTab === "ast" ? "模式一：SPDX AST 与三维传染推理" : "模式二：漂移审计与开源底座选型"}</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.9rem;">${escapeHtml(intro)}</p>
        <div class="idx-tab-bar">
          <button type="button" class="idx-tab-btn ${state.activeTab === "ast" ? "active" : ""}" data-tab="ast">1. SPDX AST 解析与三维传染性推理</button>
          <button type="button" class="idx-tab-btn ${state.activeTab === "drift" ? "active" : ""}" data-tab="drift">2. Declared/Observed 漂移与商用底座</button>
        </div>
        ${state.activeTab === "ast" ? renderAstTab() : renderDriftTab()}
      `;

      container.innerHTML = html;

      container.querySelectorAll("[data-tab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeTab = btn.dataset.tab;
          render();
        });
      });

      container.querySelectorAll('[data-action="pick-preset"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = PRESETS.find((p) => p.id === btn.dataset.id);
          if (!found) return;
          state.presetId = found.id;
          state.expr = found.expr;
          state.distribution = found.distribution;
          state.linking = found.linking;
          state.scope = found.scope;
          render();
        });
      });

      const exprInput = container.querySelector('[data-role="expr-input"]');
      if (exprInput) {
        exprInput.addEventListener("input", () => {
          state.expr = exprInput.value;
          state.presetId = "";
          const caret = exprInput.selectionStart;
          render();
          const reFocused = container.querySelector('[data-role="expr-input"]');
          if (reFocused) {
            reFocused.focus();
            if (typeof caret === "number") {
              reFocused.setSelectionRange(caret, caret);
            }
          }
        });
      }

      container.querySelectorAll("[data-ctx]").forEach((sel) => {
        sel.addEventListener("change", () => {
          state[sel.dataset.ctx] = sel.value;
          state.presetId = "";
          render();
        });
      });

      container.querySelectorAll('[data-action="pick-drift"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.driftId = btn.dataset.id;
          render();
        });
      });

      container.querySelectorAll('[data-action="pick-engine"]').forEach((btn) => {
        btn.addEventListener("click", () => {
          state.engineId = btn.dataset.id;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="license-compliance-lab"]').forEach(initLicenseComplianceLab);
  });

  // Expose pure parser/evaluator for automated Node verification when loaded under CommonJS/test harnesses
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      parseSpdxExpression,
      formatNormalized,
      evaluateAst,
      checkPairwiseCompatibility,
    };
  }
})();
