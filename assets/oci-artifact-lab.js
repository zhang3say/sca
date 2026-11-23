/* ==========================================================================
   Reusable OCI Layering & Binary Artifact Dissection Lab
   Zero-dependency vanilla JS shared across Layer 1 container/binary lessons.
   Usage:
     <section class="widget-panel" data-widget="oci-artifact-lab">
       <script type="application/json" class="oci-lab-data">{ ... }</script>
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

  const MODES = [
    { id: "naive", label: "反模式 · 粗糙/表层采集（Naive Scan）" },
    { id: "industrial", label: "推荐方案 · 用户态 Squash / 深层段解析" },
  ];

  const DEFAULT_SCENARIOS = [
    {
      id: "oci-whiteout",
      tabLabel: "1. OCI 分层与 Whiteout 遮蔽",
      contextTitle: "多阶段镜像删除文件 (.wh.) 与目录重建 (.wh..wh..opq) 终态裁决",
      inspectTitle: "OCI Layer Tarballs（自底向上 diff_ids）",
      inspectTag: "Image: app:1.4 (4 layers)",
      inspectTree: [
        "Layer 0 (Base Debian 12):",
        "  ├── var/lib/dpkg/status          (libc6@2.36, openssl@3.0.11)",
        "  └── opt/build/legacy-sdk.jar     (log4j-core@2.14.1)",
        "",
        "Layer 1 (Install temp build tools):",
        "  ├── usr/bin/curl",
        "  └── var/lib/dpkg/status          (新增 curl@7.88.1)",
        "",
        "Layer 2 (Purge curl & rebuild /opt/build):",
        "  ├── usr/bin/.wh.curl             [标准 Whiteout: 删除下层文件]",
        "  ├── opt/build/.wh..wh..opq       [Opaque Whiteout: 清空目录全部下层子项]",
        "  ├── opt/build/app.jar            (仅含 log4j-core@2.23.1)",
        "  └── var/lib/dpkg/status          (已移除 curl 条目)"
      ].join("\n"),
      badges: [
        { cls: "del", text: ".wh.curl 删除单文件" },
        { cls: "opq", text: ".wh..wh..opq 清空目录树" },
        { cls: "add", text: "Squashed 终态 = Layer 0..2 叠加" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：逐层独立扫描（AllLayers 无隔离）引爆双幽灵 CVE",
          verdictTitle: "误报已删除的 curl@7.88.1 与已被 opaque 抹除的 log4j@2.14.1",
          summary:
            "若采集器对每个 Layer Tarball 独立解包扫描并取并集，会同时命中 Layer 1 的 curl（第 2 层已 purge）与 Layer 0 的 legacy-sdk.jar（第 2 层被 .wh..wh..opq 整目录覆盖），在生产容器未运行任何脆弱代码时触发 P0 阻断！",
          irSnippet: [
            "// 错误：未构建 Squash 虚拟文件系统树直接逐层并集",
            '"active_components": [',
            '  "pkg:deb/debian/curl@7.88.1",             // ❌ .wh.curl 已删除',
            '  "pkg:maven/.../log4j-core@2.14.1",        // ❌ .wh..wh..opq 已屏蔽',
            '  "pkg:maven/.../log4j-core@2.23.1"',
            "]"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：Stereoscope 用户态 VFS 合成（SquashedScope）",
          verdictTitle: "运行态仅输出最终生效资产；历史残留降级写入审计字段",
          summary:
            "通过 anchore/stereoscope 在用户态内存逐层回放 Tarball：遇到 .wh.<name> 摘除下层节点，遇到 .wh..wh..opq 清空目录所有祖先子项。默认扫描（SquashedScope）仅面向最终挂载态输出；被遮蔽的 Layer 0/1 仅可选标记 deleted_in_layer 供密钥/合规追溯。",
          irSnippet: [
            "// Layer 2 IR 落地视图（零宿主机 mount / 零 docker exec）",
            '"squashed_active_nodes": [',
            '  "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",',
            '  "pkg:maven/org.apache.logging.log4j/log4j-core@2.23.1"',
            "],",
            '"audit_hidden_layers": [',
            '  { "component": "log4j-core@2.14.1", "reason": "opaque_whiteout", "layer": 2 },',
            '  { "component": "curl@7.88.1", "reason": "whiteout_deleted", "layer": 2 }',
            "]"
          ].join("\n"),
        },
      },
    },
    {
      id: "distroless-osdb",
      tabLabel: "2. Distroless 与 RPM 三代 DB",
      contextTitle: "无 Shell 极简镜像（status.d/*）与 RHEL 9 SQLite DB + 源码包映射",
      inspectTitle: "用户态静态 DB 路径矩阵（无 pkg manager 可执行文件）",
      inspectTag: "Debian Distroless + UBI 9",
      inspectTree: [
        "[镜像 A: gcr.io/distroless/base-debian12]",
        "  ├── bin/sh                       [不存在! 严禁依赖 docker exec]",
        "  ├── var/lib/dpkg/status          [不存在! 传统扫描器直接 0 检出]",
        "  ├── var/lib/dpkg/status.d/libssl3 (Package: libssl3, Source: openssl)",
        "  └── usr/lib/os-release           (ID=debian, VERSION_ID=12)",
        "",
        "[镜像 B: redhat/ubi9-minimal]",
        "  ├── var/lib/rpm/                 [旧路径或软链]",
        "  ├── usr/lib/sysimage/rpm/rpmdb.sqlite [RHEL 9+ SQLite 3, 非 BDB!]",
        "  │     └── zlib-1.2.11-40.el9 (SourceRPM: zlib-1.2.11-40.el9.src.rpm)",
        "  └── etc/os-release               (ID=rhel, VERSION_ID=9.4)"
      ].join("\n"),
      badges: [
        { cls: "del", text: "无 /bin/sh · 禁 docker exec" },
        { cls: "opq", text: "Distroless status.d/*" },
        { cls: "add", text: "Source / SourceRPM → upstream" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：只读 /var/lib/dpkg/status 且忽略 Source 源码包映射",
          verdictTitle: "Distroless 100% 漏报 + Debian/RPM CVE 无法匹配发行版公告",
          summary:
            "老旧扫描器或依赖容器内执行 dpkg-query/rpm -qa 的工具遇到 Distroless 直接崩溃或返回空列表；即使读出包名 libssl3，若不提取 Source: openssl 写入 upstream 并保留 distro=debian-12，Layer 3 匹配引擎将无法命中按源码包发布的 Debian DSA 公告！",
          irSnippet: [
            "// 错误：Distroless 漏报 + 缺少源码包/发行版限定符",
            '"distroless_packages": [], // ❌ 没扫 status.d/*',
            '"ubi9_packages": [',
            '  // ❌ 没兼容 /usr/lib/sysimage/rpm/rpmdb.sqlite 且缺失 distro/upstream',
            '  "pkg:rpm/redhat/libssl3@3.0.7"',
            "]"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：纯用户态多路径 DB 解析（go-rpmdb + status.d）",
          verdictTitle: "零 CGO/零进程读全四代 OS DB，完整挂载 distro 与 upstream 限定符",
          summary:
            "纯 Go 在用户态同时扫描 /var/lib/dpkg/status 与 /var/lib/dpkg/status.d/*，并用 go-rpmdb（MIT）无 CGO 自动探测 BDB / NDB / SQLite 三代 RPM DB（含 /usr/lib/sysimage/rpm）；同时解析 os-release 与 Source/origin/sourceRpm 注入标准 PURL 限定符。",
          irSnippet: [
            "// Layer 2 IR 规范化输出（可直接喂给 L3 Backport 匹配引擎）",
            '"os_packages": [',
            '  "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",',
            '  "pkg:rpm/redhat/zlib@1.2.11-40.el9?arch=x86_64&distro=rhel-9.4&upstream=zlib-1.2.11-40.el9.src.rpm"',
            "]"
          ].join("\n"),
        },
      },
    },
    {
      id: "java-fatjar",
      tabLabel: "3. Java Nested JAR vs Shade",
      contextTitle: "Spring Boot 嵌套归档 vs Maven Shade 打平重定位（Relocation）",
      inspectTitle: "容器内 Java 归档制品结构剖析",
      inspectTag: "Spring Boot JAR vs Shaded Uber-JAR",
      inspectTree: [
        "[制品 A: Spring Boot Executable JAR]",
        "  └── app.jar (ZIP)",
        "      ├── META-INF/MANIFEST.MF     (Spring-Boot-Lib: BOOT-INF/lib/)",
        "      └── BOOT-INF/lib/",
        "          ├── spring-web-6.1.4.jar (含 META-INF/maven/.../pom.properties)",
        "          └── jackson-databind-2.16.1.jar",
        "",
        "[制品 B: Maven Shade Uber-JAR]",
        "  └── service-uber.jar (ZIP 打平合并)",
        "      ├── META-INF/maven/com.corp/service/pom.properties (仅剩壳自身!)",
        "      ├── com/corp/App.class",
        "      ├── shaded/guava/collect/ImmutableList.class [包名已被重定位!]",
        "      └── shaded/netty/handler/codec/http/...      [pom.properties 已丢失]"
      ].join("\n"),
      badges: [
        { cls: "add", text: "BOOT-INF/lib 嵌套流式解析" },
        { cls: "del", text: "Shade 剥离元数据 + 重定位类路径" },
        { cls: "opq", text: "防 Zip Bomb 解压阈值" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：仅扫顶层 JAR 或无防护递归解压",
          verdictTitle: "嵌套库全漏报 + Shade 制品失明 + Zip Bomb 撑爆磁盘",
          summary:
            "非递归扫描只认出外层 app.jar；无上限全量落盘解压嵌套 JAR 容易被恶意构造的 42.zip（高压缩比 Zip Bomb）或 ../ 路径穿越击穿 Worker；面对 Maven Shade 打平重定位的字节码，传统 META-INF 提取器更是 100% 失明。",
          irSnippet: [
            "// 错误：仅仅抓到最外层业务包壳子，核心传递依赖全丢失",
            '"java_components": [',
            '  "pkg:maven/com.corp/app@1.0.0" // ❌ BOOT-INF 与 shaded.netty 全漏报',
            "]"
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：受限流式嵌套解析 + 字节码回退 + CI 前置 SBOM 融合",
          verdictTitle: "防 Zip 炸弹嵌套提取 + Shade 指纹补偿 / 构建期 BOM 对齐",
          summary:
            "对 Spring Boot/WAR 等嵌套归档采用带「最大深度(3层) + 最大解压字节限额 + ZipSlip 校验」的纯内存流式提取；对 Shade Uber-JAR，则通过 class 常量池/包前缀启发指纹（标记低置信度）+ 与构建期 cyclonedx-maven-plugin / ORT 产出的 Tier 3 BOM 按制品 Digest 关联补全。",
          irSnippet: [
            "// Layer 2 IR（Nested 实锤 + Shade 关联构建期 SBOM）",
            '"nested_jar_tier4": [',
            '  { "purl": "pkg:maven/org.springframework/spring-web@6.1.4", "virtual_path": "app.jar!/BOOT-INF/lib/spring-web-6.1.4.jar" }',
            "],",
            '"shaded_uberjar_strategy": {',
            '  "artifact_sha256": "e3b0c442...",',
            '  "linked_pre_shade_bom": "cyclonedx-maven-plugin (Tier 3)",',
            '  "bytecode_hint": "relocated: shaded.netty -> pkg:maven/io.netty/netty-all (low_conf_hint)"',
            "}"
          ].join("\n"),
        },
      },
    },
    {
      id: "go-rust-binary",
      tabLabel: "4. Go & Rust 静态编译二进制",
      contextTitle: "scratch 无 OS 镜像中 stripped ELF 二进制依赖还原（.go.buildinfo vs .dep-v0）",
      inspectTitle: "ELF Binary Sections（已使用 strip / -ldflags=\"-s -w\"）",
      inspectTag: "FROM scratch (无任何源码/锁文件)",
      inspectTree: [
        "[二进制 1: api-gateway (Go 1.22, 编译参数: -ldflags=\"-s -w\")]",
        "  ├── .symtab / .debug_*          [已全部剥离!]",
        "  └── .go.buildinfo               [保留完整! 运行时 panic 堆栈与 debug/buildinfo 依赖它]",
        "        ├── GoVersion: go1.22.1",
        "        ├── dep: github.com/gin-gonic/gin v1.9.1",
        "        └── replace: golang.org/x/net v0.17.0 => v0.23.0",
        "",
        "[二进制 2: crypto-worker (Rust release)]",
        "  ├── [默认 cargo build --release] 仅剩机器码，无 Cargo.lock，依赖全失明！",
        "  └── [cargo auditable build --release] 嵌入专用链接器段：",
        "        └── .dep-v0 (zlib compressed JSON: openssl@0.10.64, tokio@1.36.0)"
      ].join("\n"),
      badges: [
        { cls: "add", text: ".go.buildinfo 抗 -s -w 剥离" },
        { cls: "opq", text: "必生成 pkg:golang/stdlib" },
        { cls: "add", text: "Rust .dep-v0 段解析" },
      ],
      modes: {
        naive: {
          status: "danger",
          verdictLabel: "灾难：忽略 GoVersion 标准库 & 仅查源版本 / 对 Rust 失明",
          verdictTitle: "漏掉 Go stdlib CVE、误报被 replace 修复的包、Rust 零检出",
          summary:
            "很多粗糙扫描器解析 Go 二进制时：1) 忘记把 GoVersion (go1.22.1) 单独映射为 pkg:golang/stdlib@1.22.1，导致标准库 net/http 或 crypto/tls 高危漏洞全漏报；2) 忽略 replace 字段，对已替换为 v0.23.0 的原版本继续报假警；3) 对未带 Cargo.lock 的 Rust 二进制彻底失明。",
          irSnippet: [
            "// 错误：漏掉 stdlib、误报 replace 原版本、Rust 0 检出",
            '"go_components": [',
            '  "pkg:golang/golang.org/x/net@v0.17.0" // ❌ 实际已被 replace 为 v0.23.0',
            '], // ❌ 缺失 pkg:golang/stdlib@1.22.1',
            '"rust_components": [] // ❌ 未解析 .dep-v0'
          ].join("\n"),
        },
        industrial: {
          status: "ok",
          verdictLabel: "推荐架构：debug/buildinfo（含 stdlib+replace）+ .dep-v0 原生提取",
          verdictTitle: "即使在 scratch 无源码 stripped 镜像中也能精准还原依赖",
          summary:
            "调用 Go 标准库 debug/buildinfo 无须源码或符号表即可读出 .go.buildinfo：生成 pkg:golang/stdlib 节点并严格取 Replace 生效版本；对 Rust 推行 CI 接入 cargo-auditable（零运行时开销、MIT/Apache-2.0），通过解析 .dep-v0 段还原精确 Crate 树。",
          irSnippet: [
            "// Layer 2 IR 标准化二进制制品输出",
            '"go_binary_nodes": [',
            '  "pkg:golang/stdlib@1.22.1",',
            '  "pkg:golang/github.com/gin-gonic/gin@v1.9.1",',
            '  "pkg:golang/golang.org/x/net@v0.23.0"  // 已按 replace 解析',
            "],",
            '"rust_binary_nodes_from_dep_v0": [',
            '  "pkg:cargo/openssl@0.10.64",',
            '  "pkg:cargo/tokio@1.36.0"',
            "]"
          ].join("\n"),
        },
      },
    },
  ];

  function initOciArtifactLab(container) {
    const dataEl = container.querySelector("script.oci-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        container.innerHTML = "<p>OCI 与制品实验台数据解析失败。</p>";
        return;
      }
    }

    const scenarios = config.scenarios || DEFAULT_SCENARIOS;
    const state = {
      scenarioIdx: 0,
      modeId: "naive",
    };

    function render() {
      const sc = scenarios[state.scenarioIdx] || scenarios[0];
      const out = sc.modes[state.modeId] || sc.modes.industrial;

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "OCI 镜像分层与编译制品解剖实验台")}</h3>
          <div class="widget-status">${escapeHtml(sc.tabLabel)}</div>
        </div>
      `;

      if (config.intro) {
        html += `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(config.intro)}</p>`;
      }

      html += `<div class="dep-lab-tabs">`;
      scenarios.forEach((item, idx) => {
        html += `
          <button type="button" class="dep-tab-btn ${idx === state.scenarioIdx ? "active" : ""}" data-sc="${idx}">
            ${escapeHtml(item.tabLabel)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="dep-lab-controls">`;
      html += `<span class="dep-lab-ctrl-label">切换采集策略对比</span>`;
      MODES.forEach((m) => {
        html += `
          <button type="button" class="dep-toggle-btn ${m.id === state.modeId ? "active" : ""}" data-mode="${m.id}">
            ${escapeHtml(m.label)}
          </button>
        `;
      });
      html += `</div>`;

      html += `<div class="oci-lab-grid">`;

      // Left column: Raw artifact / layer filesystem anatomy
      html += `<div>`;
      html += `<div class="oci-lab-col-head">${escapeHtml(sc.inspectTitle)}</div>`;
      html += `
        <div class="oci-lab-inspect">
          <div class="oci-lab-inspect-head">
            <span>物理层 / 二进制段布局</span>
            <span>${escapeHtml(sc.inspectTag)}</span>
          </div>
          <pre class="oci-lab-tree">${escapeHtml(sc.inspectTree)}</pre>
        </div>
      `;
      if (sc.badges && sc.badges.length) {
        html += `<div class="oci-lab-badges">`;
        sc.badges.forEach((b) => {
          html += `<span class="wh-pill ${escapeHtml(b.cls)}">${escapeHtml(b.text)}</span>`;
        });
        html += `</div>`;
      }
      html += `</div>`;

      // Right column: Verdict + IR projection
      html += `
        <div class="oci-lab-result">
          <div class="oci-lab-col-head">采集裁决与 Layer 2 IR 落库投影 · ${escapeHtml(sc.contextTitle)}</div>
          <div class="dep-verdict-box ${escapeHtml(out.status)}">
            <div class="dep-verdict-label">${escapeHtml(out.verdictLabel)}</div>
            <div class="dep-verdict-main">${escapeHtml(out.verdictTitle)}</div>
            <p class="dep-verdict-note">${escapeHtml(out.summary)}</p>
          </div>
          <div class="dep-graph-box">
            <div class="dep-graph-head">
              <span>写入 Layer 2 IR 输出结构</span>
              <span>模式：${escapeHtml(MODES.find((m) => m.id === state.modeId)?.label || state.modeId)}</span>
            </div>
            <pre class="fusion-json">${escapeHtml(out.irSnippet)}</pre>
          </div>
        </div>
      `;

      html += `</div>`;

      container.innerHTML = html;

      container.querySelectorAll(".dep-tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.scenarioIdx = Number(btn.dataset.sc);
          render();
        });
      });

      container.querySelectorAll(".dep-toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.modeId = btn.dataset.mode;
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="oci-artifact-lab"]').forEach(initOciArtifactLab);
  });
})();
