# Modern SCA & Supply Chain Security Resources

## Knowledge

### 核心开放标准与数据模型（Layer 2 & Layer 3 规范）
- [Standard: Package-URL (PURL) Specification — Ecma ECMA-427](https://github.com/package-url/purl-spec) ([ECMA-427 官方标准仓库](https://github.com/Ecma-TC54/ECMA-427) / [packageurl.org](https://www.packageurl.org/))
  跨生态软件包唯一标识的事实与国际标准（含 VERS 版本区间规范与 `pypi`/`npm`/`maven`/`golang`/`deb`/`rpm`/`huggingface` 类型规范化规则，以及 [PEP 503](https://peps.python.org/pep-0503/) PyPI 名称折叠标准）。用于：设计统一组件主键与反腐败归一化器、规避传统 CPE 命名歧义与漏洞错配。
- [Standard: OWASP CycloneDX 1.7 — Ecma ECMA-424 2nd Edition](https://github.com/CycloneDX/specification) ([1.7 JSON Schema Reference](https://cyclonedx.org/docs/1.7/json/))
  面向应用安全与全栈供应链的轻量级 BOM 国际标准，原生涵盖 `bom-ref`、依赖图（`dependsOn`/`provides`）、`evidence.occurrences`、`evidence.callstack`、VEX、CBOM、ML-BOM（`modelCard`）及 v1.7 新增的 `citations`（多工具富化溯源）与专利断言 `patents`。用于：设计平台对外高精度交换契约与内部 IR 双向投影。
- [Standard: SPDX 3.0.1 Model & AI/Dataset Profiles](https://spdx.github.io/spdx-spec/v3.0.1/) ([spdx/spdx-3-model](https://github.com/spdx/spdx-3-model))
  Linux 基金会主导的模块化 BOM 模型（Core + Software/Security/Licensing/AI/Dataset Profiles），以 JSON-LD 图结构及一等公民 `Relationship`（如 `ai_AIPackage` --`trainedOn`--> `dataset_DatasetPackage`）表达合规与训练血缘。用于：对标国际法律/政府合规导出视图与 AI-BOM 映射。
- [Standard: NIST NVD CPE 2.3 Specification](https://nvd.nist.gov/products/cpe)
  传统商业软件、OS 内核与硬件固件的平台枚举命名规范。用于：理解第一代 SCA 的 CPE 命名碰撞/误报成因，并在 Layer 2 IR 中以双标识（PURL 主键 + CPE 兼容槽位）承接闭源商业软件与传统审计。
- [SDKs: PURL & SBOM 商用合规开源基础库](https://github.com/protobom/protobom)
  官方 MIT 协议 PURL 解析库（[`packageurl-go`](https://github.com/package-url/packageurl-go) / [`packageurl-java`](https://github.com/package-url/packageurl-java) / [`packageurl-python`](https://github.com/package-url/packageurl-python)）与 Apache-2.0 SBOM 序列化/互转库（[`CycloneDX/cyclonedx-go`](https://github.com/CycloneDX/cyclonedx-go)、[`CycloneDX/cyclonedx-core-java`](https://github.com/CycloneDX/cyclonedx-core-java)、OpenSSF [`protobom/protobom`](https://github.com/protobom/protobom)）。用于：避免手写低层解析器，把研发精力聚焦在自研 IR 规范化器与图谱存储上。
- [Standard: OpenSSF OSV Schema v1.7.0 (`ossf/osv-schema`)](https://ossf.github.io/osv-schema/) ([osv.dev](https://osv.dev/) / [`upstream` 字段设计博客](https://osv.dev/blog/posts/supporting-upstream-field/))
  面向开源生态的机器可读漏洞交换格式（2025-03 发布 v1.7.0），以生态原生版本区间（`SEMVER` / `ECOSYSTEM` / `GIT`）替代模糊 CPE 匹配；严格区分 `aliases`（等价传递闭包）、`upstream`（v1.7.0 新增，用于 Debian DSA / Ubuntu USN 等 Backport 有向衍生关系防污染）与 `related`，并支持 `CVSS_V4`、`withdrawn` 撤销墓碑及 `ecosystem_specific` 函数符号扩展。用于：设计 Layer 3 统一入库模型与图谱去重契约。
- [Standard: SLSA v1.2 Specification (`slsa.dev`)](https://slsa.dev/) & [OpenVEX (`openvex/spec`)](https://github.com/openvex/spec) & [FIRST EPSS (`first.org/epss`)](https://www.first.org/epss/)
  软件构建溯源与防篡改证明标准（SLSA v1.2 Build/Source Track、Provenance/VSA）、轻量级 SBOM 无关可利用性交换格式（OpenVEX）以及 30 天在野利用概率模型（EPSS API）。用于：Phase 2/3 智能降噪（VEX/EPSS）与构建可信溯源闭环。
- [Framework: OWASP LLM Top 10 (`LLM03`) & Agentic Top 10 (`ASI04`)](https://owasp.org/)
  面向大模型与自主 Agent（含 MCP Server、Agent Skills、模型权重序列化与数据集投毒）的供应链威胁分类框架。用于：规划 AI-BOM、模型文件扫描（Pickle vs Safetensors）与 MCP 治理架构。

### 多语言依赖解析规范、实证基准与构建期沙箱（Layer 1）
- [Paper: Balliu et al. (IEEE S&P 2023) — Challenges of Producing Software Bill of Materials for Java (`arXiv:2303.11102`)](https://arxiv.org/abs/2303.11102)
  以 26 个真实 Java/Maven 项目（Flink、Jenkins 等）为基准实测 6 款 SBOM 生成器精度与完整度落差，证实纯静态清单解析的精度天花板与构建有效图谱必要性。
- [Official Docs: Apache Maven Dependency Mechanism](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html) & [Gradle Dependency Locking](https://docs.gradle.org/current/userguide/dependency_locking.html)
  JVM 生态两条截然相反的依赖裁决规则（Maven Nearest Definition / First Declaration / BOM `import` 覆写 vs Gradle Highest Version Wins / 动态范围 / `gradle.lockfile` 确定性锁定）。
- [Official Docs: npm `package-lock.json` v3](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json) & [pnpm Workspaces / Lockfile](https://pnpm.io/workspaces)
  Node.js 合法多版本共存模型、npm 扁平提升（Hoisting）与幽灵依赖成因、以及 pnpm `importers` + `snapshots` 严格符号链接隔离结构。
- [Specs: Python PEP 508 (Dependency Specification)](https://peps.python.org/pep-0508/) & [PEP 751 (`pylock.toml`)](https://peps.python.org/pep-0751/)
  Python 跨平台通用锁文件标准与 Environment Markers 求值语义（按目标 OS / Python 版本剪枝，消除跨平台误报）。
- [Official Docs: Go Modules Reference (`go.dev/ref/mod`)](https://go.dev/ref/mod) & [Russ Cox — Minimal Version Selection (MVS)](https://research.swtch.com/vgo-mvs)
  阐明 Go MVS「选满足约束最低版本」数学模型，以及 **`go.sum` 是防篡改校验和日志而非 Lockfile** 的核心事实（消除 Ghost CVE 误报）。
- [Sandboxes: Google gVisor (`google/gvisor`, Apache-2.0)](https://github.com/google/gvisor)、[Kata Containers (`kata-containers/kata-containers`, Apache-2.0)](https://github.com/kata-containers/kata-containers)、[AWS Firecracker (`firecracker-microvm/firecracker`, Apache-2.0)](https://github.com/firecracker-microvm/firecracker) & [Dependabot Core Proxy Pattern (MIT)](https://github.com/dependabot/dependabot-core)
  商用合规构建期防 RCE 纵深隔离方案（用户态内核 vs OCI/K8s MicroVM 运行时 vs 独立 KVM MicroVM），以及「沙箱无明文密钥 + 外部白名单代理动态注入凭据」架构范式。
- [Standard: OCI Image Format Specification (`opencontainers/image-spec`)](https://github.com/opencontainers/image-spec/blob/main/layer.md)
  容器镜像分层变更集（Layer Changesets）官方规范，定义单文件删除标记 `.wh.<filename>` 与目录不透明遮蔽标记 `.wh..wh..opq`（Opaque Whiteout）的精确叠加语义。用于：设计无守护进程用户态镜像终态合成器，避免 `AllLayers` 历史层幽灵误报。
- [Repos: Anchore Stereoscope (`anchore/stereoscope`, Apache-2.0)](https://github.com/anchore/stereoscope) & [Google `go-containerregistry` (`google/go-containerregistry`, Apache-2.0)](https://github.com/google/go-containerregistry)
  纯 Go 用户态 OCI/Docker 镜像拉取、Manifest 解析、层 Tarball 流式读取与内存虚拟文件系统树（Virtual FileTree / `Squashed` 终态视图）合成基础设施。用于：零 `docker exec`、零内核 `overlayfs` 挂载的高并发容器资产采集。
- [OS DBs & Distroless: `knqyf263/go-rpmdb` (MIT)](https://github.com/knqyf263/go-rpmdb) & [Google Distroless (`GoogleContainerTools/distroless`, Apache-2.0)](https://github.com/GoogleContainerTools/distroless)
  涵盖 Debian `/var/lib/dpkg/status`、Distroless 碎片目录 `/var/lib/dpkg/status.d/*`、Alpine `/lib/apk/db/installed` 及 RPM 三代数据库（BerkeleyDB `Packages`、NDB `Packages.db`、RHEL 9+ SQLite `rpmdb.sqlite` 及 `/usr/lib/sysimage/rpm` 路径）的无 CGO 纯 Go 解析方案，以及二进制包到源码包（`Source` / `origin` / `sourceRpm`）映射，解决按源码包发布安全公告导致的误报/漏报。
- [Binary Metadata: Go `debug/buildinfo`](https://pkg.go.dev/debug/buildinfo)、[Rust `cargo-auditable` (MIT/Apache-2.0)](https://github.com/rust-secure-code/cargo-auditable) & [Apache Maven Shade / Spring Boot Nested JAR](https://maven.apache.org/plugins/maven-shade-plugin/)
  编译期交付制品内嵌依赖规范：Go 二进制 `.go.buildinfo` 段（含 `stdlib` 主版本与 `replace` 模块信息，不被 `-ldflags="-s -w"` 剥离）、Rust `.dep-v0` zlib 压缩 JSON 段（弥补 `cargo build --release` 剥离锁文件盲区）、以及 Spring Boot `BOOT-INF/lib/*.jar` 递归流式读取与 Maven Shade 重定位打平盲区对策。

### 顶级商用合规开源底座（Apache-2.0 / MIT 架构参考）
- [Repo: Google OSV-SCALIBR (`google/osv-scalibr`, Apache-2.0)](https://github.com/google/osv-scalibr)（[Supported Inventory Types](https://github.com/google/osv-scalibr/blob/main/docs/supported_inventory_types.md) / [New Enricher Guide](https://github.com/google/osv-scalibr/blob/main/docs/new_enricher.md) / [OSV-Scanner v2](https://github.com/google/osv-scanner)）
  Google 内部大规模使用的模块化 Go SCA 库，以 `FilesystemExtractor`（`FileRequired` 零打开预过滤 + `Extract`）、`StandaloneExtractor`、`Enricher`（如结合 `deps.dev` 的 `transitivedependency/pomxml` 与 `transitivedependency/requirements`）及 `plugin.Capabilities` / `FilterByCapabilities` 驱动精细化插件调度与离线/在线双模切换。用于：作为 Go 核心 Worker 直接嵌入并裁剪插件。
- [Repo: Anchore Syft (`anchore/syft`, Apache-2.0)](https://github.com/anchore/syft)（[Go Package Docs](https://pkg.go.dev/github.com/anchore/syft/syft) / [Grype](https://github.com/anchore/grype)）
  容器镜像、文件系统与制品 SBOM 提取标杆（Go 库 + CLI），核心管道为 `syft.GetSource` → `syft.CreateSBOM` → `*sbom.SBOM`，以 `pkg.Cataloger`、`artifact.Relationship` 及 `SquashedScope` vs `AllLayersScope` 精确刻画镜像分层与组件证据；静态源码扫描在无锁传递图上存在边界，与 Grype 共同示范「提取与匹配解耦」。用于：库级嵌入镜像分层、OS 包库与制品元数据采集。
- [Repo: OWASP cdxgen (`CycloneDX/cdxgen`, Apache-2.0)](https://github.com/CycloneDX/cdxgen) & [CVE-2024-50611](https://nvd.nist.gov/vuln/detail/CVE-2024-50611) / [GHSA-5vwr-qchf-q4pf](https://github.com/CycloneDX/cdxgen/security/advisories/GHSA-5vwr-qchf-q4pf)
  多语言深度源码与构建感知 CycloneDX 1.7 生成器（提供 `createBom` API、`--lifecycle pre-build|build|post-build`、`--deep` / `evinse`、`internal:workspaceRef` Monorepo 标记与 `evidence.identity` / `citations` / CBOM / ML-BOM）。**安全红线**：默认 `build` 生命周期会调用原生构建器，扫不可信仓库存在构建文件代码执行风险（`CVE-2024-50611`），旧版 Maven 模块路径另曝出命令注入（`GHSA-5vwr-qchf-q4pf`，12.3.3+ 修复）；静态快速扫须强制 `--lifecycle pre-build --no-install-deps`（或 `CDXGEN_SECURE_MODE=true`），跑 `build` 须进 Tier 3 隔离沙箱。
- [Repo: OSS Review Toolkit (`oss-review-toolkit/ort`, Apache-2.0)](https://github.com/oss-review-toolkit/ort)（[Analyzer Documentation](https://oss-review-toolkit.org/ort/docs/tools/analyzer)）
  Linux 基金会 ACT 旗下 Kotlin/JVM 企业级依赖与合规管线，核心链条为 `Analyzer` → `PackageManager`（Maven Resolver / `GradleInspector`）→ 全局去重 `DependencyGraph`（按 `Scope` 精确分离 `runtime` / `test`）→ `OrtResult`，默认 `allowDynamicVersions=false` 严守构建可复现性。用于：隔离/CI Hook 跑复杂 JVM 有效图与高精度许可证合规。
- [Repo: Aqua Trivy (`aquasecurity/trivy`, Apache-2.0)](https://github.com/aquasecurity/trivy)
  高覆盖度的全能开源安全扫描器（OS/语言包、镜像、IaC、密钥、许可证）。用于：研究高并发 CLI 工程化、本地离线漏洞库分发格式（BoltDB/OCI）与多生态适配细节；同时作为「一体化扫描器不宜直接充当核心数据底座」的架构对照。
- [Repo: OWASP Dependency-Track (`DependencyTrack/dependency-track`, Apache-2.0)](https://github.com/DependencyTrack/dependency-track) ([官方文档](https://docs.dependencytrack.org/))
  企业级 SBOM 持续监控平台参考架构：v5（原孵化代号 Project Hyades，现已并入主仓库）将 v4 单体内存队列拆分为无状态 HA `apiserver` + Kafka 事件流 + 独立扩缩容 `vulnerability-analyzer` / `notification-publisher` + PostgreSQL，示范「一次采集、持续重算」与十万级项目高并发入库设计。
- [Repo: Snyk Language Server (`snyk/snyk-ls`, Apache-2.0)](https://github.com/snyk/snyk-ls) & [Snyk CLI MCP (`snyk/cli`, Apache-2.0)](https://github.com/snyk/cli)
  本地左移触点的两代演进参照：先以单一 Go LSP 后台进程（`snyk-ls`）通过 `stdio` JSON-RPC 与 `didSave` 缓存失效服务传统多端 IDE；再在 `snyk/cli` 中内置 `snyk mcp -t stdio`（提供 `snyk_sca_scan`、`snyk_package_health_check` 等工具）对接 Claude Code/Cursor 等对话式 AI Coding Agent。
- [Paper: Spracklen et al. (USENIX Security) — *We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs* (`arXiv:2406.10279`)](https://arxiv.org/abs/2406.10279)
  基于 16 款 LLM、57.6 万份代码样本的实证研究：揭示模型平均 **19.7%** 推荐包名属于幻觉（商业模型 5.2%、开源模型 21.7%），且 43% 可稳定复现（Slopsquatting）。用于：论证 AI Agent 时代本地触点必须从 `LSP-only` 演进为 `MCP + Hook + LSP` 三模事前/事中防线。
- [Action & API: GitHub `actions/dependency-review-action` (MIT)](https://github.com/actions/dependency-review-action) & [Dependency Submission API](https://docs.github.com/en/rest/dependency-graph/dependency-submission)
  PR 增量依赖门禁事实参照：基于 commit SHA 提交构造期依赖快照，对比 `merge-base` 与 PR Head 图差仅拦截净新增风险，以及 `retry-on-snapshot-warnings` 快照等待机制。
- [Service & Docs: Google Open Source Insights (`deps.dev`)](https://docs.deps.dev/)
  Google 提供的跨生态开源依赖图、版本关系与安全公告查询服务（HTTP/gRPC API）。用于：研究大规模传递依赖图预计算与元数据补全思路。
- [Data & Architecture: Google `osv.dev` (`google/osv.dev`, Apache-2.0)](https://google.github.io/osv.dev/architecture/) ([数据源与许可表 `data/`](https://google.github.io/osv.dev/data/))
  OSV 聚合后端参考架构（含 `relations` CronJob 自动维护 `aliases` / `upstream` / `related` 传递关系与 GCS `all.zip` 导出）。**商用合规关键事实**：OSV.dev 平台代码为 Apache-2.0，但**漏洞数据没有单一许可**，各源按上游继承（如 GHSA/Go/PyPA `CC-BY-4.0`、RustSec `CC0-1.0`、Ubuntu/Alpine 转换库 `CC-BY-SA-4.0`、Chainguard/Wolfi `CC-BY-NC-ND-4.0` / 商业扫描器受限条款），商业闭源产品严禁整包 `all.zip` 直接混卖。
- [Feeds: `github/advisory-database` (`CC-BY-4.0`)](https://github.com/github/advisory-database) &amp; [`CVEProject/cvelistV5`](https://github.com/CVEProject/cvelistV5)
  解决 2024+ NIST NVD 积压与大量新 CVE 缺 CPE 断点的双主键通道：GHSA 必须区分人工精校 `Reviewed` 与自动抓取 `Unreviewed`（且商业集成须保留 `CC-BY-4.0` 署名）；`cvelistV5` 须同时解析 `containers.cna` 与 `containers.adp`（如 `CISA-ADP` Vulnrichment 补充的 SSVC、KEV、CVSS 与 CPE）。
- [Collector: Anchore Vunnel (`anchore/vunnel`, Apache-2.0)](https://github.com/anchore/vunnel)
  多源漏洞数据采集 ETL 架构参照，以独立 `Provider`（NVD、GHSA、Debian、RHEL、Ubuntu、Alpine、Wolfi 等）解耦上游格式转换。用于：设计自研 Layer 3 采集架构并额外叠加商业 License Policy Gate 与分字段权威裁决。
- [Specs & Libraries: VERS (`package-url/vers-spec`) & `aboutcode-org/univers` (`Apache-2.0 AND BSD-3-Clause AND MIT`)](https://github.com/package-url/vers-spec)
  跨生态统一版本区间 URI 规范（`vers:<scheme>/<constraints>`，严格零空白、按生态全序排序与去重），以及 `univers` 区间合并化简（`VersionRange.normalize`）参考实现。用于：设计 CycloneDX `versionRange` 导出与自研纯 Go VERS 规范化器。
- [Specs: 跨生态原生版本排序规范（SemVer / `node-semver` / Maven / PEP 440 / `deb-version` / RPM / APK）](https://maven.apache.org/pom.html#Version_Order_Specification)
  涵括 [SemVer 2.0.0](https://semver.org/)、[npm `node-semver` 预发布元组规则](https://github.com/npm/node-semver#prerelease-tags)、[Maven `ComparableVersion`](https://maven.apache.org/pom.html#Version_Order_Specification)（已知 vs 未知修饰符顺序）、[Python PEP 440](https://peps.python.org/pep-0440/)（`SpecifierSet` 排他比较 vs 全序 Comparator）、[`deb-version(7)`](https://man7.org/linux/man-pages/man7/deb-version.7.html)（`~` 与字母/非字母权序）、[RPM `rpmvercmp`](https://rpm-software-management.github.io/rpm/manual/dependencies.html#versioning)（`~` 与 `^` 脱字符）及 [Alpine `apk` 版本规范](https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver)。用于：构筑 Layer 3 零误报/零漏报匹配比较层。
- [Libraries & Feeds: Go 版本比较库（Apache-2.0 / MIT）与 Distro Backport 真值（Debian DSA / Red Hat CSAF VEX）](https://docs.redhat.com/en/documentation/red_hat_security_data_api/)
  纯 Go 嵌入式底座：[`google/osv-scalibr/semantic`](https://github.com/google/osv-scalibr)（Apache-2.0）、[`anchore/grype/grype/version`](https://github.com/anchore/grype)（Apache-2.0）、[`aquasecurity/go-version`](https://github.com/aquasecurity/go-version)（Apache-2.0）及 [`knqyf263/go-deb-version`](https://github.com/knqyf263/go-deb-version) / [`go-rpm-version`](https://github.com/knqyf263/go-rpm-version)（MIT）；以及以 [`CVE-2024-6387`](https://www.debian.org/security/2024/dsa-5724)（`DSA-5724-1` / [`RHSA-2024:4312`](https://access.redhat.com/errata/RHSA-2024:4312) + Red Hat CSAF VEX）为代表的发行版 Backport 与 Epoch 隔离范式。
- [Repo: OpenSSF Malicious Packages (`ossf/malicious-packages`, Apache-2.0)](https://github.com/ossf/malicious-packages)
  采用 OSV 格式发布的开源恶意包情报聚合库。用于：在 Layer 3 快速冷启动恶意包基础拦截能力。
- [Repo: AboutCode ScanCode-Toolkit (`aboutcode-org/scancode-toolkit`, Apache-2.0 / LicenseDB CC-BY-4.0)](https://github.com/aboutcode-org/scancode-toolkit)
  源码级许可证与版权扫描标杆。用于：理解代码与知识库双许可（Apache-2.0 vs CC-BY-4.0 署名要求）的商用合规边界。

### 商用协议排雷与商业标杆技术剖析
- [License Reference: Semgrep CE (LGPL-2.1 + Semgrep Rules License v1.0)](https://semgrep.dev/) / [FOSSology (GPL-2.0)](https://www.fossology.org/) / [GitHub CodeQL Terms (Non-Commercial for Private Repos)](https://codeql.github.com/)
  商业闭源 SCA 产品必须警惕的典型协议边界：强传染性（GPL）、动态链接/边界约束（LGPL）、禁止竞品 SaaS 商用的规则协议、以及仅限开源代码分析的专有引擎条款。
- [Technical Architecture: Endor Labs Reachability Analysis](https://www.endorlabs.com/) / [Socket.dev Behavioral Supply Chain Analysis](https://socket.dev/) / [Snyk Vulnerability Database & Contextual SCA](https://snyk.io/)
  全球商业标杆的三条差异化护城河：函数级调用图可达性降噪（Endor Labs）、基于 AST 行为信号的主动投毒拦截（Socket）、人工研判+语义版本区间+修复图谱（Snyk）。用于：校准自研高价值壁垒方向（注意甄别官网内容中的营销表述，聚焦底层架构原理）。

## Wisdom (Communities)

- [OpenSSF Working Groups & Slack](https://openssf.org/working-groups/)（重点关注 [Securing Software Repositories WG](https://github.com/ossf/wg-securing-software-repos) 与 Vulnerability Disclosures WG）
  全球包管理器维护者与供应链安全一线架构师聚集地，覆盖 OSV、恶意包治理、Trusted Publishers 与构建溯源标准。用于：跟进前沿供应链威胁与验证架构选型是否符合国际生态演进方向。
- [OWASP CycloneDX & Dependency-Track 社区](https://cyclonedx.org/)（GitHub Discussions & OWASP Slack）
  SBOM/VEX/ML-BOM 标准制定者与大规模落地团队的直接交流渠道。用于：探讨复杂 SBOM 建模、VEX 工作流与企业级海量组件性能瓶颈。
- [Package-URL / Ecma TC54 社区](https://github.com/package-url/purl-spec)
  PURL 与 VERS 版本规范的核心维护社区。用于：解决跨生态冷门包管理器命名规范与版本区间边界争议。

## Gaps
- **静态函数级可达性（Call Graph）跨语言评测基准**：尚缺经过学术界或第三方独立验证的跨语言（Java/JS/Python/Go）调用图精度/召回率对比论文与基准测试集（将在进入 Layer 4 专项前补齐）。
- **AI 供应链（MCP / Agent Skills / Model Serialization）威胁分类学与实证数据**：尚缺系统性的开源威胁基准库与标准检测范式（将在 AI-BOM 阶段深入调研补齐）。
- **多语言依赖解析器（Lockfile vs Build-time）、四大引擎、镜像制品与多触点采集（Ch 02 已全面收口）**：已于第 3 课补齐 Java/多语言静态 vs 构建期实证研究（Balliu et al., IEEE S&P 2023 `arXiv:2303.11102`）与五大生态解析算法规范，于第 4 课补齐 OSV-SCALIBR / Syft / cdxgen / ORT 接口与融合架构对比，于第 5 课补齐 OCI 镜像分层合成（`.wh.` / `.wh..wh..opq`）、OS 数据库及 Java/Go/Rust 二进制提取，并于第 6 课及 Ref 03 Section 06 补齐 Agentic 时代本地三模入口（MCP + Hook + LSP / `arXiv:2406.10279`）、GitHub Dependency Review、CAS 去重与 Dependency-Track v5（Hyades）事件驱动持续重算架构。
