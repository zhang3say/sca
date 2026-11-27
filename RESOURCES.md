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
- [Offline DB & Distribution: Trivy DB (`aquasecurity/trivy-db`, Apache-2.0) & Grype DB v6 (`anchore/grype`, Apache-2.0)](https://github.com/aquasecurity/trivy-db)
  嵌入式本地漏洞库与离线交付两大标杆：Trivy 采用 `go.etcd.io/bbolt`（MIT）单文件运行态桶结构（`vulnerability` / `data-source` / 各平台包桶；构建期 `advisory-detail` 临时桶优化后清理）+ `metadata.json`（`NextUpdate`），通过 OCI Artifact（`application/vnd.aquasec.trivy.db.layer.v1.tar+gzip`）分发（注意官方未默认对 DB 附 Cosign 签名，商业自建须自行补签）（[Trivy Air-Gap Docs](https://trivy.dev/docs/latest/guide/advanced/air-gap/)）；Grype v6 采用 SQLite3 Handle 搜索表（`affected_package_handles` / `vulnerability_handles`）+ 去重 JSON `blobs` + Zstd（v6.0 首发 `.tar.zst` ~65 MB / 解压 ~900 MB）及 `v6/latest.json`（含 `path` 与 `sha256` `checksum`）。配合 [ORAS](https://oras.land/)（Apache-2.0）、[Sigstore Cosign](https://docs.sigstore.dev/cosign/verifying/verify/)（离线 `cosign initialize` 导出 TUF 根）、[`ncruces/go-sqlite3`](https://github.com/ncruces/go-sqlite3)（MIT）与 [`RoaringBitmap/roaring`](https://github.com/RoaringBitmap/roaring)（Apache-2.0）构成双模私有化与高并发内存索引体系。
- [Repo: OpenSSF Malicious Packages (`ossf/malicious-packages`, Apache-2.0)](https://github.com/ossf/malicious-packages)
  采用 OSV 格式发布的开源恶意包情报聚合库。用于：在 Layer 3 快速冷启动恶意包基础拦截能力。
- [Repo: AboutCode ScanCode-Toolkit (`aboutcode-org/scancode-toolkit`, Apache-2.0 / LicenseDB CC-BY-4.0)](https://github.com/aboutcode-org/scancode-toolkit)
  源码级许可证与版权扫描标杆。用于：Tier 2 异步容器深度探测（抓包内文件头夹带漂移）及履行代码（Apache-2.0）与 LicenseDB 知识库（CC-BY-4.0 署名）双许可合规边界。
- [Specs & Go Libraries: SPDX v3.0.1 Annex B (`License Expressions`)](https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/)、[`github/go-spdx` (MIT)](https://github.com/github/go-spdx)、[`spdx/tools-golang` (Apache-2.0 OR GPL-2.0-or-later)](https://github.com/spdx/tools-golang) &amp; [`google/licensecheck` (BSD-3-Clause)](https://github.com/google/licensecheck)
  规范定义 SPDX 表达式运算符优先级（`+ > WITH > AND > OR`）、运算符全大写或全小写（禁混写，推荐全大写兼容 2.x）与 `LicenseRef-` 规则；三款纯 Go 商用合规基础库支撑 Single Go Core 本地/云端 AST 求值与毫秒级 `LICENSE` 文件文本识别。
- [Compatibility & Curation Data: FSF License List & Compatibility](https://www.gnu.org/licenses/license-list.html)、[OSADL Compatibility Matrix (`CC-BY-4.0`)](https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html) &amp; [ClearlyDefined (`MIT` / `CC0-1.0` Data)](https://clearlydefined.io/)
  FSF 官方协议兼容性规则（`Apache-2.0` vs `GPL-2.0-only`/`GPL-3.0-only`、GPLv3/AGPLv3 §13 桥接）与 OSADL 机器可读 JSON/CSV 兼容性矩阵（CC-BY-4.0 需保留署名）；ClearlyDefined 提供 CC0 公有领域社区校对 `Declared`/`Discovered` 坐标，用于救回 `NOASSERTION` 组件。
- [Curation & Notice Reference: ORT Evaluator / `curations.yml` / `PlainTextTemplate` (Apache-2.0)](https://oss-review-toolkit.org/ort/docs/tools/evaluator) &amp; [`aboutcode-org/license-expression` (Apache-2.0)](https://github.com/aboutcode-org/license-expression)
  ORT 提供策略规则 DSL、人工覆写（Curation）真值收敛及自动生成 `THIRD-PARTY-NOTICES` 的模板范式；`license-expression` 为 Python 侧布尔表达式化简参照。

### 静态函数级可达性（Call Graph）与跨语言程序分析（Layer 4）
- [Algorithms & Go Production Reference: Bacon & Sweeney (OOPSLA 1996, RTA) · Sundaresan et al. (OOPSLA 2000, VTA) · `golang.org/x/tools/go/callgraph/vta` (`BSD-3-Clause`) & `govulncheck` (`golang.org/x/vuln`, `BSD-3-Clause`)](https://pkg.go.dev/golang.org/x/tools/go/callgraph/vta)
  奠定「类层次分析 CHA → 快速类型分析 RTA → 变量类型分析 VTA」的调用图精度/性能阶梯（[`go.dev/doc/security/vuln`](https://go.dev/doc/security/vuln/)）。Go 官方 `govulncheck` 基于 Go SSA + VTA 逐变量追踪接口/函数值具体类型流，并直接消费 `vuln.go.dev`（条目数据 `CC-BY-4.0`）中的 OSV `ecosystem_specific.imports[].symbols` 实现默认函数级可达性判定。
- [Java Soundness & Code-Centric SCA: Reif et al. (ISSTA 2019, *Judge*, DOI `10.1145/3293882.3330555`) · `opalj/JCG` & `opalj/opal` (`BSD-2-Clause`) · Ponta et al. (ICSME 2018, `arXiv:1806.05893`) & `eclipse-steady/steady` (`Apache-2.0`)](https://doi.org/10.1145/3293882.3330555)
  *Judge* 与 [`opalj/JCG`](https://github.com/opalj/JCG) 系统揭示主流 Java 调用图框架因反射、动态代理、序列化与框架入口（Spring DI）导致的不完备性（Unsoundness / 漏报来源）；[`arXiv:1806.05893`](https://arxiv.org/abs/1806.05893) 与 [`eclipse-steady/steady`](https://github.com/eclipse-steady/steady) 开创代码级/用法级漏洞可达性先河。字节码底层与选型边界：[`OW2 ASM`](https://asm.ow2.io/)（`BSD-3-Clause`）、[`opalj/opal`](https://github.com/opalj/opal)（`BSD-2-Clause`）、[`wala/WALA`](https://github.com/wala/WALA)（`EPL-2.0` 文件级弱传染）；严防 [`soot-oss/SootUp`](https://github.com/soot-oss/SootUp)（`LGPL-2.1`，商业闭源 Fat-JAR / 静态合包打包风险）。
- [JS/TS Modular Call Graph: Nielsen et al. (ISSTA 2021) · Chakraborty, Gnanakumar, Sridharan & Møller (ECOOP 2024, *Indirection-Bounded Call Graph Analysis*) · `cs-au-dk/jelly` (`BSD-3-Clause`) & `microsoft/TypeScript` (`Apache-2.0`)](https://github.com/cs-au-dk/jelly)
  面向 Node.js / TypeScript 高阶回调、事件驱动、原型链与多模块边界的模块化静态调用图分析范式（ISSTA 2021 提出跨包模块化安全扫描，ECOOP 2024 引入 Indirection-Bounded 间接引用界定缓解组合爆炸）。源自 Aarhus 大学该研究谱系的 Coana 已被 Socket 于 2025 年 4 月收购整合。
- [Python Call Graph Benchmarks: Salis et al. (ICSE 2021, *PyCG*, `arXiv:2103.00587`, `Apache-2.0`) & Huang et al. (*JARVIS*, `arXiv:2305.05949`, 2023/2024 预印本)](https://arxiv.org/abs/2103.00587)
  [*PyCG*](https://github.com/vitsalis/PyCG) 以跨过程赋值流分析在基准测试集取得 ~99.2% 精确率（Precision）与 ~69.9% 召回率（Recall）；[*JARVIS*](https://arxiv.org/abs/2305.05949) 进一步采用「应用为中心（Application-Centered）、按需（Demand-Driven）的流敏感过程内类型图 + 强更新」解决 PyCG 在真实大仓库全程序不动点计算上的扩展性瓶颈与误报问题。
- [Multi-Language Syntax, CPG & OSV Call Analysis: `tree-sitter` (`MIT`) · `google/osv-scanner` (`Apache-2.0`) · `AppThreat/atom` (`Apache-2.0`) & `joernio/joern` (`Apache-2.0`)](https://github.com/google/osv-scanner)
  [`tree-sitter/tree-sitter`](https://github.com/tree-sitter/tree-sitter)（`MIT`）仅提供单文件增量 CST/AST 语法解析，适合做 L3 修复 Commit Patch-Diff 符号提取，**不可充当跨文件调用图引擎**；[`google/osv-scanner`](https://github.com/google/osv-scanner) 的 `--call-analysis` 目前默认支持 Go（`govulncheck`）、实验性支持 Rust（需执行 `build.rs`）、尚无原生 Java CLI 调用分析；[`AppThreat/atom`](https://github.com/AppThreat/atom) 与 [`joernio/joern`](https://github.com/joernio/joern)（`Apache-2.0`）提供重型代码属性图（CPG）离线深度参考。

### 动态运行时可达性、执行遥测与容器裁剪（Layer 4 Runtime & Debloating）
- [Runtime Container Relevancy: Kubescape & `kubescape/node-agent` (`Apache-2.0`, CNCF)](https://github.com/kubescape/node-agent) ([Kubescape Docs](https://kubescape.io/docs/operator/runtime-threat-detection/))
  CNCF 孵化项目；以轻量 eBPF Node Agent 观察生产容器文件与进程访问，生成 `ApplicationProfile` CRD 并与 `SBOMSyft` 交叉过滤输出 `SBOMSyftFiltered`（消除 60%–80% 未使用 OS 冗余包 CVE）。用于：作为 BYO-Telemetry 标准接入参照及容器 OS 层运行态过滤标杆。
- [eBPF Runtime Sensors & Dual-License Boundary: Cilium Tetragon (`cilium/tetragon`) · Aqua Tracee (`aquasecurity/tracee`) · Falco Libs (`falcosecurity/libs`) · Inspektor Gadget (`inspektor-gadget/inspektor-gadget`)](https://github.com/cilium/tetragon)
  四者用户态组件均采用 `Apache-2.0`，但内核侧调用 GPL-only helper 的 eBPF C 程序须声明 `GPL-2.0` / `Dual BSD-GPL`（`SEC("license") = "GPL"`）。商用闭源架构边界：严禁把 GPL eBPF 内核源码静态混编进核心闭源二进制，须独立进程/DaemonSet 运行并通过 gRPC/JSON 输出标准化 `RuntimeEvidence`。
- [Language-Level Low-Overhead Telemetry: OpenJDK JFR (`jdk.ClassLoad`) · `async-profiler` (`Apache-2.0`) · OpenTelemetry Java (`Apache-2.0`) · Python PEP 669 (`sys.monitoring`) · Node.js `NODE_V8_COVERAGE`](https://peps.python.org/pep-0669/)
  语言级低开销（`< 1%–2.5%` CPU）生产遥测原语：Java 使用 JFR `jdk.ClassLoad`（稳态设 `stackTrace=false`）替代会引发类表锁与数组分配抖动的 `Instrumentation.getAllLoadedClasses()`；Python 3.12+ 采用集成进自适应解释器的 [PEP 669 `sys.monitoring`](https://peps.python.org/pep-0669/) 淘汰慢十倍的 `sys.settrace`；Node.js 使用原生 [`NODE_V8_COVERAGE`](https://nodejs.org/api/cli.html#node_v8_coveragedir) 与 `v8.takeCoverage()`。
- [Minimal Images & Debloating Toolchains: Google Distroless (`Apache-2.0`) · Chainguard `apko` & `melange` (`Apache-2.0`) · MinToolkit `mint` (`Apache-2.0`) vs Canonical `chisel` (`AGPL-3.0`)](https://github.com/chainguard-dev/apko)
  构建期最小闭包首选 [`GoogleContainerTools/distroless`](https://github.com/GoogleContainerTools/distroless) 与 [`chainguard-dev/apko`](https://github.com/chainguard-dev/apko)（消除近九成 OS 臃肿 CVE 且输出确定性 SBOM）；运行期动态瘦身 [`mintoolkit/mint`](https://github.com/mintoolkit/mint)（原 DockerSlim，CNCF `Apache-2.0`）受限测试覆盖率，易误删冷路径库并破坏包管理收据。**商用闭源红线**：[`canonical/chisel`](https://github.com/canonical/chisel) 为 `AGPL-3.0`，严禁嵌入商业闭源 SaaS 后端服务！
- [Debloating Research Foundations: *SoK: Software Debloating* (`arXiv:2407.11259`) · *Cimplifier* (ESEC/FSE 2017, DOI `10.1145/3106237.3106271`) · *JShrink* (ESEC/FSE 2020, DOI `10.1145/3368089.3409738`) · *Confine* (RAID 2020, `arXiv:2008.05561`)](https://arxiv.org/abs/2407.11259)
  确立软件与容器裁剪三大铁律：纯动态删文件面临冷路径崩毁（如遗漏 `libnss_dns.so`）、黑盒排障困难与“删元数据造成扫描清零假象”缺陷；*JShrink* 揭示字节码裁剪须静动态类型结合；*Confine* 提供不删文件而通过静态提取 Syscall 白名单生成 `seccomp` 策略的正交减面路线。

### 漏洞优先级排序（EPSS / KEV / SSVC）与 VEX 标准化降噪（Layer 4 Prioritization & VEX）
- [Exploit Prediction & Scoring Specs: FIRST EPSS v4 (`first.org/epss`, FIRST Services ToS) · Jacobs et al. (EuroS&PW 2023, `arXiv:2302.14172`) · FIRST CVSS v4.0 Spec](https://www.first.org/epss/)
  [`EPSS v4`](https://www.first.org/epss/)（2025 年 3 月演进自 [`arXiv:2302.14172`](https://arxiv.org/abs/2302.14172) ~1,500 维特征框架并强化恶意软件/勒索遥测）预测未来 30 天内漏洞在野利用概率（区分 `epss` 绝对概率与 `percentile` 相对分位）。工程必须每日定时同步官方全量 gzip CSV（禁止热路径同步调 API），并严守 [FIRST Services Terms of Use](https://www.first.org/about/policies/terms)（保留版权署名，限防御性安全用途，禁止脱离产品转售原始数据集）。[`CVSS v4.0`](https://www.first.org/cvss/v4.0/specification-document) 显式区分 `CVSS-B`（默认最坏威胁假设）与 `CVSS-BT`（`E:A/P/U` 阶梯）。
- [Active Exploitation & Non-Compensatory Decision Tree: CISA KEV Catalog (Public Domain) & CISA SSVC Decision Tree](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)（8 个必填字段 + `knownRansomwareCampaignUse` `"Known"/"Unknown"` + `dueDate`）作为实锤在野利用底线（Floor），无视低 CVSS；[CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)（`Exploitation × Automatable × Technical Impact × Mission & Well-being` → `Act / Attend / Track* / Track`）取代存在“补偿掩蔽”缺陷的线性加权公式。
- [OpenVEX Ecosystem: `openvex/spec` · `openvex/go-vex` (`Apache-2.0`) · `openvex/vexctl` (`Apache-2.0`) & CISA VEX Minimum Requirements](https://github.com/openvex/spec)
  轻量级 JSON-LD VEX 标准（`not_affected` / `affected` / `fixed` / `under_investigation` 及 5 大标准 justification）；支持通过 `products[].subcomponents[]` 把子依赖 PURL 严格绑定在父容器/制品下防止全局误消警，并配合 `vexctl` 与 Sigstore 生成 OCI 1.1 Referrers 证明。
- [CycloneDX VDR/VEX & OASIS CSAF 2.0: `CycloneDX/cyclonedx-go` (`Apache-2.0`) · `gocsaf/csaf` (`Apache-2.0`) · `aquasecurity/trivy` (`Apache-2.0`) · `anchore/grype` (`Apache-2.0`)](https://github.com/gocsaf/csaf)
  [`CycloneDX 1.7`](https://cyclonedx.org/docs/1.7/json/) 严格区分内嵌全量资产台账 VDR 与独立 VEX，区分 `false_positive`（扫描器误识别）与 `not_affected + code_not_reachable`，并提供 `resolved_with_pedigree`；[`OASIS CSAF 2.0`](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)（`product_status` 带 `known_` 前缀 + `flags[].label`）由 `gocsaf/csaf`（`Apache-2.0`）提供 Go 生态官方解析；[`Trivy VEX`](https://trivy.dev/latest/docs/supply-chain/vex/) 与 `VEX Hub` 示范 `--vex` 显式顺序优先级与 OCI Referrers 自动发现。

### 无破坏性自动修复、依赖求解与升级影响分析（Layer 4 Guided Remediation）
- [Guided Remediation & Dependency Graph Resolution: `google/osv-scanner` (`Apache-2.0`) · `google/deps.dev` (`Apache-2.0`)](https://google.github.io/osv-scanner/experimental/guided-remediation/)
  Google 官方 `osv-scanner fix` 提出 `--strategy=in-place`（仅锁文件原位修补）、`--strategy=relax`（Relock and relax 直接依赖重算）与 `--strategy=override`（Maven `<dependencyManagement>` 覆写，可配 `--maven-fix-management`）三大策略及 `--upgrade-config`/`--min-severity`/`--max-depth` 过滤框架，底层依托 `deps.dev/util/resolve` 进行跨生态传递图求解；注意重锁会调用原生包管理器，必须进入 Tier 3 隔离沙箱执行。
- [Empirical Upgrade Impact: Ochoa, Degueule, Falleri & Vinju, *"Breaking bad? Semantic versioning and impact of breaking changes in Maven Central"* (EMSE 2022, DOI `10.1007/s10664-021-10052-y`)](https://doi.org/10.1007/s10664-021-10052-y)
  基于 *Maracas* 对约 120,000 次升级与 293,000 个客户端的实证研究：83.4% 遵守 SemVer，但即便包含破坏性变更也仅 ~7.9% 客户端实际调用到受影响符号（同时 16.6% 非 Major 更新暗藏破坏），奠定「`API Diff ∩ 第一方调用图` 放行 Safe Major」的核心依据。
- [Version Solving Algorithms: Natalie Weizenbaum (*PubGrub: Next-Generation Version Solving*) · `pubgrub-rs/pubgrub` (`MPL-2.0`)](https://github.com/dart-lang/pub/blob/master/doc/solver.md)
  CDCL 冲突驱动子句学习版本求解算法（驱动 Dart `pub` 与 Astral `uv`）；`pubgrub-rs` 为 `MPL-2.0` 文件级弱传染许可，修改源码须公开对应修改文件。
- [Lossless Code Refactoring & Updaters: `openrewrite/rewrite` (`Apache-2.0`) · `dependabot/dependabot-core` (`MIT`) vs `renovatebot/renovate` (`AGPL-3.0`)](https://github.com/openrewrite/rewrite)
  `OpenRewrite` 以 Lossless Semantic Tree（LST）实现类型感知且保留格式/注释的 XML 与源码迁移（注意区分 Apache-2.0 开源核心与 Moderne 商业专有 Recipes）；`dependabot-core` 已重授权为 `MIT` 可安全隔离复用；**商业红线**：`renovatebot/renovate` 为 `AGPL-3.0` 强网络传染，严禁嵌入商业闭源 SaaS 后端。
- [Ecosystem API Diff Engines: `siom79/japicmp` (`Apache-2.0`) · `revapi/revapi` (`Apache-2.0`) · `golang.org/x/exp/apidiff` (`BSD-3-Clause`) · `mkdocstrings/griffe` (`ISC`) · `obi1kenobi/cargo-semver-checks` (`MIT OR Apache-2.0`)](https://pkg.go.dev/golang.org/x/exp/apidiff)
  五大语言生态二进制/AST 破坏性变更检测底座；特别警惕**不要**把 `golang.org/x/exp/apidiff`（BSD-3-Clause）与 OpenJDK 同名 `apidiff`（`GPL-2.0 + Classpath Exception`）混淆。

### 恶意包、供应链投毒检测与发布防火墙（Ch 05 · Lesson 0015）
- [Taxonomies & Empirical Studies: Ohm et al. (DIMVA 2020, *Backstabber's Knife Collection*, `arXiv:2005.09535`) · Ladisa et al. (IEEE S&P 2023, *SoK*, `arXiv:2204.04008`) · Spracklen et al. (USENIX Security, `arXiv:2406.10279`)](https://arxiv.org/abs/2005.09535)
  实证确认 **56%** 恶意包在安装期（`preinstall`/`postinstall`/`setup.py`）触发且无 CVE 编号；系统分类 Typosquatting/Combosquatting、Slopsquatting（LLM 幻觉 19.7%）、Dependency Confusion、Account Takeover 与构建产物夹带五大载体。
- [OpenSSF Supply Chain Malware Infrastructure: `ossf/malicious-packages` (`Apache-2.0`) · `ossf/package-analysis` (`Apache-2.0`) · `ossf/package-feeds` (`Apache-2.0`)](https://github.com/ossf/malicious-packages)
  `ossf/malicious-packages` 以 OSV `MAL-*` 格式汇聚已确认恶意包情报（冷启动必接底座）；`package-feeds` 归一化多生态实时更新流；`package-analysis` 示范基于 **gVisor** 用户态内核的 `strace`/`pcap` 隔离引爆沙箱架构。
- [Realtime Registry Feeds (2025 Breaking Change): npm `replicate.npmjs.com/registry/_changes` (2025-05-29 Deprecation) · PyPI `changelog_since_serial` & PEP 691](https://github.blog/changelog/2025-02-27-changes-and-deprecation-notice-for-npm-replication-apis/)
  npm 自 2025-05-29 起正式废弃 CouchDB `feed=continuous`、`include_docs=true` 与 `heartbeat` 参数（`skimdb` 301 跳转），须改用轻量化 `GET /registry/_changes?since=<seq>&limit=<n>` 增量拉取序列并异步下载元数据与 Tarball。
- [Static Engines, Cooldowns & Commercial License Minefields: `VirusTotal/yara-x` (`BSD-3-Clause`) · `oxc-project/oxc` (`MIT`) vs `DataDog/guarddog` (`Apache-2.0` + Semgrep `LGPL-2.1`/Rules v1.0) · `chainguard-dev/malcontent` (`Apache-2.0` + `ELv2`/`DRL 1.1`)](https://github.com/VirusTotal/yara-x)
  纯商用 AST/特征底座首选 `oxc` + `Tree-sitter`（`MIT`）+ `yara-x`（`BSD-3-Clause`）；跨生态冷却期规范涵盖 `pnpm` (`minimumReleaseAge` 分钟)、`npm` (`min-release-age` 天)、`uv` (`exclude-newer`)、`pip` (`--uploaded-prior-to`)。**商用排雷**：严禁将 GuardDog 底层 Semgrep 规则或 Malcontent 打包的 Elastic `ELv2` / Nextron `DRL 1.1` 第三方规则直接塞入商业闭源 SaaS，必须剥离替换为自有 Capability Diff 规则；交付侧参考 Socket Firewall (`sfw`) 与 `sca_check_package` MCP 实现安装前零落盘阻断。

### 代码片段同源检测与无源码二进制 SCA（Ch 05 · Lesson 0016）
- [Snippet Fingerprinting & Nested Attribution: Schleimer, Wilkerson & Aiken (SIGMOD 2003, *Winnowing*, DOI `10.1145/872757.872770`) · Kim, Woo & Lee (ICSE 2021, *CENTRIS*, DOI `10.1109/ICSE43902.2021.00083`, `WOOSEUNGHOON/Centris-public`)](https://doi.org/10.1109/ICSE43902.2021.00083)
  *Winnowing* 提供 $t = w + k - 1$ 共享切片 100% 检出数学保障并支持 `Zero-Source-Upload` 客户端单向哈希；*CENTRIS* 结合函数级 **TLSH**、跨仓冗余消除与最早提交时间戳（Birth-Time Attribution）彻底解决嵌套拷贝误报爆炸与归属倒置问题。
- [Binary-to-Source SCA Foundations: Duan et al. (CCS 2017, *OSSPolice*, DOI `10.1145/3133956.3134048`) · Feng et al. (ASE 2019, *B2SFinder*, DOI `10.1109/ASE.2019.00100`) · Xu et al. (CCS 2017, *Gemini*, DOI `10.1145/3133956.3134018` / `arXiv:1708.06525`)](https://arxiv.org/abs/1708.06525)
  确立无源码二进制三层特征金字塔：**Layer A** 符号/横幅 &rarr; **Layer B** 穿透 `strip -s` 的 `.rodata` 高 IDF 唯一报错串与魔数常量池 &rarr; **Layer C** 跨架构 ACFG 控制流图向量嵌入，并在 CycloneDX 1.7 `evidence.identity` 显式输出 `confidence` 置信度。
- [Binary & LSH Permissive Stack vs GPL Redlines: `lief-project/LIEF` (`Apache-2.0`) · `ReFirmLabs/binwalk` v3 (`MIT`) · `trendmicro/tlsh` (`Apache-2.0 OR BSD-3`) · `capstone` (`BSD-3`) · `ghidra` (`Apache-2.0`) vs `scanoss` (`GPL-2.0`) · `ossf/cve-bin-tool` (`GPL-3.0-or-later`) · `radare2` (`LGPL-3.0`)](https://github.com/lief-project/LIEF)
  明确商业闭源栈边界：采用 Pure Go 自研 Winnowing/TF-IDF 核心 + 宽松协议解析/解包/模糊哈希/反编译底座；严禁将 `scanoss/wfp`、`scanoss/engine`（`GPL-2.0`）与 `ossf/cve-bin-tool`（`GPL-3.0-or-later`）嵌入闭源产品，规避 `radare2`（`LGPL-3.0`）静态链接负担。

### AI-BOM 统一建模、OCI 模型打包与模型合规（Ch 05 · Lesson 0017）
- [AI-BOM Dual Standards: CycloneDX 1.7 ML-BOM (`bom-1.7.schema.json`) & SPDX 3.0.1 AI/Dataset Profiles (`spdx/spdx-3-model`)](https://cyclonedx.org/schema/bom-1.7.schema.json)
  CycloneDX 1.7 规定 `machine-learning-model` 挂载 `modelCard`（MUST NOT 用于非模型组件）并指向 `data` 组件；SPDX 3.0.1 在 `@graph` 中以 `ai_AIPackage` 和 `dataset_DatasetPackage` 搭配标准 `Core_Relationship`（`trainedOn` / `testedOn`）精确建模数据血缘。
- [Model Identifiers & Threat Scope: `pkg:huggingface` (ECMA-427 `package-url/purl-spec`) & OWASP LLM03:2025 Supply Chain](https://genai.owasp.org/)
  `pkg:huggingface/<namespace>/<name>@<commit-hash>` 严格规定 `namespace`/`name` 区分大小写而 Commit Hash 转小写，生产严禁 `@main` 可变引用；对齐 OWASP `LLM03:2025` 将基座、LoRA、数据集与推理框架纳入统一 Layer 2 IR 图谱。
- [Zero-Execution Extractors, OCI Model Packaging & Non-OSI Governance: CNCF ModelPack (`modelpack/model-spec`, `Apache-2.0`) · KitOps (`kitops-ml/kitops`, `Apache-2.0`) · `ggml-org/ggml` (GGUF)](https://github.com/modelpack/model-spec)
  只读解析 `adapter_config.json`（`base_model_name_or_path`）、GGUF Header（`general.license`）、Safetensors `__metadata__` 及 OCI ModelPack/`Kitfile`（严禁 `torch.load()`）；沿血缘递归校验 `CC-BY-NC-4.0` 污染、Llama 3（700M MAU / `"Built with Llama"`）、OpenRAIL-M 禁令及 2025-08-02 生效的 EU AI Act Art. 53(1)(d) 训练数据摘要。

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
- **模型反序列化安全与 MCP/Agent 供应链治理（Ch 05 · Lesson 0018–0019）**：`Lesson 0015–0017` 及 `Ref 06` 第 01–04 节已补齐恶意包投毒防御、Winnowing/TLSH/CENTRIS 同源与三层二进制 SCA、以及 AI-BOM 统一建模（CycloneDX 1.7 ML-BOM / SPDX 3.0.1 / `pkg:huggingface` / ModelPack / 非 OSI 与 EU AI Act 合规）；待后续在 0018–0019 补齐 Pickle RCE vs Safetensors 操作码扫描与 MCP/Agentic AI (ASI04) 治理。
- **静态、运行时可达性与优先级/VEX/自动修复协同闭环（Ch 04 · Lessons 0011–0014 已全面收口）**：第 11–13 课已覆盖静态调用图（RTA/VTA/Java/JS/Python）、运行时融合/容器裁剪与 EPSS/KEV/SSVC/VEX 协同降噪；第 14 课及 Ref 05 第 05 节已补齐 OSV-Scanner v2 Guided Remediation（`in-place/relock/override`）、`deps.dev/util/resolve`、PubGrub（`MPL-2.0`）、Ochoa et al. (EMSE 2022) `API Diff ∩ Call Graph` 实证与五大生态 Diff 底座、OpenRewrite LST（`Apache-2.0`）、`dependabot-core`（`MIT`）vs `Renovate`（`AGPL-3.0`）红线及双触点防 PR 风暴闭环。
- **多语言依赖解析器（Lockfile vs Build-time）、四大引擎、镜像制品与多触点采集（Ch 02 已全面收口）**：已于第 3 课补齐 Java/多语言静态 vs 构建期实证研究（Balliu et al., IEEE S&P 2023 `arXiv:2303.11102`）与五大生态解析算法规范，于第 4 课补齐 OSV-SCALIBR / Syft / cdxgen / ORT 接口与融合架构对比，于第 5 课补齐 OCI 镜像分层合成（`.wh.` / `.wh..wh..opq`）、OS 数据库及 Java/Go/Rust 二进制提取，并于第 6 课及 Ref 03 Section 06 补齐 Agentic 时代本地三模入口（MCP + Hook + LSP / `arXiv:2406.10279`）、GitHub Dependency Review、CAS 去重与 Dependency-Track v5（Hyades）事件驱动持续重算架构。
- **Layer 3 情报底座、版本引擎、离线分发与许可合规（Phase 1 · Ch 03 已全面收口）**：已于第 7–10 课及 Ref 04 完整覆盖 OSV v1.7.0 与 License Gate、六大生态版本排序与 Backport 隔离、Trivy `bbolt` / Grype v6 `SQLite Handle+Blob` / OCI 签名逻辑增量与 `atomic.Pointer` / `RoaringBitmap` 内存索引，以及 SPDX v3.0.1 Annex B AST、三维传染性矩阵、OSADL/FSF 双向兼容判定与 `THIRD-PARTY-NOTICES` 自动化闭环。
