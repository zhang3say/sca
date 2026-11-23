/* ==========================================================================
   Reusable Multi-Ecosystem Dependency Resolution Simulator & Pitfall Lab
   Zero-dependency vanilla JS shared across Layer 1 / Layer 2 lessons.
   Usage:
     <section class="widget-panel" data-widget="dep-lab">
       <script type="application/json" class="dep-lab-data">{ ... }</script>
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

  const DEFAULT_SCENARIOS = [
    {
      id: "maven",
      tabLabel: "Maven · Nearest vs BOM",
      controlLabel: "切换 Maven 裁决情境",
      modes: [
        {
          id: "nearest",
          label: "默认菱形冲突（Nearest Definition）",
          graphTitle: "pom.xml 传递依赖树 · 深度裁决对比",
          graphHeadNote: "短路径胜出（与版本号高低无关）",
          inputSnippet: [
            "app (root)",
            "├── mod-a:1.0  (深度 1)",
            "│   └── lib-x:1.0.0  [深度 2 · 含 CVE-2024-XXXX]",
            "└── mod-b:1.0  (深度 1)",
            "    └── mod-d:1.0  (深度 2)",
            "        └── lib-x:2.1.0  [深度 3 · 已修复]",
            "",
            "# 静态单文件解析器视角：",
            "# 仅见直接声明 mod-a / mod-b，或只扫到 ${lib.version} 占位符",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "单文件 pom.xml 静态解析：完全盲区 / 误猜最新版",
          naiveNote:
            "只读根 pom.xml 根本看不到传递边的 lib-x；若用粗糙的全局最高版猜想，会误判成 2.1.0（安全），从而对生产打包的 1.0.0 漏洞产生致命漏报。",
          realStatus: "warn",
          realTitle: "Maven 真实裁决：lib-x @ 1.0.0（路径深度 2 < 3）",
          realNote:
            "Apache Maven 采取「Nearest Definition（最短路径优先）」，完全不比较语义版本号大小！虽然 mod-b 传递引入了修复版 2.1.0，但因为路径更长，最终打入 WAR/JAR 的反而是带漏洞的 1.0.0。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "Tier 2 需通过 deps.dev / 私有 Nexus 拉取父 POM 与全部传递 POM 构建有效图（Effective POM），并在 snapshot_edges 标记被调解裁剪（omitted）的竞态边。",
        },
        {
          id: "first-decl",
          label: "等深并列（First-Declaration Wins）",
          graphTitle: "pom.xml 等深度冲突 · XML 声明顺序决定生死",
          graphHeadNote: "深度均为 2 时，谁写在前面谁胜出",
          inputSnippet: [
            "<dependencies>",
            "  <!-- 声明 1（先出场）：mod-a 传递引入 lib-x:1.0.0 (CVE) -->",
            "  <dependency><groupId>com.example</groupId><artifactId>mod-a</artifactId><version>1.0</version></dependency>",
            "  <!-- 声明 2（后出场）：mod-c 传递引入 lib-x:2.1.0 (Fixed) -->",
            "  <dependency><groupId>com.example</groupId><artifactId>mod-c</artifactId><version>1.0</version></dependency>",
            "</dependencies>",
            "",
            "# 若仅将 mod-c 调整到 mod-a 上方，裁决结果瞬间反转！",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "无序集合解析器：丢失 XML 顺序导致随机结果",
          naiveNote:
            "若解析器把 <dependencies> 读入无序 Hash Map / Set 后再求版本，遇到同深度冲突就无法复现 Maven 的「第一声明优先」确定性规则。",
          realStatus: "warn",
          realTitle: "Maven 真实裁决：lib-x @ 1.0.0（声明序号 #1 胜出）",
          realNote:
            "在相同树深（Depth = 2）下，Maven 按 pom.xml 中出现顺序仲裁，先声明的 mod-a 路径胜出，导致 1.0.0 漏洞版本生效。调换两段 XML 位置即可逆转结果。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "解析器必须保留有向边序号（declaration_order），在静态模拟求解（Tier 2）时严格按 BFS + 声明顺序复刻 Maven 调解器。",
        },
        {
          label: "启用 <dependencyManagement> BOM Import",
          id: "bom",
          graphTitle: "Effective POM · BOM 优先级压倒调解规则",
          graphHeadNote: "BOM 属于 dependencyManagement，最高优先级",
          inputSnippet: [
            "<dependencyManagement>",
            "  <dependencies>",
            "    <dependency>",
            "      <groupId>com.example</groupId>",
            "      <artifactId>platform-bom</artifactId>",
            "      <version>2026.1</version>",
            "      <type>pom</type><scope>import</scope>",
            "      <!-- 内部锁定 lib-x = 2.1.0 -->",
            "    </dependency>",
            "  </dependencies>",
            "</dependencyManagement>",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "忽略 parent / import BOM 的扫描器：误报 1.0.0 高危",
          naiveNote:
            "不展开 <scope>import</scope> BOM 与父 POM 属性插值（${lib-x.version}）的静态工具，会遗漏 BOM 的强制覆写，或因变量未展开导致 PURL 版本为空。",
          realStatus: "ok",
          realTitle: "Maven 真实裁决：lib-x @ 2.1.0（BOM 强制覆写生效）",
          realNote:
            "依据 Maven 官方规则，dependencyManagement（含导入的 BOM）优先级高于传递依赖调解。无论 mod-a 路径多近，最终均统一锁定为修复版 2.1.0。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "Tier 2 注册表求解必须递归下载 parent POM 与 <scope>import</scope> BOM（Apache-2.0 的 OSV-SCALIBR / deps.dev Maven 求解器即采用此无执行方案）。",
        },
      ],
    },
    {
      id: "gradle",
      tabLabel: "Gradle · Highest & 动态范围",
      controlLabel: "切换 Gradle 配置模式",
      modes: [
        {
          id: "highest",
          label: "默认策略（Highest-Version-Wins）",
          graphTitle: "Gradle Resolution · 同拓扑与 Maven 相反裁决",
          graphHeadNote: "跨全图选最高版本，无视路径深浅",
          inputSnippet: [
            "dependencies {",
            "  implementation('com.example:mod-a:1.0') // -> lib-x:1.0.0",
            "  implementation('com.example:mod-b:1.0') // -> mod-d -> lib-x:2.1.0",
            "}",
            "",
            "// 注意：Gradle 会将两条路径的候选版本统一排序：",
            "// max(1.0.0, 2.1.0) => 2.1.0（全局静默升级）",
          ].join("\n"),
          naiveStatus: "warn",
          naiveTitle: "套用 Maven 逻辑或只扫 build.gradle：错判成 1.0.0 漏洞",
          naiveNote:
            "用正则扫 build.gradle 既看不到传递依赖，也搞不清 Gradle 默认会把所有子图汇聚后再按最高版本淘汰旧版；若混用 Maven 规则更会完全算反。",
          realStatus: "ok",
          realTitle: "Gradle 真实裁决：lib-x @ 2.1.0（最高版本胜出）",
          realNote:
            "哪怕 1.0.0 的路径更短（Depth 2 vs 3），Gradle 仍全局对比候选集并挑选最高版本 2.1.0。但反过来：如果某传递包恶意抬高版本号，也会被静默拉入构建！",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "有 gradle.lockfile 时直读 Tier 1 锁文件；无锁文件且存在 resolutionStrategy / constraints / 插件动态改写时，需升阶到 Tier 3 CI Hook 或沙箱。",
        },
        {
          id: "dynamic",
          label: "动态范围声明（31.+ / [1.0, 2.0)）",
          graphTitle: "build.gradle 动态版本漂移陷阱",
          graphHeadNote: "同一份源码，今天扫安全 ≠ 明天构建安全",
          inputSnippet: [
            "dependencies {",
            "  implementation 'com.google.guava:guava:31.+'",
            "  // 也可能是 [31.0-jre, 32.0-jre)",
            "  // 甚至通过 ext.guavaVer = findProperty(...) 动态拼接",
            "}",
            "",
            "// 11 月 19 日扫描解析 -> 31.1-jre",
            "// 11 月 20 日上游发版/被投毒 -> 31.99-jre（构建自动拉取）",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "把范围表达式当成版本写死在 PURL：匹配彻底失效",
          naiveNote:
            "把 pkg:maven/com.google.guava/guava@31.+ 直接送进 Layer 3 漏洞匹配引擎，由于 '31.+' 不是合法具体版本，SemVer/Maven 比较器直接报错或静默跳过。",
          realStatus: "danger",
          realTitle: "Gradle 真实裁决：非确定性（随构建时刻仓库索引漂移）",
          realNote:
            "没有 lockfile 时，每次构建都会向 Maven Central / 私有仓拉取匹配范围的最新版本。昨天的绿灯扫描，无法保证今天 CI 打出的制品没有拉入新漏洞或投毒包。",
          irStatus: "warn",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "snapshot_edges.constraint_expr 记录原始声明范围 '31.+'，同时在扫描报告显式发出「非确定性构建风险（Missing Lockfile）」策略门禁告警。",
        },
        {
          id: "lockfile",
          label: "启用 gradle.lockfile 确定性锁定",
          graphTitle: "gradle.lockfile · Tier 1 零执行精确快照",
          graphHeadNote: "./gradlew dependencies --write-locks 生成",
          inputSnippet: [
            "# This is a Gradle generated file for dependency locking.",
            "com.example:mod-a:1.0=compileClasspath,runtimeClasspath",
            "com.example:mod-b:1.0=compileClasspath,runtimeClasspath",
            "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath",
            "empty=annotationProcessor,testCompileClasspath",
          ].join("\n"),
          naiveStatus: "warn",
          naiveTitle: "只认 build.gradle 而忽视 gradle.lockfile：丢失确定性真值",
          naiveNote:
            "不少早期 SCA 仅关注 build.gradle / pom.xml，却跳过 gradle.lockfile，导致面对动态范围和复杂 DSL 依然束手无策。",
          realStatus: "ok",
          realTitle: "Gradle 真实裁决：精确锁定 guava @ 31.1-jre（零构建执行）",
          realNote:
            "一旦仓库提交了 gradle.lockfile，Gradle 构建期会强制校验并锁定文件内声明的精确版本（偏离即 fail build），Layer 1 无需启动高危 JVM 即可实现近 100% 确定性提取。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "高优先级走 Tier 1 解析 gradle.lockfile 并利用末尾配置名（compileClasspath vs testCompileClasspath）精准映射 L2 IR 的 scope（required vs excluded）。",
        },
      ],
    },
    {
      id: "node",
      tabLabel: "npm v3 vs pnpm · 多版本共存",
      controlLabel: "切换 Node.js 包管与提取方式",
      modes: [
        {
          id: "npm-hoist",
          label: "npm v3（package-lock.json 扁平提升）",
          graphTitle: "npm v7+ lockfileVersion: 3 · 扁平提升与嵌套共存",
          graphHeadNote: "同一组件多版本合法共存于磁盘不同层级",
          inputSnippet: [
            "repo-root/",
            "├── node_modules/",
            "│   └── lodash/                   [4.17.21 · 安全，被提升到根]",
            "└── packages/",
            "    └── legacy/",
            "        └── node_modules/",
            "            └── lodash/           [4.17.15 · 含高危 CVE，局部嵌套]",
            "",
            "// package-lock.json (lockfileVersion: 3) packages 字典：",
            '  "node_modules/lodash": { "version": "4.17.21" }',
            '  "packages/legacy/node_modules/lodash": { "version": "4.17.15" }',
          ].join("\n"),
          naiveStatus: "warn",
          naiveTitle: "只扫描根目录或按 PURL 强行去重：吞掉嵌套漏洞路径",
          naiveNote:
            "若扫描器错误地以为每个项目只能有一个 lodash（类似 Java/Go 单版本模型），或用 Lesson 0002 反面教材按 (snapshot_id, purl) 合并，将无法定位应修改哪个工作区子包。",
          realStatus: "warn",
          realTitle: "npm 真实行为：双版本同时生效 + 存在幽灵依赖风险",
          realNote:
            "Node.js 按就近目录查找 require('lodash')：api 命中根 4.17.21，legacy 命中嵌套 4.17.15。此外若 api 未声明某个仅被提升到根的传递包（如 debug），代码也能意外 import 成功（幽灵依赖）。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "解析 package-lock.json v3 的 packages 字典路径前缀，在 snapshot_nodes 为两个实例分别创建独立 bom-ref，把磁盘路径写入 occurrences[]，同时提取 dev:true 映射为 scope=excluded。",
        },
        {
          id: "pnpm",
          label: "pnpm（.pnpm 虚拟仓 + Symlink 严格隔离）",
          graphTitle: "pnpm-lock.yaml · importers 与 snapshots 拓扑",
          graphHeadNote: "彻底消灭幽灵依赖，精准还原 workspace:* 边",
          inputSnippet: [
            "lockfileVersion: '9.0'",
            "importers:",
            "  packages/api:",
            "    dependencies:",
            "      lodash: { specifier: ^4.17.21, version: 4.17.21 }",
            "  packages/legacy:",
            "    dependencies:",
            "      lodash: { specifier: 4.17.15, version: 4.17.15 }",
            "# packages: 存哈希元数据；snapshots: 存解析后依赖边图",
            "snapshots:",
            "  lodash@4.17.21: {}",
            "  lodash@4.17.15: {}",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "不认识 pnpm-lock.yaml v6/v9 新结构：全量漏扫 Monorepo",
          naiveNote:
            "如果只支持旧版 dependencies 嵌套格式而不支持 pnpm 的 importers（工作区入口）+ snapshots（有向图节点），会导致整个 Monorepo 内部服务依赖关系彻底断裂。",
          realStatus: "ok",
          realTitle: "pnpm 真实行为：严格按软链隔离，每个 importer 边清晰可溯",
          realNote:
            "pnpm 通过 node_modules/.pnpm 集中存放实包并用符号链接精确映射，杜绝幽灵依赖。importers 与 snapshots 的分离结构几乎天然同构于 Layer 2 IR 的节点与边表。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "Tier 1 直接解析 pnpm-lock.yaml，将每个 importer 建为 application 子节点，将 snapshots 建为组件节点，workspace:* 协议映射为 contains/depends_on 内部边。",
        },
      ],
    },
    {
      id: "python",
      tabLabel: "Python · PEP 508/751 Markers",
      controlLabel: "选择目标部署环境（模拟 Marker 求值）",
      modes: [
        {
          id: "linux-312",
          label: "生产目标：Linux + Python 3.12（忽略 dev）",
          graphTitle: "PEP 751 pylock.toml / uv.lock · 按目标环境剪枝",
          graphHeadNote: "通用锁文件同时包含跨 OS / 跨 Py 版本的条件分支",
          inputSnippet: [
            "# pylock.toml (PEP 751 标准语法)",
            'lock-version = "1.0"',
            'environments = ["sys_platform == \'linux\'", "sys_platform == \'win32\'"]',
            'dependency-groups = ["dev"]',
            "",
            "[[packages]]",
            'name = "requests"',
            'version = "2.32.3"                             # 无 marker -> 通用必装',
            "[[packages]]",
            'name = "colorama"',
            'version = "0.4.6"',
            'marker = "sys_platform == \'win32\'"             # 仅 Windows',
            "[[packages]]",
            'name = "importlib-metadata"',
            'version = "4.13.0"',
            'marker = "python_version < \'3.10\'"             # 仅旧版 Python',
            "[[packages]]",
            'name = "pytest"',
            'version = "8.3.0"',
            'marker = "\'dev\' in dependency_groups"          # 仅 dev 依赖组',
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "反模式（忽略 Marker 全量入库）：报出 3 条虚假漏洞/资产",
          naiveNote:
            "不求值 PEP 508 Environment Markers 的扫描器会把 Windows 专用的 colorama、旧版本才装的 importlib-metadata 与开发期的 pytest 全部当成生产运行时资产上报，触发严重误报噪音。",
          realStatus: "ok",
          realTitle: "真实有效清单（仅 1 个生产组件）：requests@2.32.3",
          realNote:
            "在 Linux + Python 3.12 生产环境下：colorama（仅 win32）、importlib-metadata（仅 py<3.10）在安装阶段根本不会被下载；pytest 属于 dev 组应标为 scope=excluded。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "在 Layer 1 解析 uv.lock / poetry.lock / pylock.toml 时接入目标环境档案（Target Env Profile），将不匹配的分支裁剪或标为 optional/excluded，而不是粗暴全删。",
        },
        {
          id: "win-38",
          label: "切换目标：Windows + Python 3.8（旧产线）",
          graphTitle: "同一份锁文件在不同运行环境下产出不同 SBOM",
          graphHeadNote: "验证「环境上下文感知」对 SCA 准确率的决定性影响",
          inputSnippet: [
            "# 同一份 pylock.toml，切换目标运行环境参数：",
            "# sys_platform = 'win32', python_version = '3.8', groups = []",
            "",
            '1. requests@2.32.3           -> 匹配 (无 marker，通用必装)',
            '2. colorama@0.4.6            -> 匹配 (sys_platform == "win32")',
            '3. importlib-metadata@4.13.0 -> 匹配 (python_version < "3.10")',
            '4. pytest@8.3.0              -> 剪枝 ("dev" not in dependency_groups)',
          ].join("\n"),
          naiveStatus: "warn",
          naiveTitle: "若锁死单环境（如扫描器自身 Linux 容器）将漏报 colorama 等组件",
          naiveNote:
            "如果在 Linux 容器里直接跑 pip list 反扫，或者把扫描机自身的 OS/Python 版本当成所有项目的默认值，就会完全漏掉客户端 Windows/macOS 或 Python 3.8 运行的依赖。",
          realStatus: "ok",
          realTitle: "真实有效清单（3 个生产组件）：requests + colorama + importlib-metadata",
          realNote:
            "同一个仓库代码与同一份 uv.lock，仅仅因为交付目标不同（Windows + Py3.8），生效依赖图就多了 2 个生产包。PEP 751 明确内置 environments 元数据来支持确定性多环境求解。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "支持在扫描任务参数传入 target_env（os / arch / python_version）；缺省未指定时对条件依赖保留全量并标注 env_marker 条件，供 L4 降噪区分。",
        },
      ],
    },
    {
      id: "go",
      tabLabel: "Go · MVS 与 go.sum 幽灵陷阱",
      controlLabel: "切换 Go 解析数据源与策略",
      modes: [
        {
          id: "mvs-gomod",
          label: "正确做法：解析 go.mod（MVS 最小版本选择）",
          graphTitle: "go.mod MVS 算法 · 不追新、不凭空猜测",
          graphHeadNote: "选择满足所有 require 约束的最低版本",
          inputSnippet: [
            "// 主模块 go.mod (go 1.22，经 MVS 裁决后落盘结果)",
            "require (",
            "  example.com/mod-a v1.0.0 // 其 go.mod 要求 x/net v0.17.0 (含 CVE)",
            "  example.com/mod-b v1.2.0 // 其 go.mod 要求 x/net v0.23.0 (已修复)",
            ")",
            "require golang.org/x/net v0.23.0 // indirect (MVS 裁决结果)",
            "",
            "// 注意：Go Proxy 此时最新版为 v0.30.0；未 tidy 的 go.sum 残留 v0.15.0/v0.17.0",
          ].join("\n"),
          naiveStatus: "warn",
          naiveTitle: "用 SemVer 猜最新 v0.30.0，或盲信旧边 v0.17.0：双向失真",
          naiveNote:
            "传统按 npm/Cargo「取最新兼容版」思维去猜 Go 代理最新版 v0.30.0 是错的；反之如果只看 mod-a 的 v0.17.0 而不全局求 max(min_required)，又会误报漏洞。",
          realStatus: "ok",
          realTitle: "Go MVS 真实裁决：golang.org/x/net @ v0.23.0（已修复）",
          realNote:
            "Russ Cox 设计的 MVS 严格选择「同时满足所有上游 require 最低约束的最小版本」：max(v0.17.0, v0.23.0) = v0.23.0，绝不会自动跳去 v0.30.0（除非显式 go get -u）。",
          irStatus: "ok",
          irTitle: "Layer 1 → L2 IR 落地要求",
          irNote:
            "Go 1.17+ 主 go.mod 已显式收录全部构建及测试所需的间接依赖（// indirect），Tier 1 直接解析 go.mod（配合 replace/exclude）即可得准；若要剔除仅测试期依赖，可由 Tier 4 读取编译产物 debug.BuildInfo。",
        },
        {
          id: "gosum-trap",
          label: "经典反模式：误将 go.sum 当作 Lockfile 扫描",
          graphTitle: "go.sum 幽灵误报（Ghost CVE）解剖",
          graphHeadNote: "go.sum 是加密校验和日志，不是依赖清单！",
          inputSnippet: [
            "# go.sum 内容（append-only 校验和缓存记录）",
            "golang.org/x/net v0.15.0 h1:...           # 半年前升级前残留（含 3 个高危 CVE）",
            "golang.org/x/net v0.15.0/go.mod h1:...    ",
            "golang.org/x/net v0.17.0 h1:...           # mod-a 的 go.mod 触发校验（含 1 个 CVE）",
            "golang.org/x/net v0.17.0/go.mod h1:...    ",
            "golang.org/x/net v0.23.0 h1:...           # 【唯一真实编入二进制的版本】",
            "golang.org/x/net v0.23.0/go.mod h1:...    ",
          ].join("\n"),
          naiveStatus: "danger",
          naiveTitle: "扫描 go.sum 的结果：同时上报 v0.15.0 / v0.17.0 / v0.23.0",
          naiveNote:
            "这是商业 SCA 最容易被 Go 研发团队嘲笑的事故：因为团队升级过依赖却没运行 go mod tidy，或者 MVS 计算过程下载过旧版本的 go.mod 验签，导致 go.sum 里躺着早已不用的 v0.15.0 与 v0.17.0——扫 go.sum 直接炸出一堆根本不在二进制里的幽灵高危 CVE！",
          realStatus: "ok",
          realTitle: "真实编译产物（go list -m all）：仅包含 v0.23.0",
          realNote:
            "Go 官方文档明确指出 go.sum 仅用于对照 sum.golang.org 防止包内容被篡改，对版本解析零语义影响。v0.15.0 与 v0.17.0 压根没有参与编译。",
          irStatus: "danger",
          irTitle: "架构红线：禁止将 go.sum 作为 L2 IR 组件节点输入",
          irNote:
            "Layer 1 提取器只应从 go.mod（或编译产物 debug.BuildInfo）生成 snapshot_nodes；go.sum 最多只能用来辅助做完整性核验或可疑篡改旁路告警。",
        },
      ],
    },
  ];

  function initDepLab(container) {
    let scenarios = DEFAULT_SCENARIOS;
    const dataEl = container.querySelector("script.dep-lab-data");
    let title = "交互实验室：5 大生态依赖裁决真相与 Layer 1 误判复现";
    let intro = "依次切换下方 5 个生态场景与解析开关，对比「天真静态解析」与「真实包管理器裁决」之间的版本落差与误报/漏报成因：";

    if (dataEl && dataEl.textContent.trim()) {
      try {
        const parsed = JSON.parse(dataEl.textContent);
        if (parsed.title) title = parsed.title;
        if (parsed.intro) intro = parsed.intro;
        if (Array.isArray(parsed.scenarios) && parsed.scenarios.length > 0) {
          scenarios = parsed.scenarios;
        }
      } catch (_) {
        // Fallback to DEFAULT_SCENARIOS
      }
    }

    const state = {
      scenarioIdx: 0,
      modeIdx: 0,
    };

    function render() {
      const scenario = scenarios[state.scenarioIdx] || scenarios[0];
      const modes = scenario.modes || [];
      const mode = modes[state.modeIdx] || modes[0];

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(title)}</h3>
          <div class="widget-status">场景 ${state.scenarioIdx + 1} / ${scenarios.length} · ${escapeHtml(scenario.tabLabel)}</div>
        </div>
        <p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(intro)}</p>
        <div class="dep-lab-tabs">
      `;

      scenarios.forEach((sc, idx) => {
        html += `
          <button type="button" class="dep-tab-btn ${idx === state.scenarioIdx ? "active" : ""}" data-sc="${idx}">
            ${escapeHtml(sc.tabLabel)}
          </button>
        `;
      });

      html += `</div>`;

      if (modes.length > 0) {
        html += `<div class="dep-lab-controls"><span class="dep-lab-ctrl-label">${escapeHtml(scenario.controlLabel || "切换解析场景")}：</span>`;
        modes.forEach((m, mIdx) => {
          html += `
            <button type="button" class="dep-toggle-btn ${mIdx === state.modeIdx ? "active" : ""}" data-mode="${mIdx}">
              ${escapeHtml(m.label)}
            </button>
          `;
        });
        html += `</div>`;
      }

      html += `
        <div class="dep-lab-grid">
          <div class="dep-graph-box">
            <div class="dep-graph-head">
              <span>${escapeHtml(mode.graphTitle)}</span>
              <span style="color:var(--ink-muted);font-weight:400;">${escapeHtml(mode.graphHeadNote || "")}</span>
            </div>
            <pre class="dep-tree-pre"><code>${escapeHtml(mode.inputSnippet)}</code></pre>
          </div>
          <div class="dep-compare-cards">
            <div class="dep-verdict-box ${escapeHtml(mode.naiveStatus || "warn")}">
              <div class="dep-verdict-label">1. 天真静态解析器（常见扫描坑）</div>
              <div class="dep-verdict-main">${escapeHtml(mode.naiveTitle)}</div>
              <p class="dep-verdict-note">${escapeHtml(mode.naiveNote)}</p>
            </div>
            <div class="dep-verdict-box ${escapeHtml(mode.realStatus || "ok")}">
              <div class="dep-verdict-label">2. 生态真实裁决（构建/运行时真相）</div>
              <div class="dep-verdict-main">${escapeHtml(mode.realTitle)}</div>
              <p class="dep-verdict-note">${escapeHtml(mode.realNote)}</p>
            </div>
            <div class="dep-verdict-box ${escapeHtml(mode.irStatus || "ok")}">
              <div class="dep-verdict-label">3. 你的 Layer 1 → Layer 2 IR 架构对策</div>
              <div class="dep-verdict-main">${escapeHtml(mode.irTitle)}</div>
              <p class="dep-verdict-note">${escapeHtml(mode.irNote)}</p>
            </div>
          </div>
        </div>
      `;

      container.innerHTML = html;

      container.querySelectorAll(".dep-tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.scenarioIdx = Number(btn.dataset.sc);
          state.modeIdx = 0;
          render();
        });
      });

      container.querySelectorAll(".dep-toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.modeIdx = Number(btn.dataset.mode);
          render();
        });
      });
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="dep-lab"]').forEach(initDepLab);
  });
})();
