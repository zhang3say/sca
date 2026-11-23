/* ==========================================================================
   Reusable Multi-Ecosystem Version Range Comparator & Backport Lab
   Zero-dependency vanilla JS shared across Layer 3 lessons.
   Implements native total-order comparators for:
     - semver (SemVer 2.0.0 / npm / Go)
     - maven (Apache ComparableVersion)
     - pep440 (Python PEP 440)
     - deb (Debian EVR / dpkg verrevcmp)
     - rpm (RPM EVR / rpmvercmp with ~ and ^)
     - apk (Alpine apk version)
   Usage:
     <section class="widget-panel" data-widget="version-range-lab">
       <script type="application/json" class="version-range-lab-data">{ ... }</script>
     </section>
   ========================================================================== */

(function (globalScope) {
  "use strict";

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ------------------------------------------------------------------------
     1. SemVer 2.0.0 (with optional Go 'v' prefix detection & build metadata)
     ------------------------------------------------------------------------ */
  function parseSemver(raw) {
    const trimmed = String(raw || "").trim();
    const hadLeadingV = /^[vV]/.test(trimmed);
    const cleaned = hadLeadingV ? trimmed.slice(1) : trimmed;
    const m = cleaned.match(
      /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/
    );
    if (!m) {
      return { valid: false, raw: trimmed, tokens: [{ text: trimmed, kind: "normal" }] };
    }
    const coerced = m[2] === undefined || m[3] === undefined;
    const major = parseInt(m[1], 10);
    const minor = m[2] !== undefined ? parseInt(m[2], 10) : 0;
    const patch = m[3] !== undefined ? parseInt(m[3], 10) : 0;
    const pre = m[4] ? m[4].split(".") : [];
    const build = m[5] || "";
    const tokens = [
      { text: `core:${major}.${minor}.${patch}`, kind: "normal" },
    ];
    if (hadLeadingV) tokens.unshift({ text: "prefix:v (OSV禁止)", kind: "special" });
    if (pre.length) tokens.push({ text: `pre:-${pre.join(".")}`, kind: "special" });
    if (build) tokens.push({ text: `build:+${build} (排序忽略)`, kind: "normal" });
    return { valid: true, raw: trimmed, hadLeadingV, coerced, major, minor, patch, pre, build, tokens };
  }

  function compareSemver(rawA, rawB) {
    const a = parseSemver(rawA);
    const b = parseSemver(rawB);
    if (!a.valid || !b.valid) {
      return {
        cmp: rawA < rawB ? -1 : rawA > rawB ? 1 : 0,
        a,
        b,
        note: "存在非标准 SemVer 字符串，退回字典序提示。",
      };
    }
    if (a.major !== b.major) return { cmp: a.major < b.major ? -1 : 1, a, b };
    if (a.minor !== b.minor) return { cmp: a.minor < b.minor ? -1 : 1, a, b };
    if (a.patch !== b.patch) return { cmp: a.patch < b.patch ? -1 : 1, a, b };

    if (a.pre.length === 0 && b.pre.length === 0) return { cmp: 0, a, b };
    if (a.pre.length === 0) return { cmp: 1, a, b };
    if (b.pre.length === 0) return { cmp: -1, a, b };

    const len = Math.max(a.pre.length, b.pre.length);
    for (let i = 0; i < len; i++) {
      if (i >= a.pre.length) return { cmp: -1, a, b };
      if (i >= b.pre.length) return { cmp: 1, a, b };
      const pa = a.pre[i];
      const pb = b.pre[i];
      const na = /^\d+$/.test(pa);
      const nb = /^\d+$/.test(pb);
      if (na && nb) {
        const va = BigInt(pa);
        const vb = BigInt(pb);
        if (va !== vb) return { cmp: va < vb ? -1 : 1, a, b };
      } else if (na !== nb) {
        return { cmp: na ? -1 : 1, a, b };
      } else if (pa !== pb) {
        return { cmp: pa < pb ? -1 : 1, a, b };
      }
    }
    return { cmp: 0, a, b };
  }

  /* ------------------------------------------------------------------------
     2. Apache Maven ComparableVersion
     ------------------------------------------------------------------------ */
  const MAVEN_QUALIFIERS = {
    alpha: "0",
    beta: "1",
    milestone: "2",
    rc: "3",
    snapshot: "4",
    "": "5",
    ga: "5",
    final: "5",
    release: "5",
    sp: "6",
  };

  function mavenQualifierKey(val) {
    if (Object.prototype.hasOwnProperty.call(MAVEN_QUALIFIERS, val)) {
      return MAVEN_QUALIFIERS[val];
    }
    return `7-${val}`;
  }

  function makeMavenItem(buf, followedByDigit) {
    if (/^\d+$/.test(buf)) {
      return { type: "int", val: BigInt(buf) };
    }
    let s = buf;
    if (followedByDigit && s.length === 1) {
      if (s === "a") s = "alpha";
      else if (s === "b") s = "beta";
      else if (s === "m") s = "milestone";
    }
    if (s === "cr") s = "rc";
    return { type: "str", val: s };
  }

  function isMavenNull(item) {
    if (!item) return true;
    if (item.type === "int") return item.val === 0n;
    if (item.type === "str") return mavenQualifierKey(item.val) === "5";
    if (item.type === "list") return item.items.length === 0;
    return false;
  }

  function normalizeMavenList(list) {
    for (let i = list.items.length - 1; i >= 0; i--) {
      const cur = list.items[i];
      if (isMavenNull(cur)) {
        list.items.splice(i, 1);
      } else if (cur.type !== "list") {
        break;
      }
    }
  }

  function parseMaven(raw) {
    const s = String(raw || "").trim().toLowerCase();
    const root = { type: "list", items: [] };
    let cur = root;
    const stack = [root];
    let isDigit = false;
    let startIdx = 0;

    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === ".") {
        if (i === startIdx) {
          cur.items.push({ type: "int", val: 0n });
        } else {
          cur.items.push(makeMavenItem(s.slice(startIdx, i), false));
        }
        startIdx = i + 1;
      } else if (c === "-") {
        if (i === startIdx) {
          cur.items.push({ type: "int", val: 0n });
        } else {
          cur.items.push(makeMavenItem(s.slice(startIdx, i), false));
        }
        startIdx = i + 1;
        normalizeMavenList(cur);
        const sub = { type: "list", items: [] };
        cur.items.push(sub);
        cur = sub;
        stack.push(cur);
      } else if (/\d/.test(c)) {
        if (!isDigit && i > startIdx) {
          cur.items.push(makeMavenItem(s.slice(startIdx, i), true));
          startIdx = i;
          normalizeMavenList(cur);
          const sub = { type: "list", items: [] };
          cur.items.push(sub);
          cur = sub;
          stack.push(cur);
        }
        isDigit = true;
      } else {
        if (isDigit && i > startIdx) {
          cur.items.push(makeMavenItem(s.slice(startIdx, i), false));
          startIdx = i;
          normalizeMavenList(cur);
          const sub = { type: "list", items: [] };
          cur.items.push(sub);
          cur = sub;
          stack.push(cur);
        }
        isDigit = false;
      }
    }

    if (s.length > startIdx) {
      cur.items.push(makeMavenItem(s.slice(startIdx), false));
    }

    for (let i = stack.length - 1; i >= 0; i--) {
      normalizeMavenList(stack[i]);
    }

    const tokens = [];
    function collectTokens(node, prefix) {
      node.items.forEach((it) => {
        if (it.type === "int") {
          tokens.push({ text: `${prefix}int:${it.val.toString()}`, kind: "normal" });
        } else if (it.type === "str") {
          const qk = mavenQualifierKey(it.val);
          const isSpecial = qk.startsWith("7-") || qk !== "5";
          tokens.push({
            text: `${prefix}str:${it.val} (${qk.startsWith("7-") ? ">正式版" : "rank=" + qk})`,
            kind: isSpecial ? "special" : "normal",
          });
        } else {
          collectTokens(it, prefix + "-");
        }
      });
    }
    collectTokens(root, "");
    if (!tokens.length) tokens.push({ text: "normalized:0", kind: "normal" });

    return { valid: s.length > 0, raw: String(raw || "").trim(), root, tokens };
  }

  function cmpMavenItem(a, b) {
    if (!a && !b) return 0;
    if (!a) return -cmpMavenItem(b, null);

    if (a.type === "int") {
      if (!b) return a.val === 0n ? 0 : 1;
      if (b.type === "int") return a.val < b.val ? -1 : a.val > b.val ? 1 : 0;
      if (b.type === "str") return 1;
      return 1;
    }

    if (a.type === "str") {
      const ka = mavenQualifierKey(a.val);
      if (!b) {
        if (ka === "5") return 0;
        return ka < "5" ? -1 : 1;
      }
      if (b.type === "int") return -1;
      if (b.type === "str") {
        const kb = mavenQualifierKey(b.val);
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      }
      return -cmpMavenItem(b, a);
    }

    // a.type === "list"
    if (!b) {
      if (a.items.length === 0) return 0;
      return cmpMavenItem(a.items[0], null);
    }
    if (b.type === "int") return -1;
    if (b.type === "str") return 1;

    const len = Math.max(a.items.length, b.items.length);
    for (let i = 0; i < len; i++) {
      const l = i < a.items.length ? a.items[i] : null;
      const r = i < b.items.length ? b.items[i] : null;
      const res = cmpMavenItem(l, r);
      if (res !== 0) return res;
    }
    return 0;
  }

  function compareMaven(rawA, rawB) {
    const a = parseMaven(rawA);
    const b = parseMaven(rawB);
    return { cmp: cmpMavenItem(a.root, b.root), a, b };
  }

  /* ------------------------------------------------------------------------
     3. Python PEP 440
     ------------------------------------------------------------------------ */
  const PEP440_REGEX =
    /^\s*v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?([0-9]*))?(?:(?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]*)))?(?:[-_.]?(dev)[-_.]?([0-9]*))?(?:\+([a-z0-9]+(?:[._-][a-z0-9]+)*))?\s*$/i;

  function normPepPre(letter) {
    if (!letter) return null;
    const l = letter.toLowerCase();
    if (l === "alpha" || l === "a") return "a";
    if (l === "beta" || l === "b") return "b";
    if (l === "c" || l === "pre" || l === "preview" || l === "rc") return "rc";
    return l;
  }

  function parsePep440(raw) {
    const s = String(raw || "").trim();
    const m = s.match(PEP440_REGEX);
    if (!m) {
      return { valid: false, raw: s, tokens: [{ text: "非合法 PEP 440 版本", kind: "special" }] };
    }
    const epoch = m[1] ? parseInt(m[1], 10) : 0;
    const release = m[2].split(".").map((n) => parseInt(n, 10));
    while (release.length > 1 && release[release.length - 1] === 0) {
      release.pop();
    }
    const preTag = normPepPre(m[3]);
    const pre = preTag ? [preTag, m[4] ? parseInt(m[4], 10) : 0] : null;
    let post = null;
    if (m[5] !== undefined) post = parseInt(m[5], 10);
    else if (m[6] !== undefined) post = m[7] ? parseInt(m[7], 10) : 0;
    const dev = m[8] !== undefined ? (m[9] ? parseInt(m[9], 10) : 0) : null;
    const local = m[10]
      ? m[10].toLowerCase().split(/[._-]/).map((seg) => (/^\d+$/.test(seg) ? [0, BigInt(seg)] : [1, seg]))
      : [];

    const tokens = [];
    if (epoch > 0) tokens.push({ text: `epoch:${epoch}!`, kind: "epoch" });
    tokens.push({ text: `release:${release.join(".")}`, kind: "normal" });
    if (pre) tokens.push({ text: `pre:${pre[0]}${pre[1]}`, kind: "special" });
    if (post !== null) tokens.push({ text: `post:.post${post}`, kind: "special" });
    if (dev !== null) tokens.push({ text: `dev:.dev${dev}`, kind: "special" });
    if (m[10]) tokens.push({ text: `local:+${m[10]}`, kind: "normal" });

    return { valid: true, raw: s, epoch, release, pre, post, dev, local, tokens };
  }

  function pepPreKey(v) {
    if (v.pre === null && v.post === null && v.dev !== null) return [-1, "", 0];
    if (v.pre === null) return [1, "", 0];
    return [0, v.pre[0], v.pre[1]];
  }

  function cmpTuple(a, b) {
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const av = i < a.length ? a[i] : 0;
      const bv = i < b.length ? b[i] : 0;
      if (av !== bv) return av < bv ? -1 : 1;
    }
    return 0;
  }

  function comparePep440(rawA, rawB) {
    const a = parsePep440(rawA);
    const b = parsePep440(rawB);
    if (!a.valid || !b.valid) {
      return { cmp: rawA < rawB ? -1 : rawA > rawB ? 1 : 0, a, b };
    }
    if (a.epoch !== b.epoch) return { cmp: a.epoch < b.epoch ? -1 : 1, a, b };
    const rCmp = cmpTuple(a.release, b.release);
    if (rCmp !== 0) return { cmp: rCmp, a, b };

    const pa = pepPreKey(a);
    const pb = pepPreKey(b);
    for (let i = 0; i < 3; i++) {
      if (pa[i] !== pb[i]) return { cmp: pa[i] < pb[i] ? -1 : 1, a, b };
    }

    const postA = a.post === null ? -Infinity : a.post;
    const postB = b.post === null ? -Infinity : b.post;
    if (postA !== postB) return { cmp: postA < postB ? -1 : 1, a, b };

    const devA = a.dev === null ? Infinity : a.dev;
    const devB = b.dev === null ? Infinity : b.dev;
    if (devA !== devB) return { cmp: devA < devB ? -1 : 1, a, b };

    const locLen = Math.max(a.local.length, b.local.length);
    for (let i = 0; i < locLen; i++) {
      if (i >= a.local.length) return { cmp: -1, a, b };
      if (i >= b.local.length) return { cmp: 1, a, b };
      const la = a.local[i];
      const lb = b.local[i];
      if (la[0] !== lb[0]) return { cmp: la[0] > lb[0] ? -1 : 1, a, b }; // numeric > string in packaging.version local
      if (la[1] !== lb[1]) return { cmp: la[1] < lb[1] ? -1 : 1, a, b };
    }
    return { cmp: 0, a, b };
  }

  /* ------------------------------------------------------------------------
     4. Debian EVR (dpkg --compare-versions verrevcmp)
     ------------------------------------------------------------------------ */
  function parseDebEvr(raw) {
    const s = String(raw || "").trim();
    let epoch = 0;
    let rest = s;
    const colon = s.indexOf(":");
    if (colon !== -1 && /^\d+$/.test(s.slice(0, colon))) {
      epoch = parseInt(s.slice(0, colon), 10);
      rest = s.slice(colon + 1);
    }
    const lastHyphen = rest.lastIndexOf("-");
    let upstream = rest;
    let revision = "";
    if (lastHyphen !== -1) {
      upstream = rest.slice(0, lastHyphen);
      revision = rest.slice(lastHyphen + 1);
    }
    const tokens = [];
    if (epoch > 0) tokens.push({ text: `epoch:${epoch}:`, kind: "epoch" });
    tokens.push({ text: `upstream:${upstream}`, kind: upstream.includes("~") ? "special" : "normal" });
    if (revision) {
      tokens.push({
        text: `revision:-${revision}`,
        kind: revision.includes("~") || revision.includes("deb") ? "special" : "normal",
      });
    }
    return { valid: s.length > 0, raw: s, epoch, upstream, revision, tokens };
  }

  function debCharOrder(ch) {
    if (!ch) return 0;
    if (ch === "~") return -1;
    const code = ch.charCodeAt(0);
    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) return code;
    if (code >= 48 && code <= 57) return 0;
    return code + 256;
  }

  function debVerRevCmp(a, b) {
    let i = 0;
    let j = 0;
    while (i < a.length || j < b.length) {
      let firstDiff = 0;
      while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
        const ac = i < a.length && !/\d/.test(a[i]) ? a[i] : "";
        const bc = j < b.length && !/\d/.test(b[j]) ? b[j] : "";
        const oa = debCharOrder(ac);
        const ob = debCharOrder(bc);
        if (oa !== ob) return oa < ob ? -1 : 1;
        if (ac) i++;
        if (bc) j++;
      }
      while (i < a.length && a[i] === "0") i++;
      while (j < b.length && b[j] === "0") j++;
      while (i < a.length && /\d/.test(a[i]) && j < b.length && /\d/.test(b[j])) {
        if (firstDiff === 0 && a[i] !== b[j]) {
          firstDiff = a[i] < b[j] ? -1 : 1;
        }
        i++;
        j++;
      }
      if (i < a.length && /\d/.test(a[i])) return 1;
      if (j < b.length && /\d/.test(b[j])) return -1;
      if (firstDiff !== 0) return firstDiff;
    }
    return 0;
  }

  function compareDeb(rawA, rawB) {
    const a = parseDebEvr(rawA);
    const b = parseDebEvr(rawB);
    if (a.epoch !== b.epoch) return { cmp: a.epoch < b.epoch ? -1 : 1, a, b };
    const uCmp = debVerRevCmp(a.upstream, b.upstream);
    if (uCmp !== 0) return { cmp: uCmp, a, b };
    return { cmp: debVerRevCmp(a.revision, b.revision), a, b };
  }

  /* ------------------------------------------------------------------------
     5. RPM EVR (rpmvercmp with ~ and ^)
     ------------------------------------------------------------------------ */
  function parseRpmEvr(raw) {
    const s = String(raw || "").trim();
    let epoch = 0;
    let rest = s;
    const colon = s.indexOf(":");
    if (colon !== -1 && /^\d+$/.test(s.slice(0, colon))) {
      epoch = parseInt(s.slice(0, colon), 10);
      rest = s.slice(colon + 1);
    }
    const lastHyphen = rest.lastIndexOf("-");
    let version = rest;
    let release = "";
    if (lastHyphen !== -1) {
      version = rest.slice(0, lastHyphen);
      release = rest.slice(lastHyphen + 1);
    }
    const tokens = [];
    if (epoch > 0) tokens.push({ text: `epoch:${epoch}:`, kind: "epoch" });
    tokens.push({
      text: `version:${version}`,
      kind: version.includes("~") || version.includes("^") ? "special" : "normal",
    });
    if (release) {
      tokens.push({
        text: `release:-${release}`,
        kind: release.includes("el") || release.includes("~") || release.includes("^") ? "special" : "normal",
      });
    }
    return { valid: s.length > 0, raw: s, epoch, version, release, tokens };
  }

  function rpmVerCmp(a, b) {
    if (a === b) return 0;
    let i = 0;
    let j = 0;
    const isAlnum = (c) => /[A-Za-z0-9]/.test(c);
    const isDigit = (c) => /[0-9]/.test(c);
    const isAlpha = (c) => /[A-Za-z]/.test(c);

    while (i < a.length || j < b.length) {
      while (i < a.length && !isAlnum(a[i]) && a[i] !== "~" && a[i] !== "^") i++;
      while (j < b.length && !isAlnum(b[j]) && b[j] !== "~" && b[j] !== "^") j++;

      // Handle tilde (~): sorts before everything else
      if ((i < a.length && a[i] === "~") || (j < b.length && b[j] === "~")) {
        if (i >= a.length || a[i] !== "~") return 1;
        if (j >= b.length || b[j] !== "~") return -1;
        i++;
        j++;
        continue;
      }

      // Handle caret (^): sorts after end of string, before non-caret segments
      if ((i < a.length && a[i] === "^") || (j < b.length && b[j] === "^")) {
        if (i >= a.length) return -1;
        if (j >= b.length) return 1;
        if (a[i] !== "^") return 1;
        if (b[j] !== "^") return -1;
        i++;
        j++;
        continue;
      }

      if (i >= a.length || j >= b.length) break;

      const s1 = i;
      const s2 = j;
      let isNum = false;
      if (isDigit(a[i])) {
        while (i < a.length && isDigit(a[i])) i++;
        while (j < b.length && isDigit(b[j])) j++;
        isNum = true;
      } else {
        while (i < a.length && isAlpha(a[i])) i++;
        while (j < b.length && isAlpha(b[j])) j++;
      }

      let seg1 = a.slice(s1, i);
      let seg2 = b.slice(s2, j);
      if (seg2.length === 0) return isNum ? 1 : -1;

      if (isNum) {
        seg1 = seg1.replace(/^0+/, "") || "0";
        seg2 = seg2.replace(/^0+/, "") || "0";
        if (seg1.length !== seg2.length) return seg1.length > seg2.length ? 1 : -1;
      }
      if (seg1 !== seg2) return seg1 < seg2 ? -1 : 1;
    }

    if (i >= a.length && j >= b.length) return 0;
    return i >= a.length ? -1 : 1;
  }

  function compareRpm(rawA, rawB) {
    const a = parseRpmEvr(rawA);
    const b = parseRpmEvr(rawB);
    if (a.epoch !== b.epoch) return { cmp: a.epoch < b.epoch ? -1 : 1, a, b };
    const vCmp = rpmVerCmp(a.version, b.version);
    if (vCmp !== 0) return { cmp: vCmp, a, b };
    return { cmp: rpmVerCmp(a.release, b.release), a, b };
  }

  /* ------------------------------------------------------------------------
     6. Alpine apk version
     ------------------------------------------------------------------------ */
  const APK_SUFFIX_ORDER = {
    _alpha: -4,
    _beta: -3,
    _pre: -2,
    _rc: -1,
    "": 0,
    _cvs: 1,
    _svn: 2,
    _git: 3,
    _hg: 4,
    _p: 5,
  };

  function parseApk(raw) {
    const s = String(raw || "").trim();
    const m = s.match(
      /^(\d+(?:\.\d+)*)([a-z])?(?:(_alpha|_beta|_pre|_rc|_cvs|_svn|_git|_hg|_p)(\d*))?(?:~([0-9a-f]+))?(?:-r(\d+))?$/i
    );
    if (!m) {
      return { valid: false, raw: s, tokens: [{ text: "非标准 apk 版本", kind: "special" }] };
    }
    const nums = m[1].split(".").map((n) => parseInt(n, 10));
    const letter = m[2] || "";
    const suffix = (m[3] || "").toLowerCase();
    const suffixNum = m[4] ? parseInt(m[4], 10) : 0;
    const rev = m[6] ? parseInt(m[6], 10) : 0;

    const tokens = [{ text: `nums:${nums.join(".")}${letter}`, kind: "normal" }];
    if (suffix) tokens.push({ text: `suffix:${suffix}${m[4] || ""} (rank=${APK_SUFFIX_ORDER[suffix]})`, kind: "special" });
    if (m[6] !== undefined) tokens.push({ text: `rev:-r${rev}`, kind: "special" });
    return { valid: true, raw: s, nums, letter, suffix, suffixNum, rev, tokens };
  }

  function compareApk(rawA, rawB) {
    const a = parseApk(rawA);
    const b = parseApk(rawB);
    if (!a.valid || !b.valid) {
      return { cmp: rawA < rawB ? -1 : rawA > rawB ? 1 : 0, a, b };
    }
    const nCmp = cmpTuple(a.nums, b.nums);
    if (nCmp !== 0) return { cmp: nCmp, a, b };
    if (a.letter !== b.letter) return { cmp: a.letter < b.letter ? -1 : 1, a, b };
    const ra = APK_SUFFIX_ORDER[a.suffix];
    const rb = APK_SUFFIX_ORDER[b.suffix];
    if (ra !== rb) return { cmp: ra < rb ? -1 : 1, a, b };
    if (a.suffixNum !== b.suffixNum) return { cmp: a.suffixNum < b.suffixNum ? -1 : 1, a, b };
    if (a.rev !== b.rev) return { cmp: a.rev < b.rev ? -1 : 1, a, b };
    return { cmp: 0, a, b };
  }

  const COMPARATORS = {
    semver: compareSemver,
    maven: compareMaven,
    pep440: comparePep440,
    deb: compareDeb,
    rpm: compareRpm,
    apk: compareApk,
  };

  function compareEcosystem(eco, a, b) {
    const fn = COMPARATORS[eco] || compareSemver;
    return fn(a, b);
  }

  /* ------------------------------------------------------------------------
     Helper: Naive SemVer / String Comparator & Dependency Specifier Pitfalls
     ------------------------------------------------------------------------ */
  function naiveCompare(a, b) {
    const sa = parseSemver(a);
    const sb = parseSemver(b);
    if (sa.valid && sb.valid) {
      const r = compareSemver(a, b);
      return {
        cmp: r.cmp,
        method: sa.coerced || sb.coerced ? "宽容 SemVer 补零强行比较" : "强行按 SemVer 2.0.0 比较",
      };
    }
    return {
      cmp: String(a).trim() < String(b).trim() ? -1 : String(a).trim() > String(b).trim() ? 1 : 0,
      method: "无法转 SemVer，退回 ASCII 字符串比较",
    };
  }

  function evaluateRangeAndPitfalls(eco, verA, introduced, fixed) {
    const v = String(verA || "").trim();
    const intro = String(introduced || "").trim();
    const fix = String(fixed || "").trim();
    if (!v || (!intro && !fix)) {
      return null;
    }

    const afterIntro = !intro || intro === "0" ? true : compareEcosystem(eco, v, intro).cmp >= 0;
    const beforeFixed = !fix ? true : compareEcosystem(eco, v, fix).cmp < 0;
    const isAffected = afterIntro && beforeFixed;

    const naiveAfterIntro = !intro || intro === "0" ? true : naiveCompare(v, intro).cmp >= 0;
    const naiveBeforeFixed = !fix ? true : naiveCompare(v, fix).cmp < 0;
    const naiveAffected = naiveAfterIntro && naiveBeforeFixed;

    // Detect Dependency Specifier Trap (npm node-semver / Python PEP 440 SpecifierSet)
    let specifierTrap = null;
    if (eco === "semver" && fix) {
      const pv = parseSemver(v);
      const pf = parseSemver(fix);
      if (pv.valid && pf.valid && pv.pre.length > 0 && pf.pre.length === 0 && isAffected) {
        specifierTrap = `若误用 npm node-semver.satisfies("${v}", "<${fix}")（未开 includePrerelease），因 ${fix} 无预发布标签或元组不同，返回 FALSE —— 导致预发布版线上静默漏报！`;
      }
    } else if (eco === "pep440" && fix) {
      const pv = parsePep440(v);
      const pf = parsePep440(fix);
      if (pv.valid && pf.valid && (pv.pre !== null || pv.dev !== null) && isAffected) {
        const sameRelease = cmpTuple(pv.release, pf.release) === 0 && pv.epoch === pf.epoch;
        specifierTrap = sameRelease
          ? `Python packaging.specifiers.SpecifierSet("<${fix}") 即使传 prereleases=True 也会对同基础版本预发布 "${v}" 返回 FALSE！拿依赖解析器做漏洞匹配必漏报。`
          : `Python SpecifierSet("<${fix}") 默认拒绝所有 pre-release（"${v}"），必须使用 Total-Order Comparator 比较！`;
      }
    }

    // Build canonical VERS string
    const scheme = eco === "semver" ? "npm" : eco === "pep440" ? "pypi" : eco;
    const parts = [];
    if (intro && intro !== "0") parts.push(`>=${intro.replace(/\s+/g, "")}`);
    if (fix) parts.push(`<${fix.replace(/\s+/g, "")}`);
    const versString = parts.length ? `vers:${scheme}/${parts.join("|")}` : `vers:${scheme}/*`;

    return {
      isAffected,
      naiveAffected,
      specifierTrap,
      versString,
    };
  }

  /* ------------------------------------------------------------------------
     Curated Architectural Presets (All Verified Against Official Specs)
     ------------------------------------------------------------------------ */
  const PRESETS = [
    {
      id: "semver-pre",
      label: "1. SemVer / npm 预发布陷阱",
      eco: "semver",
      verA: "1.2.4-alpha.1",
      verB: "1.2.4",
      intro: "1.0.0",
      fixed: "1.2.4",
      lessonNote:
        "OSV Total-Order 下 1.2.4-alpha.1 < 1.2.4，处于 [1.0.0, 1.2.4) 受影响区间；但 npm node-semver('<1.2.4') 默认按选包原则跳过所有预发布版，直接造成漏报。",
    },
    {
      id: "maven-qualifier",
      label: "2. Maven 未知修饰符陷阱",
      eco: "maven",
      verA: "1.0.0-redhat-00001",
      verB: "1.0.0",
      intro: "1.0.0",
      fixed: "1.0.1",
      lessonNote:
        "在 Apache ComparableVersion 中，alpha/beta/rc/snapshot 小于正式版，sp 大于正式版，而 redhat-00001 等未知修饰符排在 sp 之后（1.0.0 < 1.0.0-sp < 1.0.0-redhat-00001 < 1.0.1）！若误用 SemVer 解析会把 -redhat-00001 当成 pre-release 判成小于 1.0.0，导致漏报。",
    },
    {
      id: "pep440-epoch",
      label: "3. PEP 440 预发布 & Epoch 漏报",
      eco: "pep440",
      verA: "1.0.0a1",
      verB: "1.0.0",
      intro: "0.9.0",
      fixed: "1.0.0",
      lessonNote:
        "实测 Python packaging.specifiers.SpecifierSet('<1.0.0') 即使设置 prereleases=True 也会对 1.0.0a1 返回 False！漏洞匹配只能使用 PEP 440 全序比较器（1.0.0a1 < 1.0.0）。另可尝试将 verA 改为 '1!0.1' 验证 Epoch 压制一切！",
    },
    {
      id: "debian-backport",
      label: "4. Debian EVR ~ 与 Backport 双重误区",
      eco: "deb",
      verA: "1:9.2p1-2+deb12u3",
      verB: "9.8p1",
      intro: "8.5p1",
      fixed: "9.8p1",
      lessonNote:
        "真实案例 CVE-2024-6387 (regreSSHion)：Debian 12 已在 DSA-5724-1 中回溯修复至 1:9.2p1-2+deb12u3。若剥离 Epoch 直接比上游 <9.8p1 会误报；若带着 Epoch 1: 硬比上游 9.8p1 (隐式 Epoch 0:) 则变成 1:9.2p1 > 0:9.8p1 —— 哪怕未打补丁的 1:9.2p1-2+deb12u1 也会被判安全（漏报）！唯一正解是按 distro=debian-12 隔离查 DSA-5724-1。",
    },
    {
      id: "rpm-caret",
      label: "5. RPM 脱字符 ^、~ 与 RHEL 9 Backport",
      eco: "rpm",
      verA: "1.0^20240701git",
      verB: "1.0.1",
      intro: "1.0~rc1",
      fixed: "1.0.1",
      lessonNote:
        "rpmvercmp 中：~ 排在空串之前（1.0~rc1 < 1.0），而 ^ 排在空串之后且早于下一小版（1.0 < 1.0^20240701git < 1.0.1）；若退回 ASCII 比较，'^' (94) 大于 '.' (46) 会把快照误判成大于 1.0.1 导致漏报！RHEL 9 OpenSSH 8.7p1-38.el9_4.1 (RHSA-2024:4312) 则必须通过 CSAF VEX 独立匹配。",
    },
  ];

  function sym(cmp) {
    return cmp < 0 ? "<" : cmp > 0 ? ">" : "=";
  }

  function initVersionRangeLab(container) {
    const dataEl = container.querySelector("script.version-range-lab-data");
    let config = {};
    if (dataEl) {
      try {
        config = JSON.parse(dataEl.textContent);
      } catch (e) {
        container.innerHTML = "<p>版本语义实验台配置解析失败。</p>";
        return;
      }
    }

    const state = {
      presetId: PRESETS[0].id,
      eco: PRESETS[0].eco,
      verA: PRESETS[0].verA,
      verB: PRESETS[0].verB,
      intro: PRESETS[0].intro,
      fixed: PRESETS[0].fixed,
      note: PRESETS[0].lessonNote,
    };

    function renderTokens(tokens) {
      return (tokens || [])
        .map(
          (t) =>
            `<span class="ver-token-chip ${
              t.kind === "epoch" ? "is-epoch" : t.kind === "special" ? "is-special" : ""
            }">${escapeHtml(t.text)}</span>`
        )
        .join("");
    }

    function render() {
      const nativeRes = compareEcosystem(state.eco, state.verA, state.verB);
      const naiveRes = naiveCompare(state.verA, state.verB);
      const rangeEval = evaluateRangeAndPitfalls(state.eco, state.verA, state.intro, state.fixed);
      const diverged = nativeRes.cmp !== naiveRes.cmp;

      const isCrossNamespaceBackport =
        (state.eco === "deb" || state.eco === "rpm" || state.eco === "apk") &&
        state.verB.indexOf("-") === -1 &&
        !state.verB.includes(":") &&
        /(?:\+deb\d|deb\d+u\d|ubuntu|\.el\d|:|~bpo)/.test(state.verA);

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "多生态原生版本比较与区间语义实验台")}</h3>
          <div class="widget-status">生态内核：${escapeHtml(state.eco.toUpperCase())}</div>
        </div>
      `;

      if (config.intro) {
        html += `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(config.intro)}</p>`;
      }

      html += `<div class="purl-presets">`;
      PRESETS.forEach((p) => {
        html += `
          <button type="button" class="purl-preset-btn ${p.id === state.presetId ? "active" : ""}" data-preset="${p.id}">
            ${escapeHtml(p.label)}
          </button>
        `;
      });
      html += `</div>`;

      html += `
        <div class="ver-form-grid">
          <div class="ver-field">
            <label for="ver-eco-select">生态比较器</label>
            <select id="ver-eco-select" class="ver-select" data-input="eco">
              <option value="semver" ${state.eco === "semver" ? "selected" : ""}>SemVer / npm / Go</option>
              <option value="maven" ${state.eco === "maven" ? "selected" : ""}>Maven ComparableVersion</option>
              <option value="pep440" ${state.eco === "pep440" ? "selected" : ""}>Python PEP 440</option>
              <option value="deb" ${state.eco === "deb" ? "selected" : ""}>Debian EVR (dpkg)</option>
              <option value="rpm" ${state.eco === "rpm" ? "selected" : ""}>RPM EVR (rpmvercmp)</option>
              <option value="apk" ${state.eco === "apk" ? "selected" : ""}>Alpine apk</option>
            </select>
          </div>
          <div class="ver-field">
            <label for="ver-a-input">待测组件版本 A</label>
            <input id="ver-a-input" type="text" class="purl-input" data-input="verA" value="${escapeHtml(state.verA)}" />
          </div>
          <div class="ver-field">
            <label for="ver-b-input">对照版本 B</label>
            <input id="ver-b-input" type="text" class="purl-input" data-input="verB" value="${escapeHtml(state.verB)}" />
          </div>
        </div>

        <div class="ver-range-grid">
          <div class="ver-field">
            <label for="ver-intro-input">OSV 区间下界 introduced（闭区间 &ge;）</label>
            <input id="ver-intro-input" type="text" class="purl-input" data-input="intro" value="${escapeHtml(state.intro)}" placeholder="例如 0 或 1.0.0" />
          </div>
          <div class="ver-field">
            <label for="ver-fixed-input">OSV 区间上界 fixed（开区间 &lt;）</label>
            <input id="ver-fixed-input" type="text" class="purl-input" data-input="fixed" value="${escapeHtml(state.fixed)}" placeholder="例如 1.2.4" />
          </div>
        </div>
      `;

      html += `<div class="purl-output-grid">`;
      html += `
        <div class="purl-out-box ${diverged ? "highlight" : ""}">
          <div class="purl-out-label">生态原生全序比较（Total Order ✅）</div>
          <div class="purl-out-val"><strong>${escapeHtml(state.verA)}</strong> &nbsp;<code>${sym(nativeRes.cmp)}</code>&nbsp; <strong>${escapeHtml(state.verB)}</strong></div>
          <div class="ver-token-list">${renderTokens(nativeRes.a.tokens)}</div>
          <div class="ver-token-list">${renderTokens(nativeRes.b.tokens)}</div>
        </div>
        <div class="purl-out-box">
          <div class="purl-out-label">粗暴通用 SemVer / 字典序（${diverged ? "结论冲突 ❌" : "碰巧一致 ⚠️"}）</div>
          <div class="purl-out-val"><strong>${escapeHtml(state.verA)}</strong> &nbsp;<code>${sym(naiveRes.cmp)}</code>&nbsp; <strong>${escapeHtml(state.verB)}</strong></div>
          <p style="font-size:0.8rem;color:var(--ink-muted);margin:0.45rem 0 0;">判定路径：${escapeHtml(naiveRes.method)}</p>
          ${
            rangeEval
              ? `<p style="font-size:0.82rem;margin:0.45rem 0 0;color:var(--ink);">OSV 区间 <code>[${escapeHtml(state.intro || "0")}, ${escapeHtml(state.fixed || "∞")})</code> 对版本 A 判定：<strong style="color:${
                  rangeEval.isAffected ? "var(--danger)" : "var(--ok)"
                };">${rangeEval.isAffected ? "AFFECTED（命中）" : "NOT_AFFECTED（安全）"}</strong></p>
                <p style="font-size:0.78rem;font-family:var(--font-mono);color:var(--ink-muted);margin:0.3rem 0 0;word-break:break-all;">VERS: ${escapeHtml(rangeEval.versString)}</p>`
              : ""
          }
        </div>
      `;
      html += `</div>`;

      html += `<ul class="purl-diag-list">`;
      if (state.note) {
        html += `<li class="purl-diag-item">${escapeHtml(state.note)}</li>`;
      }
      if (diverged) {
        html += `<li class="purl-diag-item warn"><strong>排序分歧警报：</strong>通用 SemVer/ASCII 给出 <code>${sym(naiveRes.cmp)}</code>，而 ${escapeHtml(state.eco.toUpperCase())} 原生语义给出 <code>${sym(nativeRes.cmp)}</code>——若底层未分生态实现 Comparator，线上必现静默误报或漏报！</li>`;
      }
      if (rangeEval && rangeEval.specifierTrap) {
        html += `<li class="purl-diag-item error"><strong>选包 Specifier 漏报警报：</strong>${escapeHtml(rangeEval.specifierTrap)}</li>`;
      }
      if (isCrossNamespaceBackport) {
        html += `<li class="purl-diag-item error"><strong>跨命名空间 Backport 隔离警告：</strong>检测到发行版版本号（含 <code>:</code> Epoch 或 <code>deb/el</code> 尾缀）正在与无发行后缀的上游版本号对比！Layer 3 必须禁止此类跨命名空间直接对比，改由 <code>distro_qualifier</code> 路由至 Debian DSA / Red Hat CSAF VEX 原生通告求值。</li>`;
      }
      html += `</ul>`;

      container.innerHTML = html;

      container.querySelectorAll(".purl-preset-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const found = PRESETS.find((p) => p.id === btn.dataset.preset);
          if (!found) return;
          state.presetId = found.id;
          state.eco = found.eco;
          state.verA = found.verA;
          state.verB = found.verB;
          state.intro = found.intro;
          state.fixed = found.fixed;
          state.note = found.lessonNote;
          render();
        });
      });

      const ecoEl = container.querySelector('[data-input="eco"]');
      if (ecoEl) {
        ecoEl.addEventListener("change", () => {
          state.eco = ecoEl.value;
          state.presetId = "";
          state.note = "已切换至自定义生态比较模式，尝试输入特殊字符（如 ~、^、!、-sp、+build）观察分词变化。";
          render();
        });
      }

      ["verA", "verB", "intro", "fixed"].forEach((field) => {
        const el = container.querySelector(`[data-input="${field}"]`);
        if (!el) return;
        el.addEventListener("input", () => {
          state[field] = el.value;
          state.presetId = "";
        });
        el.addEventListener("change", () => {
          state[field] = el.value;
          state.presetId = "";
          render();
        });
        el.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter") {
            state[field] = el.value;
            state.presetId = "";
            render();
          }
        });
      });
    }

    render();
  }

  globalScope.__SCA_VERSION_ENGINE__ = {
    compareSemver,
    compareMaven,
    comparePep440,
    compareDeb,
    compareRpm,
    compareApk,
    compareEcosystem,
    evaluateRangeAndPitfalls,
  };

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
      document.querySelectorAll('[data-widget="version-range-lab"]').forEach(initVersionRangeLab);
    });
  }
})(typeof window !== "undefined" ? window : globalThis);
