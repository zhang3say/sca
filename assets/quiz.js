/* ==========================================================================
   Reusable Interactive Learning Components (Quiz & Architecture Sandbox)
   Zero-dependency vanilla JS shared across all lessons.
   ========================================================================== */

(function () {
  "use strict";

  const OPTION_KEYS = ["A", "B", "C", "D", "E", "F"];

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ------------------------------------------------------------------------
     1. Retrieval Practice Quiz Widget
     Usage:
       <section class="widget-panel" data-widget="quiz">
         <script type="application/json" class="quiz-data">{ ... }</script>
       </section>
     ------------------------------------------------------------------------ */
  function initQuiz(container) {
    const dataEl = container.querySelector("script.quiz-data");
    if (!dataEl) return;

    let config;
    try {
      config = JSON.parse(dataEl.textContent);
    } catch (e) {
      container.innerHTML = "<p>测验数据解析失败。</p>";
      return;
    }

    const questions = config.questions || [];
    const state = {
      answers: new Array(questions.length).fill(null),
    };

    function render() {
      const answeredCount = state.answers.filter((a) => a !== null).length;
      const correctCount = state.answers.filter(
        (a, idx) => a !== null && a === questions[idx].answerIndex
      ).length;

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "主动回忆测验")}</h3>
          <div class="widget-status">已答 ${answeredCount} / ${questions.length} · 正确 ${correctCount}</div>
        </div>
      `;

      if (config.intro) {
        html += `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:1rem;">${escapeHtml(config.intro)}</p>`;
      }

      questions.forEach((q, qIdx) => {
        const chosen = state.answers[qIdx];
        const isAnswered = chosen !== null;
        const isRight = chosen === q.answerIndex;

        html += `<div class="quiz-item" data-q="${qIdx}">`;
        html += `<div class="quiz-q-head"><span class="quiz-q-num">Q${qIdx + 1}.</span>${escapeHtml(q.prompt)}</div>`;
        html += `<div class="quiz-options">`;

        q.options.forEach((optText, oIdx) => {
          let cls = "quiz-opt";
          if (isAnswered) {
            if (oIdx === q.answerIndex) {
              cls += " is-correct";
            } else if (oIdx === chosen) {
              cls += " is-wrong";
            }
          }
          html += `
            <button type="button" class="${cls}" data-q="${qIdx}" data-o="${oIdx}" ${isAnswered ? "disabled" : ""}>
              <span class="quiz-opt-key">${OPTION_KEYS[oIdx]}</span>
              <span>${escapeHtml(optText)}</span>
            </button>
          `;
        });

        html += `</div>`;

        if (isAnswered) {
          const verdict = isRight ? "判断正确。" : `判断偏差（正确选项：${OPTION_KEYS[q.answerIndex]}）。`;
          html += `
            <div class="quiz-explanation visible ${isRight ? "ok" : "bad"}">
              <strong>${verdict}</strong> ${escapeHtml(q.explanation)}
            </div>
          `;
        }
        html += `</div>`;
      });

      html += `
        <div class="widget-actions">
          <button type="button" class="btn-secondary" data-action="reset-quiz">重置测验（重新回忆）</button>
          ${
            answeredCount === questions.length
              ? `<span style="font-size:0.88rem;color:var(--ink-secondary);">完成度 100% · 得分 <strong>${correctCount}/${questions.length}</strong>${
                  correctCount === questions.length
                    ? " — 架构边界已稳固，可以把你的思考带回对话继续深化。"
                    : " — 建议重读错题对应的架构解析，过几天再回来重置回忆一次。"
                }</span>`
              : `<span style="font-size:0.84rem;color:var(--ink-muted);">先凭记忆作答，不要回头翻正文；立即反馈将强化长期存储强度。</span>`
          }
        </div>
      `;

      container.innerHTML = html;

      container.querySelectorAll(".quiz-opt").forEach((btn) => {
        btn.addEventListener("click", () => {
          const qIdx = Number(btn.dataset.q);
          const oIdx = Number(btn.dataset.o);
          if (state.answers[qIdx] !== null) return;
          state.answers[qIdx] = oIdx;
          render();
        });
      });

      const resetBtn = container.querySelector('[data-action="reset-quiz"]');
      if (resetBtn) {
        resetBtn.addEventListener("click", () => {
          state.answers = new Array(questions.length).fill(null);
          render();
        });
      }
    }

    render();
  }

  /* ------------------------------------------------------------------------
     2. Architecture Decision Sandbox Widget
     Usage:
       <section class="widget-panel" data-widget="sandbox">
         <script type="application/json" class="sandbox-data">{ ... }</script>
       </section>
     ------------------------------------------------------------------------ */
  function initSandbox(container) {
    const dataEl = container.querySelector("script.sandbox-data");
    if (!dataEl) return;

    let config;
    try {
      config = JSON.parse(dataEl.textContent);
    } catch (e) {
      container.innerHTML = "<p>沙盘数据解析失败。</p>";
      return;
    }

    const modules = config.modules || [];
    const state = {
      selections: new Array(modules.length).fill(null),
      evaluated: false,
    };

    function render() {
      const selectedCount = state.selections.filter((s) => s !== null).length;

      let html = `
        <div class="widget-header">
          <h3 class="widget-title">${escapeHtml(config.title || "架构决策沙盘")}</h3>
          <div class="widget-status">已配置 ${selectedCount} / ${modules.length} 个模块</div>
        </div>
      `;

      if (config.intro) {
        html += `<p style="font-size:0.9rem;color:var(--ink-muted);margin-bottom:0.85rem;">${escapeHtml(config.intro)}</p>`;
      }

      modules.forEach((mod, mIdx) => {
        const selIdx = state.selections[mIdx];
        const chosenOpt = selIdx !== null ? mod.options[selIdx] : null;

        html += `<div class="sandbox-row">`;
        html += `
          <div class="sandbox-row-top">
            <span class="sandbox-mod-name">${mIdx + 1}. ${escapeHtml(mod.name)}</span>
            <span class="sandbox-mod-layer">${escapeHtml(mod.layer)}</span>
          </div>
          <p class="sandbox-mod-desc">${escapeHtml(mod.context)}</p>
          <div class="sandbox-options">
        `;

        mod.options.forEach((opt, oIdx) => {
          const isSelected = selIdx === oIdx;
          html += `
            <button type="button" class="sandbox-opt-btn ${isSelected ? "selected" : ""}" data-m="${mIdx}" data-o="${oIdx}">
              ${escapeHtml(opt.label)}
            </button>
          `;
        });

        html += `</div>`;

        if (state.evaluated && chosenOpt) {
          const tagMap = {
            optimal: "推荐策略",
            warning: "需权衡风险",
            critical: "高危架构债 / 合规雷区",
          };
          html += `
            <div class="sandbox-feedback visible ${escapeHtml(chosenOpt.status)}">
              <strong>[${tagMap[chosenOpt.status] || "评审"}] ${escapeHtml(chosenOpt.verdictTitle)}：</strong>
              ${escapeHtml(chosenOpt.feedback)}
            </div>
          `;
        }

        html += `</div>`;
      });

      html += `
        <div class="widget-actions">
          <button type="button" class="btn-primary" data-action="evaluate-sandbox">运行架构评审</button>
          <button type="button" class="btn-secondary" data-action="reset-sandbox">清空重配</button>
          <span style="font-size:0.83rem;color:var(--ink-muted);" data-role="sandbox-hint">
            ${selectedCount < modules.length ? `还差 ${modules.length - selectedCount} 个模块未做决策` : "所有模块已选定，点击左侧按钮查看架构评审报告"}
          </span>
        </div>
      `;

      if (state.evaluated) {
        let optimal = 0;
        let warning = 0;
        let critical = 0;
        modules.forEach((mod, idx) => {
          const sel = state.selections[idx];
          if (sel === null) return;
          const st = mod.options[sel].status;
          if (st === "optimal") optimal++;
          else if (st === "warning") warning++;
          else critical++;
        });

        const customSummary = config.summary || {};
        let summaryText = "";
        if (critical > 0) {
          summaryText = (customSummary.critical ||
            `当前方案存在 {critical} 处高危架构债或商业协议雷区（标红项）。如果按此架构进入研发，大概率会在半年内面临法务合规阻断或被迫重写核心数据模型。建议重点审视标红模块并调整策略。`
          ).replace(/\{critical\}/g, String(critical));
        } else if (warning > 0) {
          summaryText = (customSummary.warning ||
            `没有触发致命红线，但存在 {warning} 处成本或演进权衡点（标黄项）。作为总架构师，需要明确团队是否愿意为这些折中买单，并提前设计隔离边界。`
          ).replace(/\{warning\}/g, String(warning));
        } else {
          summaryText = (customSummary.optimal ||
            `全部 {optimal} 个模块的「借力 vs 自研」边界清晰：底层商品化能力高效借力 Apache-2.0 底座，核心 IR 主权与第三代高价值壁垒牢牢掌握在自研团队手中！`
          ).replace(/\{optimal\}/g, String(optimal));
        }

        html += `
          <div class="sandbox-summary visible">
            <strong>架构评审总评：</strong>
            推荐策略 <strong>${optimal}</strong> · 需权衡 <strong>${warning}</strong> · 高危雷区 <strong>${critical}</strong>
            <p style="margin:0.45rem 0 0;color:var(--ink-secondary);">${escapeHtml(summaryText)}</p>
          </div>
        `;
      }

      container.innerHTML = html;

      container.querySelectorAll(".sandbox-opt-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const mIdx = Number(btn.dataset.m);
          const oIdx = Number(btn.dataset.o);
          state.selections[mIdx] = oIdx;
          render();
        });
      });

      const evalBtn = container.querySelector('[data-action="evaluate-sandbox"]');
      if (evalBtn) {
        evalBtn.addEventListener("click", () => {
          if (state.selections.some((s) => s === null)) {
            const hint = container.querySelector('[data-role="sandbox-hint"]');
            if (hint) {
              hint.style.color = "var(--danger)";
              hint.textContent = "请先为全部模块选定策略，再运行完整架构评审。";
            }
            return;
          }
          state.evaluated = true;
          render();
        });
      }

      const resetBtn = container.querySelector('[data-action="reset-sandbox"]');
      if (resetBtn) {
        resetBtn.addEventListener("click", () => {
          state.selections = new Array(modules.length).fill(null);
          state.evaluated = false;
          render();
        });
      }
    }

    render();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[data-widget="quiz"]').forEach(initQuiz);
    document.querySelectorAll('[data-widget="sandbox"]').forEach(initSandbox);
  });
})();
