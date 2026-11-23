/* ==========================================================================
   Reusable Curriculum Hub Filter & Progress Controller (index.html)
   Zero-dependency vanilla JS.
   ========================================================================== */

(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    const filterRoot = document.querySelector('[data-widget="curriculum-filter"]');
    if (!filterRoot) return;

    const state = {
      phase: "all",
      layer: "all",
      status: "all",
    };

    const lessonRows = Array.from(document.querySelectorAll(".lesson-row"));
    const chapters = Array.from(document.querySelectorAll(".chapter-block"));
    const phaseDividers = Array.from(document.querySelectorAll(".phase-divider"));
    const countEl = filterRoot.querySelector('[data-role="visible-count"]');
    const resetBtn = filterRoot.querySelector('[data-action="reset-filters"]');

    function applyFilters() {
      let visibleCount = 0;

      lessonRows.forEach((row) => {
        const rowPhase = row.dataset.phase || "";
        const rowLayers = (row.dataset.layer || "").split(",").map((s) => s.trim());
        const rowStatus = row.dataset.status || "";

        const matchPhase = state.phase === "all" || rowPhase === state.phase;
        const matchLayer = state.layer === "all" || rowLayers.includes(state.layer);
        const matchStatus = state.status === "all" || rowStatus === state.status;

        const visible = matchPhase && matchLayer && matchStatus;
        row.classList.toggle("is-hidden", !visible);
        if (visible) visibleCount++;
      });

      // Hide chapters with zero visible lessons
      const visiblePhases = new Set();
      chapters.forEach((ch) => {
        const hasVisible = ch.querySelector(".lesson-row:not(.is-hidden)") !== null;
        ch.classList.toggle("is-hidden", !hasVisible);
        if (hasVisible && ch.dataset.phase) {
          visiblePhases.add(ch.dataset.phase);
        }
      });

      // Hide phase dividers if all their chapters are hidden
      phaseDividers.forEach((div) => {
        const p = div.dataset.phase;
        div.classList.toggle("is-hidden", !visiblePhases.has(p));
      });

      if (countEl) {
        countEl.textContent = `当前显示 ${visibleCount} / ${lessonRows.length} 课`;
      }
    }

    filterRoot.querySelectorAll(".filter-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const group = pill.dataset.filterGroup;
        const val = pill.dataset.filterValue;
        if (!group || !val) return;

        state[group] = val;
        filterRoot
          .querySelectorAll(`.filter-pill[data-filter-group="${group}"]`)
          .forEach((btn) => btn.classList.toggle("active", btn === pill));

        applyFilters();
      });
    });

    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        state.phase = "all";
        state.layer = "all";
        state.status = "all";
        filterRoot.querySelectorAll(".filter-pill").forEach((btn) => {
          btn.classList.toggle("active", btn.dataset.filterValue === "all");
        });
        applyFilters();
      });
    }

    applyFilters();
  });
})();
