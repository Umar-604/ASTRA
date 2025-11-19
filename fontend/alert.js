document.addEventListener("DOMContentLoaded", () => {
const table = document.getElementById("alertsTable");
    if (!table) return;

    const chips = document.querySelectorAll(".filters .chip[data-severity]");
    const clearBtn = document.getElementById("clearFilters");
    const searchInput = document.getElementById("alertsSearch");

    let severity = "all";
    let query = "";

    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr")).filter(r => !r.classList.contains("empty-row"));
    const emptyRow = tbody.querySelector(".empty-row");
    const countEl = document.getElementById("alertsCount");
    const exportBtn = document.getElementById("exportCSV");
    const refreshBtn = document.getElementById("refreshBtn");

    const applyFilters = () => {
        const q = query.trim().toLowerCase();
        let visible = 0;
        rows.forEach(row => {
            const severitySpan = row.querySelector("td:nth-child(4) span") || null;
            const rowText = row.textContent.toLowerCase();
        
            const sevClass = severitySpan ? (Array.from(severitySpan.classList).find(c => c.startsWith("severity-")) || "severity-").replace("severity-","") : "";
            
            const sevOk = (severity === "all") || (sevClass === severity);
            const searchOk = q.length === 0 || rowText.includes(q);

            const show = (sevOk && searchOk);
            row.style.display = show ? "" : "none";
            if (show) visible += 1;
            });
        if (emptyRow) emptyRow.style.display = visible === 0 ? "" : "none";
        if (countEl) countEl.textContent = ${visible} result${visible === 1 ? "" : "s"};
    };

    chips.forEach(chip => {
        chip.addEventListener("click", () => {
            chips.forEach(c => c.setAttribute("aria-pressed", "false"));
            chip.setAttribute("aria-pressed", "true");
            severity = chip.dataset.severity || "all";
            applyFilters();
        });
    });
