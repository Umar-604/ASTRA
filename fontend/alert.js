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

    clearBtn.addEventListener("click", () => {
        severity = "all";
        query = "";
        chips.forEach(c => c.setAttribute("aria-pressed", c.dataset.severity === "all" ? "true" : "false"));
        if (searchInput) searchInput.value = "";
        applyFilters();
    });

    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            query = e.target.value || "";
            applyFilters();
        });
    }

    // Export visible rows to CSV
    const toCSV = () => {
        const headers = Array.from(table.querySelectorAll("thead th")).slice(0, 4).map(th => th.textContent.trim());
        const lines = [headers.join(",")];
        rows.forEach(row => {
            if (row.style.display === "none") return;
            const cells = Array.from(row.querySelectorAll("td")).slice(0, 4).map(td => {
                const text = td.textContent.trim().replace(/\s+/g, " ");
                if (text.includes(",") || text.includes("\"")) {
                    return "${text.replace(/"/g, '""')}";
                }
                return text;
            });
            if (cells.length) lines.push(cells.join(","));
        });
        const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "alerts.csv";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    if (exportBtn) {
        exportBtn.addEventListener("click", toCSV);
    }

    // Refresh button (demo)
    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            refreshBtn.disabled = true;
            refreshBtn.style.opacity = "0.7";
            setTimeout(() => {
                refreshBtn.disabled = false;
                refreshBtn.style.opacity = "1";
            }, 500);
        });
    }

    // Initial filter
    applyFilters();
});