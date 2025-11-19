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