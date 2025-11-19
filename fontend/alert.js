document.addEventListener("DOMContentLoaded", () => {
const table = document.getElementById("alertsTable");
    if (!table) return;

    const chips = document.querySelectorAll(".filters .chip[data-severity]");
    const clearBtn = document.getElementById("clearFilters");
    const searchInput = document.getElementById("alertsSearch");
