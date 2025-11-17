document.addEventListener("DOMContentLoaded", () => {
    const navLinks = document.querySelectorAll(".sidebar-nav a");
    const bodyEl = document.body;
    const themeToggle = document.getElementById("themeToggle");
    const rootEl = document.documentElement;
    const accentSwatches = document.querySelectorAll(".accent-swatch");

    // Accent palettes
    const ACCENTS = {
        teal:    { hex: "#0d9488", hover: "#0f766e", rgb: "13, 148, 136" },
        emerald: { hex: "#10b981", hover: "#059669", rgb: "16, 185, 129" },
        violet:  { hex: "#8b5cf6", hover: "#7c3aed", rgb: "139, 92, 246" },
        indigo:  { hex: "#4f46e5", hover: "#4338ca", rgb: "79, 70, 229" },
        amber:   { hex: "#f59e0b", hover: "#d97706", rgb: "245, 158, 11" },
        rose:    { hex: "#e11d48", hover: "#be123c", rgb: "225, 29, 72" },
        red:     { hex: "#ef4444", hover: "#dc2626", rgb: "239, 68, 68" },
        orange:  { hex: "#f97316", hover: "#ea580c", rgb: "249, 115, 22" },
        lime:    { hex: "#84cc16", hover: "#65a30d", rgb: "132, 204, 22" },
        cyan:    { hex: "#06b6d4", hover: "#0891b2", rgb: "6, 182, 212" },
        sky:     { hex: "#0ea5e9", hover: "#0284c7", rgb: "14, 165, 233" },
        purple:  { hex: "#a855f7", hover: "#9333ea", rgb: "168, 85, 247" },
        fuchsia: { hex: "#d946ef", hover: "#c026d3", rgb: "217, 70, 239" },
        slate:   { hex: "#64748b", hover: "#475569", rgb: "100, 116, 139" },
        blush:   { hex: "#f472b6", hover: "#db2777", rgb: "244, 114, 182" },
        coral:   { hex: "#fb7185", hover: "#e11d48", rgb: "251, 113, 133" },
        peach:   { hex: "#fb923c", hover: "#ea580c", rgb: "251, 146, 60" },
        sage:    { hex: "#84a98c", hover: "#6b8f74", rgb: "132, 169, 140" },
        mint:    { hex: "#2dd4bf", hover: "#14b8a6", rgb: "45, 212, 191" },
        ocean:   { hex: "#0891b2", hover: "#0e7490", rgb: "8, 145, 178" },
        lavender:{ hex: "#c084fc", hover: "#a855f7", rgb: "192, 132, 252" },
        periwinkle:{ hex: "#8ea2ff", hover: "#7b91ff", rgb: "142, 162, 255" },
        "rose-gold": { hex: "#b76e79", hover: "#9e5d68", rgb: "183, 110, 121" },
        bronze:  { hex: "#b87333", hover: "#a05f2a", rgb: "184, 115, 51" }
    };

    const setAccentVars = (hex, hover, rgb) => {
        rootEl.style.setProperty("--primary-accent", hex);
        rootEl.style.setProperty("--primary-accent-hover", hover);
        rootEl.style.setProperty("--accent-rgb", rgb);
        bodyEl.style.setProperty("--primary-accent", hex);
        bodyEl.style.setProperty("--primary-accent-hover", hover);
        bodyEl.style.setProperty("--accent-rgb", rgb);
    };

    let rebuildTimeout;
    const rebuildChartsDebounced = () => {
        clearTimeout(rebuildTimeout);
        rebuildTimeout = setTimeout(() => {
            buildCharts();
        }, 50);
    };

    const applyAccent = (name) => {
        const palette = ACCENTS[name] || ACCENTS.teal;
        setAccentVars(palette.hex, palette.hover, palette.rgb);
        localStorage.setItem("astra-accent", name);
        accentSwatches.forEach(btn => {
            btn.setAttribute("aria-pressed", btn.dataset.accent === name ? "true" : "false");
        });
        rebuildChartsDebounced();
    };

    // Theme handling
    const savedTheme = localStorage.getItem("astra-theme");
    if (savedTheme === "dark") {
        bodyEl.setAttribute("data-theme", "dark");
        if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-sun" aria-hidden="true"></i>';
    }
    const applyTheme = (next) => {
        if (next === "dark") {
            bodyEl.setAttribute("data-theme", "dark");
            localStorage.setItem("astra-theme", "dark");
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-sun" aria-hidden="true"></i>';
        } else {
            bodyEl.removeAttribute("data-theme");
            localStorage.setItem("astra-theme", "light");
            if (themeToggle) themeToggle.innerHTML = '<i class="fas fa-moon" aria-hidden="true"></i>';
        }
        rebuildChartsDebounced();
    };
    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const isDark = bodyEl.getAttribute("data-theme") === "dark";
            applyTheme(isDark ? "light" : "dark");
        });
    }

    // Accent init and events
    const initialAccent = localStorage.getItem("astra-accent") || "teal";
    applyAccent(initialAccent);
    accentSwatches.forEach(btn => {
        btn.addEventListener("click", () => {
            applyAccent(btn.dataset.accent);
        });
    });

    navLinks.forEach(link => {
        link.addEventListener("click", function(e) {
            // Check if it's not the logout button
            if (!this.parentElement.classList.contains("logout")) {
                e.preventDefault(); // Prevent navigation for demo

                // Remove 'active' class from all links
                navLinks.forEach(nav => {
                    nav.classList.remove("active");
                    nav.removeAttribute("aria-current");
                });
                
                // Add 'active' class to the clicked link
                this.classList.add("active");
                this.setAttribute("aria-current", "page");
                
                // Update the main-header title
                const headerTitle = document.querySelector(".main-header h2");
                if (headerTitle) {
                    headerTitle.textContent = this.textContent.trim();
                }
            }
        });
    });

    // Chart.js initialization with rebuild support
    function buildCharts() {
        if (!window.Chart) return;
        // Destroy previous charts if any
        if (window.__astraCharts) {
            if (window.__astraCharts.line) { window.__astraCharts.line.destroy(); }
            if (window.__astraCharts.donut) { window.__astraCharts.donut.destroy(); }
        }

        const styles = getComputedStyle(document.body);
        const accent = styles.getPropertyValue("--primary-accent").trim() || "#007bff";
        const textColor = styles.getPropertyValue("--dark-text").trim() || "#000";
        const gridColor = styles.getPropertyValue("--border-color").trim() || "#e9ecef";
        const sevCritical = styles.getPropertyValue("--severity-critical").trim() || "#dc3545";
        const sevHigh = styles.getPropertyValue("--severity-high").trim() || "#fd7e14";
        const sevMedium = styles.getPropertyValue("--severity-medium").trim() || "#ffc107";

        let newLine = null;
        let newDonut = null;

        const lineCanvas = document.getElementById("alertsOverTimeChart");
        if (lineCanvas) {
            const ctx = lineCanvas.getContext("2d");
            const gradient = ctx.createLinearGradient(0, 0, 0, 250);
            gradient.addColorStop(0, accent + "33"); // ~20% opacity
            gradient.addColorStop(1, accent + "00");

            newLine = new Chart(ctx, {
                type: "line",
                data: {
                    labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                    datasets: [{
                        label: "Alerts",
                        data: [12, 18, 27, 35, 46, 59, 73],
                        borderColor: accent,
                        backgroundColor: gradient,
                        tension: 0.35,
                        fill: true,
                        pointRadius: 3,
                        pointHoverRadius: 5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    resizeDelay: 150,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: textColor }
                        },
                        y: {
                            grid: { color: gridColor },
                            beginAtZero: true,
                            ticks: { color: textColor, precision: 0 }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: "#000",
                            titleColor: "#fff",
                            bodyColor: "#fff",
                            borderColor: "#333",
                            borderWidth: 1
                        }
                    }
                }
            });
        }

        const doughnutCanvas = document.getElementById("alertsBySeverityChart");
        if (doughnutCanvas) {
            const ctx2 = doughnutCanvas.getContext("2d");
            newDonut = new Chart(ctx2, {
                type: "doughnut",
                data: {
                    labels: ["Critical", "High", "Medium"],
                    datasets: [{
                        data: [12, 26, 49],
                        backgroundColor: [sevCritical, sevHigh, sevMedium],
                        borderColor: [sevCritical, sevHigh, sevMedium],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    resizeDelay: 150,
                    cutout: "65%",
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: { color: textColor, usePointStyle: true }
                        },
                        tooltip: {
                            backgroundColor: "#000",
                            titleColor: "#fff",
                            bodyColor: "#fff",
                            borderColor: "#333",
                            borderWidth: 1
                        }
                    }
                }
            });
        }

        window.__astraCharts = { line: newLine, donut: newDonut };
    }

    // Initial build
    buildCharts();
});