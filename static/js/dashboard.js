/**
 * Security Log Analyzer - Frontend Script
 * Handles Chart.js charts and file drag-and-drop.
 */

// Drag and drop handler for upload page
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectedFileName = document.getElementById('selectedFileName');

    if (dropZone && fileInput) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
            }, false);
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                if (selectedFileName) {
                    selectedFileName.textContent = `Selected: ${files[0].name} (${(files[0].size / 1024).toFixed(1)} KB)`;
                    selectedFileName.style.display = 'block';
                }
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0 && selectedFileName) {
                selectedFileName.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
                selectedFileName.style.display = 'block';
            }
        });
    }
});

/**
 * Initializes clean, professional Chart.js charts on the dashboard.
 * @param {Object} severityData - Counts for CRITICAL, HIGH, MEDIUM, LOW
 * @param {Object} hourlyActivity - Hourly buckets of failed and successful logins
 */
function initDashboardCharts(severityData, hourlyActivity) {
    if (typeof Chart === 'undefined') {
        console.error("Chart.js is not loaded yet.");
        return;
    }

    severityData = severityData || {};
    hourlyActivity = hourlyActivity || {};

    // -------------------------------------------------------------
    // 1. Severity Doughnut Chart
    // -------------------------------------------------------------
    const ctxDoughnut = document.getElementById('severityDoughnutChart');
    if (ctxDoughnut) {
        const existingChart = Chart.getChart(ctxDoughnut);
        if (existingChart) existingChart.destroy();

        const crit = Number(severityData.CRITICAL) || 0;
        const high = Number(severityData.HIGH) || 0;
        const med = Number(severityData.MEDIUM) || 0;
        const low = Number(severityData.LOW) || 0;
        const total = crit + high + med + low;

        let labels = ['Critical', 'High', 'Medium', 'Low'];
        let dataValues = [crit, high, med, low];
        let bgColors = ['#dc2626', '#f87171', '#f59e0b', '#10b981'];

        if (total === 0) {
            labels = ['No Incidents'];
            dataValues = [1];
            bgColors = ['#e2e8f0'];
        }

        new Chart(ctxDoughnut, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: dataValues,
                    backgroundColor: bgColors,
                    borderWidth: 2,
                    borderColor: '#ffffff',
                    hoverOffset: total > 0 ? 4 : 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: total > 0,
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} incidents`;
                            }
                        }
                    }
                },
                cutout: '72%'
            }
        });
    }

    // -------------------------------------------------------------
    // 2. Hourly Authentication Activity (Bar Chart)
    // -------------------------------------------------------------
    const ctxBar = document.getElementById('loginActivityChart');
    if (ctxBar) {
        const existingBar = Chart.getChart(ctxBar);
        if (existingBar) existingBar.destroy();

        const sortedHours = Object.keys(hourlyActivity).sort();
        let labels = [];
        let failedSeries = [];
        let successSeries = [];

        if (sortedHours.length > 0) {
            labels = sortedHours.map(h => {
                // Shorten '2026-10-21 09:00' to '10-21 09:00'
                const parts = h.split(' ');
                if (parts.length === 2) {
                    const datePart = parts[0].slice(5); // MM-DD
                    return `${datePart} ${parts[1]}`;
                }
                return h;
            });
            failedSeries = sortedHours.map(h => hourlyActivity[h].failed || 0);
            successSeries = sortedHours.map(h => hourlyActivity[h].success || 0);
        } else {
            labels = ['No Activity'];
            failedSeries = [0];
            successSeries = [0];
        }

        new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Failed Logins (Threats/Errors)',
                        data: failedSeries,
                        backgroundColor: '#ef4444',
                        borderRadius: 4,
                        barPercentage: 0.6,
                        categoryPercentage: 0.7
                    },
                    {
                        label: 'Successful Logins (Authorized)',
                        data: successSeries,
                        backgroundColor: '#10b981',
                        borderRadius: 4,
                        barPercentage: 0.6,
                        categoryPercentage: 0.7
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: {
                            color: '#64748b',
                            font: { family: 'Inter', size: 11, weight: 500 }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: '#64748b',
                            font: { family: 'Inter', size: 11 }
                        },
                        grid: {
                            color: '#f1f5f9'
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        align: 'end',
                        labels: {
                            color: '#475569',
                            boxWidth: 12,
                            boxHeight: 12,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            font: { family: 'Inter', weight: 600, size: 11 }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleFont: { family: 'Inter', size: 12 },
                        bodyFont: { family: 'Inter', size: 12 },
                        padding: 10,
                        cornerRadius: 6
                    }
                }
            }
        });
    }
}
