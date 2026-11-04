/**
 * CodeNova Security Command Center - Frontend Controller
 * Integrates Chart.js visualizations, drop zone listeners, and UI interactivity.
 */

// Initialize Drag & Drop Zone if on Upload Page
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
            if (files.length > 0) {
                fileInput.files = files;
                if (selectedFileName) {
                    selectedFileName.textContent = `SELECTED FOR INGESTION: ${files[0].name} (${(files[0].size / 1024).toFixed(1)} KB)`;
                }
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0 && selectedFileName) {
                selectedFileName.textContent = `SELECTED FOR INGESTION: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
            }
        });
    }
});

/**
 * Initializes SOC Dashboard Charts with Chart.js
 * @param {Object} severityData - Counts for CRITICAL, HIGH, MEDIUM, LOW
 * @param {Object} hourlyActivity - Chronological hourly event breakdown
 */
function initDashboardCharts(severityData, hourlyActivity) {
    const isDark = document.body.classList.contains('theme-soc-dark');
    const textColor = isDark ? '#94a3b8' : '#475569';
    const gridColor = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';

    // 1. Severity Doughnut Chart
    const ctxDoughnut = document.getElementById('severityDoughnutChart');
    if (ctxDoughnut) {
        const labels = ['Critical', 'High', 'Medium', 'Low'];
        const dataValues = [
            severityData.CRITICAL || 0,
            severityData.HIGH || 0,
            severityData.MEDIUM || 0,
            severityData.LOW || 0
        ];

        new Chart(ctxDoughnut, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: dataValues,
                    backgroundColor: [
                        '#ef4444', // Critical: Red
                        '#f87171', // High: Light Red
                        '#f59e0b', // Medium: Orange
                        '#10b981'  // Low: Green
                    ],
                    borderWidth: 2,
                    borderColor: isDark ? '#111827' : '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
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

    // 2. Authentication Activity Timeline (Bar Chart)
    const ctxBar = document.getElementById('loginActivityChart');
    if (ctxBar) {
        const sortedHours = Object.keys(hourlyActivity).sort();
        const failedSeries = sortedHours.map(h => hourlyActivity[h].failed || 0);
        const successSeries = sortedHours.map(h => hourlyActivity[h].success || 0);

        // Friendly label: e.g. "Oct 21 14:00"
        const friendlyLabels = sortedHours.map(h => h.replace(/^\d{4}-/, ''));

        new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: friendlyLabels.length > 0 ? friendlyLabels : ['No Activity Recorded'],
                datasets: [
                    {
                        label: 'Failed Logins (Anomalies)',
                        data: failedSeries.length > 0 ? failedSeries : [0],
                        backgroundColor: '#ef4444',
                        borderRadius: 3
                    },
                    {
                        label: 'Authorized Logins',
                        data: successSeries.length > 0 ? successSeries : [0],
                        backgroundColor: '#10b981',
                        borderRadius: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0, color: textColor, font: { family: 'JetBrains Mono', size: 10 } },
                        grid: { color: gridColor }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: textColor,
                            boxWidth: 10,
                            font: { family: 'Inter', weight: 600, size: 11 }
                        }
                    }
                }
            }
        });
    }
}
