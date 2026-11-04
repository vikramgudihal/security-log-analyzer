/**
 * CodeNova Security Log Analyzer - Frontend JavaScript
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
                    selectedFileName.textContent = `Selected: ${files[0].name} (${(files[0].size / 1024).toFixed(1)} KB)`;
                }
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0 && selectedFileName) {
                selectedFileName.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
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
                        '#991b1b', // Critical: Dark Red
                        '#dc2626', // High: Red
                        '#ea580c', // Medium: Orange
                        '#16a34a'  // Low: Green
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
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
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} alerts`;
                            }
                        }
                    }
                },
                cutout: '68%'
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
                        label: 'Failed Logins',
                        data: failedSeries.length > 0 ? failedSeries : [0],
                        backgroundColor: '#dc2626',
                        borderRadius: 4
                    },
                    {
                        label: 'Successful Logins',
                        data: successSeries.length > 0 ? successSeries : [0],
                        backgroundColor: '#16a34a',
                        borderRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { font: { family: 'Inter', size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0, font: { family: 'Inter', size: 11 } },
                        grid: { color: '#f1f5f9' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            boxWidth: 12,
                            font: { family: 'Inter', weight: 600 }
                        }
                    }
                }
            }
        });
    }
}
