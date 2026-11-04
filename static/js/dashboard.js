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
                dropZone.style.borderColor = '#2563eb';
                dropZone.style.backgroundColor = '#eff6ff';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropZone.style.borderColor = '#cbd5e1';
                dropZone.style.backgroundColor = '#f8fafc';
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
 * Initializes clean, professional Chart.js charts on the dashboard.
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
                        '#dc2626', // Critical (Red)
                        '#f87171', // High (Light Red)
                        '#f59e0b', // Medium (Amber)
                        '#16a34a'  // Low (Green)
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
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
                cutout: '70%'
            }
        });
    }

    // 2. Hourly Authentication Timeline (Bar Chart)
    const ctxBar = document.getElementById('loginActivityChart');
    if (ctxBar) {
        const sortedHours = Object.keys(hourlyActivity).sort();
        const failedSeries = sortedHours.map(h => hourlyActivity[h].failed || 0);
        const successSeries = sortedHours.map(h => hourlyActivity[h].success || 0);
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
                        borderRadius: 3
                    },
                    {
                        label: 'Successful Logins',
                        data: successSeries.length > 0 ? successSeries : [0],
                        backgroundColor: '#16a34a',
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
                        ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0, color: '#64748b', font: { family: 'Inter', size: 11 } },
                        grid: { color: '#f1f5f9' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#475569',
                            boxWidth: 12,
                            font: { family: 'Inter', weight: 600, size: 11 }
                        }
                    }
                }
            }
        });
    }
}
