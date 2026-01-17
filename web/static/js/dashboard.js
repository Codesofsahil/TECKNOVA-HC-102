<<<<<<< HEAD
let severityChart, mitreChart, timelineChart, detectionChart, geoChart, alertTrendChart, responseTimeChart, threatActorChart, trendChart;
let trendData = [];
let trendLabels = [];
let lastAlertCount = 0;
const maxTrendPoints = 20;
=======
let severityChart, mitreChart, timelineChart, detectionChart, geoChart, alertTrendChart, responseTimeChart, threatActorChart;
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2

function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    event.target.classList.add('active');
    
    if (tabName === 'alerts') loadAlerts();
    if (tabName === 'incidents') loadIncidents();
    if (tabName === 'logs') loadLogs();
    if (tabName === 'analytics') loadAnalyticsCharts();
}

async function loadStats() {
    const response = await fetch('/api/stats');
    const stats = await response.json();
    
    document.getElementById('critical-count').textContent = stats.severity_distribution.CRITICAL;
    document.getElementById('high-count').textContent = stats.severity_distribution.HIGH;
    document.getElementById('incident-count').textContent = stats.active_incidents;
    document.getElementById('log-count').textContent = stats.total_logs;
    
    updateSeverityChart(stats.severity_distribution);
<<<<<<< HEAD
    updateLiveTrendChart(stats.total_alerts);
    updateTopAttackers(stats.top_attackers);
    updateAIPrediction();
=======
    updateMitreChart(stats.mitre_techniques);
    updateTopAttackers(stats.top_attackers);
    updateTimelineChart();
    updateGeoChart();
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
}

function updateSeverityChart(data) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    if (severityChart) severityChart.destroy();
    
<<<<<<< HEAD
    const total = data.CRITICAL + data.HIGH + data.MEDIUM + data.LOW + data.INFO;
    document.getElementById('severityTotal').querySelector('div').textContent = total;
    
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [data.CRITICAL, data.HIGH, data.MEDIUM, data.LOW, data.INFO],
<<<<<<< HEAD
                backgroundColor: [
                    '#ef4444',
                    '#f97316', 
                    '#eab308',
                    '#3b82f6',
                    '#6b7280'
                ],
                borderWidth: 0,
                hoverOffset: 15,
=======
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'],
                borderWidth: 0,
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                hoverBorderWidth: 3,
                hoverBorderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
<<<<<<< HEAD
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1500,
                easing: 'easeInOutQuart'
            },
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
            plugins: {
                legend: { 
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true,
<<<<<<< HEAD
                        font: { size: 13, weight: '600' },
                        color: '#fff',
                        generateLabels: function(chart) {
                            const data = chart.data;
                            return data.labels.map((label, i) => ({
                                text: `${label}: ${data.datasets[0].data[i]}`,
                                fillStyle: data.datasets[0].backgroundColor[i],
                                hidden: false,
                                index: i
                            }));
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 },
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '70%'
=======
                        font: { size: 12 }
                    }
                }
            },
            cutout: '60%'
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
        }
    });
}

<<<<<<< HEAD
function updateLiveTrendChart(alertCount) {
    const ctx = document.getElementById('trendChart').getContext('2d');
    
    // Only add point if alert count increased
    if (alertCount > lastAlertCount || trendData.length === 0) {
        const now = new Date();
        const timeLabel = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        trendLabels.push(timeLabel);
        trendData.push(alertCount || 0);
        lastAlertCount = alertCount;
        
        // Keep only last 20 points
        if (trendLabels.length > maxTrendPoints) {
            trendLabels.shift();
            trendData.shift();
        }
    }
    
    if (trendChart) trendChart.destroy();
    
    trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trendLabels,
            datasets: [{
                label: 'Total Alerts',
                data: trendData,
                borderColor: '#8b5cf6',
                backgroundColor: function(context) {
                    const ctx = context.chart.ctx;
                    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                    gradient.addColorStop(0, 'rgba(139, 92, 246, 0.4)');
                    gradient.addColorStop(1, 'rgba(139, 92, 246, 0.0)');
                    return gradient;
                },
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#8b5cf6',
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                pointRadius: 5,
                pointHoverRadius: 8,
                pointHoverBackgroundColor: '#a78bfa',
                pointHoverBorderWidth: 3
=======
function updateMitreChart(data) {
    const ctx = document.getElementById('mitreChart').getContext('2d');
    if (mitreChart) mitreChart.destroy();
    
    const labels = Object.keys(data).slice(0, 5).map(label => label.split(' - ')[1] || label);
    const values = Object.values(data).slice(0, 5);
    
    mitreChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Occurrences',
                data: values,
                backgroundColor: 'rgba(102, 126, 234, 0.8)',
                borderColor: '#667eea',
                borderWidth: 1,
                borderRadius: 4,
                borderSkipped: false
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
<<<<<<< HEAD
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: { 
                    display: true,
                    labels: {
                        color: '#fff',
                        font: { size: 13, weight: '600' },
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 },
                    callbacks: {
                        label: function(context) {
                            return `Alerts: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { 
                        color: 'rgba(255,255,255,0.1)',
                        drawBorder: false
                    },
                    ticks: { 
                        color: '#fff', 
                        font: { size: 11 },
                        padding: 8
                    }
=======
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { font: { size: 11 } }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                },
                x: {
                    grid: { display: false },
                    ticks: { 
<<<<<<< HEAD
                        color: '#fff',
                        font: { size: 9 },
                        maxRotation: 45,
                        minRotation: 45
=======
                        font: { size: 10 },
                        maxRotation: 45
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                    }
                }
            }
        }
    });
}

function updateTimelineChart() {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    if (timelineChart) timelineChart.destroy();
    
    // Generate sample timeline data
    const hours = [];
    const alertCounts = [];
    for (let i = 11; i >= 0; i--) {
        const hour = new Date();
        hour.setHours(hour.getHours() - i);
        hours.push(hour.getHours() + ':00');
        alertCounts.push(Math.floor(Math.random() * 15) + 1);
    }
    
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours,
            datasets: [{
                label: 'Alerts',
                data: alertCounts,
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#dc3545',
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
<<<<<<< HEAD
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    ticks: { font: { size: 10 }, color: '#fff' }
=======
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { font: { size: 10 } }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                },
                x: {
                    grid: { display: false },
                    ticks: { 
                        font: { size: 10 },
<<<<<<< HEAD
                        maxTicksLimit: 8,
                        color: '#fff'
=======
                        maxTicksLimit: 8
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                    }
                }
            }
        }
    });
}

function updateGeoChart() {
    const ctx = document.getElementById('geoChart').getContext('2d');
    if (geoChart) geoChart.destroy();
    
    const countries = ['Russia', 'China', 'USA', 'Ukraine', 'Internal'];
    const attacks = [25, 18, 12, 8, 15];
    
    geoChart = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: countries,
            datasets: [{
                data: attacks,
                backgroundColor: [
                    'rgba(220, 53, 69, 0.8)',
                    'rgba(255, 193, 7, 0.8)',
                    'rgba(23, 162, 184, 0.8)',
                    'rgba(40, 167, 69, 0.8)',
                    'rgba(108, 117, 125, 0.8)'
                ],
                borderColor: [
                    '#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        usePointStyle: true,
<<<<<<< HEAD
                        font: { size: 11 },
                        color: '#fff'
=======
                        font: { size: 11 }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                    }
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
<<<<<<< HEAD
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    ticks: { display: false },
                    pointLabels: { color: '#fff' }
=======
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { display: false }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                }
            }
        }
    });
}

async function loadAlerts() {
    const severity = document.getElementById('severity-filter')?.value || '';
    const status = document.getElementById('status-filter')?.value || '';
    
    const response = await fetch(`/api/alerts?severity=${severity}&status=${status}`);
    const alerts = await response.json();
    
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';
    
    alerts.forEach(alert => {
        const alertCard = document.createElement('div');
        alertCard.className = `alert-card severity-${alert.severity.toLowerCase()}`;
        alertCard.innerHTML = `
            <div class="alert-header">
                <h4>${alert.title}</h4>
                <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
            </div>
            <div class="alert-body">
                <p><strong>Source IP:</strong> ${alert.source_ip || 'N/A'}</p>
                <p><strong>MITRE ATT&CK:</strong> ${alert.mitre_attack || 'N/A'}</p>
                <p><strong>Priority Score:</strong> ${alert.priority_score.toFixed(1)}/10</p>
                <p>${alert.description}</p>
                <p class="timestamp">${new Date(alert.timestamp).toLocaleString()}</p>
            </div>
            <div class="alert-footer">
                <span class="status-badge">${alert.status}</span>
            </div>
        `;
        container.appendChild(alertCard);
    });
}

async function loadIncidents() {
    const response = await fetch('/api/incidents');
    const incidents = await response.json();
    
    const container = document.getElementById('incidents-container');
    container.innerHTML = '';
    
    incidents.forEach(incident => {
        const incidentCard = document.createElement('div');
        incidentCard.className = 'incident-card';
        incidentCard.innerHTML = `
            <div class="incident-header">
                <h4>${incident.title}</h4>
                <span class="badge badge-${incident.severity.toLowerCase()}">${incident.severity}</span>
            </div>
            <div class="incident-body">
                <p><strong>Incident ID:</strong> ${incident.incident_id}</p>
                <p><strong>Status:</strong> ${incident.status}</p>
                <p><strong>Created:</strong> ${new Date(incident.created_at).toLocaleString()}</p>
                <div class="timeline">
                    <h5>Timeline:</h5>
                    ${incident.timeline.map(t => `
                        <div class="timeline-item">
                            <span class="time">${new Date(t.timestamp).toLocaleTimeString()}</span>
                            <span>${t.action}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        container.appendChild(incidentCard);
    });
}

async function loadLogs() {
<<<<<<< HEAD
    try {
        const response = await fetch('/api/logs?limit=50');
        const logs = await response.json();
        
        const container = document.getElementById('logs-container');
        container.innerHTML = '';
        
        if (!logs || logs.length === 0) {
            container.innerHTML = '<div class="text-gray-400 text-center py-8">No logs available. Generate test data using test_generator.py</div>';
            return;
        }
        
        logs.reverse().forEach((log, index) => {
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry glass rounded-xl p-4 severity-${(log.severity || 'INFO').toLowerCase()}`;
            logEntry.style.animationDelay = `${index * 0.02}s`;
            logEntry.style.animation = 'fadeIn 0.3s ease-out forwards';
            
            const severityColors = {
                CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/50',
                HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
                MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
                LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
                INFO: 'bg-gray-500/20 text-gray-400 border-gray-500/50'
            };
            
            const severity = log.severity || 'INFO';
            const colorClass = severityColors[severity] || severityColors.INFO;
            
            logEntry.innerHTML = `
                <div style="display: flex; align-items: center; gap: 16px;">
                    <div style="flex-shrink: 0; width: 140px;">
                        <div style="color: rgba(255,255,255,0.5); font-size: 12px; font-family: monospace;">${log.timestamp || new Date().toISOString()}</div>
                    </div>
                    <div style="flex-shrink: 0; width: 120px;">
                        <div style="color: #60a5fa; font-size: 13px; font-family: monospace; font-weight: 500;">${log.source_ip || 'N/A'}</div>
                    </div>
                    <div style="flex-shrink: 0;">
                        <span class="badge ${colorClass} border" style="font-size: 10px; padding: 4px 10px;">${severity}</span>
                    </div>
                    <div style="flex: 1; color: rgba(255,255,255,0.8); font-size: 13px; line-height: 1.5;">
                        ${log.message || log.event_type || JSON.stringify(log).substring(0, 100)}
                    </div>
                </div>
            `;
            container.appendChild(logEntry);
        });
    } catch (error) {
        console.error('Error loading logs:', error);
        const container = document.getElementById('logs-container');
        container.innerHTML = '<div class="text-red-400 text-center py-8">Error loading logs. Check console for details.</div>';
    }
=======
    const response = await fetch('/api/logs?limit=50');
    const logs = await response.json();
    
    const container = document.getElementById('logs-container');
    container.innerHTML = '';
    
    logs.reverse().forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `
            <span class="log-time">${log.timestamp}</span>
            <span class="log-ip">${log.source_ip || 'N/A'}</span>
            <span class="log-severity severity-${log.severity.toLowerCase()}">${log.severity}</span>
            <span class="log-message">${log.message || log.event_type || 'No message'}</span>
        `;
        container.appendChild(logEntry);
    });
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
}

function filterAlerts() {
    loadAlerts();
}

function searchLogs() {
    const searchTerm = document.getElementById('log-search').value.toLowerCase();
    const logEntries = document.querySelectorAll('.log-entry');
    
    logEntries.forEach(entry => {
        const text = entry.textContent.toLowerCase();
<<<<<<< HEAD
        if (text.includes(searchTerm)) {
            entry.style.display = 'block';
            entry.style.animation = 'fadeIn 0.3s ease-out';
        } else {
            entry.style.display = 'none';
        }
=======
        entry.style.display = text.includes(searchTerm) ? 'flex' : 'none';
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    });
}

function updateTime() {
    document.getElementById('current-time').textContent = new Date().toLocaleString();
}

// Auto-refresh
setInterval(() => {
    loadStats();
    updateTime();
}, 5000);

// Notification System
function showNotification(title, message, severity = 'info', duration = 0) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.className = `notification ${severity.toLowerCase()}`;
    
    const notificationId = 'notif_' + Date.now();
    notification.id = notificationId;
    
<<<<<<< HEAD
    const icons = {
        CRITICAL: '<svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>',
        HIGH: '<svg class="w-6 h-6 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>',
        MEDIUM: '<svg class="w-6 h-6 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
        INFO: '<svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
    };
    
    notification.innerHTML = `
        <div style="position: relative; z-index: 1;">
            <div style="display: flex; align-items-start; gap: 12px;">
                <div style="flex-shrink: 0; margin-top: 2px;">
                    ${icons[severity] || icons.INFO}
                </div>
                <div style="flex: 1;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                        <div style="font-weight: 700; font-size: 15px; color: white;">${title}</div>
                        <button onclick="closeNotification('${notificationId}')" style="background: none; border: none; color: rgba(255,255,255,0.6); cursor: pointer; font-size: 20px; line-height: 1; padding: 0; margin-left: 12px; transition: color 0.2s;" onmouseover="this.style.color='white'" onmouseout="this.style.color='rgba(255,255,255,0.6)'">&times;</button>
                    </div>
                    <div style="color: rgba(255,255,255,0.8); font-size: 13px; line-height: 1.5; margin-bottom: 8px;">${message}</div>
                    <div style="color: rgba(255,255,255,0.5); font-size: 11px;">${new Date().toLocaleTimeString()}</div>
                </div>
            </div>
        </div>
=======
    notification.innerHTML = `
        <div class="notification-header">
            <div class="notification-title">${title}</div>
            <button class="notification-close" onclick="closeNotification('${notificationId}')">&times;</button>
        </div>
        <div class="notification-body">${message}</div>
        <div class="notification-time">${new Date().toLocaleTimeString()}</div>
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    `;
    
    container.appendChild(notification);
    
<<<<<<< HEAD
=======
    // Only auto-remove if duration > 0
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    if (duration > 0) {
        setTimeout(() => {
            closeNotification(notificationId);
        }, duration);
    }
    
<<<<<<< HEAD
=======
    // Play sound for critical/high alerts
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    if (severity === 'CRITICAL' || severity === 'HIGH') {
        playAlertSound();
    }
}

function closeNotification(notificationId) {
    const notification = document.getElementById(notificationId);
    if (notification) {
<<<<<<< HEAD
        notification.style.animation = 'slideOutRight 0.3s ease-out forwards';
=======
        notification.style.animation = 'slideOut 0.3s ease-out';
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
        setTimeout(() => {
            notification.remove();
        }, 300);
    }
}

<<<<<<< HEAD
// Add slideOut animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutRight {
        from { transform: translateX(0) scale(1); opacity: 1; }
        to { transform: translateX(400px) scale(0.8); opacity: 0; }
    }
`;
document.head.appendChild(style);

=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
function playAlertSound() {
    const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT');
    audio.volume = 0.3;
    audio.play().catch(() => {});
}

// Check for new logs and show notifications
let lastLogCount = 0;
async function checkForNewLogs() {
    try {
        const response = await fetch('/api/logs?limit=100');
        const logs = await response.json();
        
        if (logs.length > lastLogCount) {
            const newLogs = logs.slice(lastLogCount);
            newLogs.forEach(log => {
                if (log.severity && ['CRITICAL', 'HIGH', 'MEDIUM'].includes(log.severity)) {
                    showNotification(
                        `📋 New ${log.severity} Log`,
                        `${log.event_type || 'Event'} from ${log.source_ip || 'Unknown'}: ${log.message || 'No message'}`,
                        log.severity,
<<<<<<< HEAD
                        1000
=======
                        0
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                    );
                }
            });
        }
        
        lastLogCount = logs.length;
    } catch (error) {
        console.error('Error checking logs:', error);
    }
}

// Check for new alerts and show notifications
let lastAlertCount = 0;
async function checkForNewAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const alerts = await response.json();
        
        if (alerts.length > lastAlertCount) {
            const newAlerts = alerts.slice(lastAlertCount);
            newAlerts.forEach(alert => {
                showNotification(
                    `🚨 ${alert.severity} Alert`,
                    `${alert.title} from ${alert.source_ip || 'Unknown'}`,
                    alert.severity,
<<<<<<< HEAD
                    1000
=======
                    0
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                );
            });
        }
        
        lastAlertCount = alerts.length;
    } catch (error) {
        console.error('Error checking alerts:', error);
    }
}

// Test notification function
function testNotification() {
    showNotification(
        '🧪 Test Alert',
        'This is a test notification to verify the popup system is working.',
        'HIGH',
<<<<<<< HEAD
        1000
=======
        8000
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    );
}

function updateTopAttackers(attackers) {
    const tbody = document.getElementById('top-attackers-body');
    tbody.innerHTML = '';
    
    attackers.forEach(attacker => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${attacker.ip}</td>
            <td><span class="badge">${attacker.count}</span></td>
            <td><span class="badge badge-danger">Suspicious</span></td>
        `;
    });
}

function loadAnalyticsCharts() {
    updateAlertTrendChart();
    updateDetectionChart();
<<<<<<< HEAD
=======
    updateResponseTimeChart();
    updateThreatActorChart();
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
}

function updateAlertTrendChart() {
    const ctx = document.getElementById('alertTrendChart').getContext('2d');
    if (alertTrendChart) alertTrendChart.destroy();
    
<<<<<<< HEAD
    fetch('/api/alerts')
        .then(res => res.json())
        .then(alerts => {
            const last7Days = {};
            for (let i = 6; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                const dateStr = date.toLocaleDateString('en-US', { weekday: 'short' });
                last7Days[dateStr] = { critical: 0, high: 0 };
            }
            
            alerts.forEach(alert => {
                const alertDate = new Date(alert.timestamp);
                const dateStr = alertDate.toLocaleDateString('en-US', { weekday: 'short' });
                if (last7Days[dateStr]) {
                    if (alert.severity === 'CRITICAL') last7Days[dateStr].critical++;
                    if (alert.severity === 'HIGH') last7Days[dateStr].high++;
                }
            });
            
            const days = Object.keys(last7Days);
            const criticalData = Object.values(last7Days).map(d => d.critical);
            const highData = Object.values(last7Days).map(d => d.high);
            
            alertTrendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: days,
                    datasets: [
                        {
                            label: 'Critical',
                            data: criticalData,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            borderWidth: 3,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'High',
                            data: highData,
                            borderColor: '#f97316',
                            backgroundColor: 'rgba(249, 115, 22, 0.1)',
                            borderWidth: 3,
                            fill: false,
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top', labels: { usePointStyle: true, color: '#fff' } }
                    },
                    scales: {
                        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#fff' } },
                        x: { grid: { display: false }, ticks: { color: '#fff' } }
                    }
                }
            });
        });
=======
    const days = [];
    const criticalAlerts = [];
    const highAlerts = [];
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        days.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
        criticalAlerts.push(Math.floor(Math.random() * 8) + 2);
        highAlerts.push(Math.floor(Math.random() * 12) + 5);
    }
    
    alertTrendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: days,
            datasets: [
                {
                    label: 'Critical',
                    data: criticalAlerts,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    borderWidth: 3,
                    fill: false,
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: highAlerts,
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253, 126, 20, 0.1)',
                    borderWidth: 3,
                    fill: false,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'top', labels: { usePointStyle: true } }
            },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.1)' } },
                x: { grid: { display: false } }
            }
        }
    });
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
}

function updateDetectionChart() {
    const ctx = document.getElementById('detectionChart').getContext('2d');
    if (detectionChart) detectionChart.destroy();
    
<<<<<<< HEAD
    fetch('/api/alerts')
        .then(res => res.json())
        .then(alerts => {
            const methods = {
                'Rule-based': 0,
                'ML Anomaly': 0,
                'Behavioral': 0,
                'Signature': 0,
                'Threat Intel': 0
            };
            
            alerts.forEach(alert => {
                const rule = alert.rule_name || '';
                if (rule.includes('ML') || rule.includes('Anomaly')) methods['ML Anomaly']++;
                else if (rule.includes('Behavioral')) methods['Behavioral']++;
                else if (rule.includes('Signature')) methods['Signature']++;
                else if (rule.includes('Intel')) methods['Threat Intel']++;
                else methods['Rule-based']++;
            });
            
            detectionChart = new Chart(ctx, {
                type: 'radar',
                data: {
                    labels: Object.keys(methods),
                    datasets: [{
                        label: 'Detections',
                        data: Object.values(methods),
                        borderColor: '#8b5cf6',
                        backgroundColor: 'rgba(139, 92, 246, 0.2)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        r: {
                            beginAtZero: true,
                            ticks: { display: true, color: '#fff' },
                            pointLabels: { color: '#fff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    }
                }
            });
        });
=======
    detectionChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['Rule-based', 'ML Anomaly', 'Behavioral', 'Signature', 'Threat Intel'],
            datasets: [{
                label: 'Effectiveness',
                data: [85, 78, 92, 88, 82],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.2)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { display: false }
                }
            }
        }
    });
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
}

function updateResponseTimeChart() {
    const ctx = document.getElementById('responseTimeChart').getContext('2d');
    if (responseTimeChart) responseTimeChart.destroy();
    
    responseTimeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['< 1min', '1-5min', '5-15min', '15-30min', '> 30min'],
            datasets: [{
                data: [45, 32, 18, 8, 3],
                backgroundColor: ['#28a745', '#17a2b8', '#ffc107', '#fd7e14', '#dc3545'],
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
<<<<<<< HEAD
                y: { beginAtZero: true, ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
                x: { grid: { display: false }, ticks: { color: '#fff' } }
=======
                y: { beginAtZero: true },
                x: { grid: { display: false } }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
            }
        }
    });
}

function updateThreatActorChart() {
    const ctx = document.getElementById('threatActorChart').getContext('2d');
    if (threatActorChart) threatActorChart.destroy();
    
    threatActorChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['APT Groups', 'Script Kiddies', 'Insider Threats', 'Ransomware', 'Botnets'],
            datasets: [{
                data: [15, 35, 8, 22, 20],
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
<<<<<<< HEAD
                    labels: { usePointStyle: true, font: { size: 11 }, color: '#fff' }
=======
                    labels: { usePointStyle: true, font: { size: 11 } }
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                }
            },
            cutout: '50%'
        }
    });
}

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    updateTime();
    
    // Show welcome notification
    setTimeout(() => {
        showNotification(
            '🛡️ SOC Platform Active',
            'Security Operations Center is now monitoring. Core features operational.',
            'INFO',
<<<<<<< HEAD
            1000
=======
            10000
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
        );
    }, 2000);
    
    // Add test notification button
    const header = document.querySelector('header');
    const testBtn = document.createElement('button');
    testBtn.textContent = '🔔 Test Alert';
    testBtn.style.cssText = 'padding: 8px 12px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px;';
    testBtn.onclick = testNotification;
    header.appendChild(testBtn);
    
    // Start checking for new alerts and logs
    setInterval(() => {
        checkForNewAlerts();
        checkForNewLogs();
    }, 5000);
});
<<<<<<< HEAD

// Report Generation Functions
async function generateExecutiveReport() {
    try {
        const response = await fetch('/api/reports/executive');
        const report = await response.json();
        
        downloadJSON(report, 'executive-report.json');
        addRecentReport('Executive Summary', 'executive-report.json');
        showNotification('📄 Report Generated', 'Executive summary report downloaded successfully', 'INFO', 1000);
    } catch (error) {
        showNotification('❌ Error', 'Failed to generate report', 'HIGH', 1000);
    }
}

async function generateComplianceReport() {
    try {
        const framework = document.getElementById('complianceFramework').value;
        const response = await fetch(`/api/compliance/report?framework=${framework}`);
        const report = await response.json();
        
        downloadJSON(report, `compliance-${framework}-report.json`);
        addRecentReport(`Compliance Report (${framework})`, `compliance-${framework}-report.json`);
        showNotification('📄 Report Generated', `${framework} compliance report downloaded`, 'INFO', 1000);
    } catch (error) {
        showNotification('❌ Error', 'Failed to generate compliance report', 'HIGH', 1000);
    }
}

function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function generatePDF() {
    try {
        const alerts = document.querySelectorAll('.alert-card');
        if (alerts.length === 0) {
            showNotification('No Alerts', 'No alerts to export', 'WARNING');
            return;
        }
        
        let pdfContent = 'SOC PLATFORM - ALERT REPORT\\n';
        pdfContent += '='.repeat(80) + '\\n';
        pdfContent += `Generated: ${new Date().toLocaleString()}\\n`;
        pdfContent += '='.repeat(80) + '\\n\\n';
        
        const alertsData = await fetch('/api/alerts').then(r => r.json());
        
        alertsData.forEach((alert, index) => {
            pdfContent += `\\n[${index + 1}] ${alert.title}\\n`;
            pdfContent += '-'.repeat(80) + '\\n';
            pdfContent += `Severity: ${alert.severity}\\n`;
            pdfContent += `Status: ${alert.status}\\n`;
            pdfContent += `Priority Score: ${alert.priority_score.toFixed(1)}/10\\n`;
            pdfContent += `Source IP: ${alert.source_ip || 'N/A'}\\n`;
            pdfContent += `MITRE ATT&CK: ${alert.mitre_attack || 'N/A'}\\n`;
            pdfContent += `Timestamp: ${new Date(alert.timestamp).toLocaleString()}\\n`;
            pdfContent += `Description: ${alert.description}\\n`;
        });
        
        const blob = new Blob([pdfContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `alerts_report_${new Date().getTime()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('Report Generated', 'Alert report downloaded successfully', 'INFO', 1000);
    } catch (error) {
        console.error('PDF generation error:', error);
        showNotification('Error', 'Failed to generate PDF report', 'ERROR');
    }
}

async function generateDemoAttacks() {
    try {
        const response = await fetch('/api/demo-attacks', { method: 'POST' });
        const result = await response.json();
        showNotification('Demo Attacks Sent', `${result.attacks_sent} simulated attacks generated`, 'SUCCESS', 2000);
        setTimeout(() => loadAlerts(), 1000);
    } catch (error) {
        console.error('Demo attacks error:', error);
        showNotification('Error', 'Failed to generate demo attacks', 'ERROR');
    }
}

function addRecentReport(name, filename) {
    const container = document.getElementById('recentReports');
    if (container.querySelector('.text-center')) {
        container.innerHTML = '';
    }
    
    const reportItem = document.createElement('div');
    reportItem.className = 'glass rounded-xl p-4 flex items-center justify-between hover:bg-white/10 transition-all';
    reportItem.innerHTML = `
        <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            </div>
            <div>
                <div class="text-white font-medium">${name}</div>
                <div class="text-gray-400 text-xs">${new Date().toLocaleString()}</div>
            </div>
        </div>
        <div class="text-green-400 text-sm">✓ Downloaded</div>
    `;
    container.insertBefore(reportItem, container.firstChild);
}
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
