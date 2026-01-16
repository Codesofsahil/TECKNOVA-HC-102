let severityChart, mitreChart, timelineChart, detectionChart, geoChart, alertTrendChart, responseTimeChart, threatActorChart;

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
    updateMitreChart(stats.mitre_techniques);
    updateTopAttackers(stats.top_attackers);
    updateTimelineChart();
    updateGeoChart();
}

function updateSeverityChart(data) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    if (severityChart) severityChart.destroy();
    
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [data.CRITICAL, data.HIGH, data.MEDIUM, data.LOW, data.INFO],
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'],
                borderWidth: 0,
                hoverBorderWidth: 3,
                hoverBorderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true,
                        font: { size: 12 }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

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
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { font: { size: 11 } }
                },
                x: {
                    grid: { display: false },
                    ticks: { 
                        font: { size: 10 },
                        maxRotation: 45
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
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { font: { size: 10 } }
                },
                x: {
                    grid: { display: false },
                    ticks: { 
                        font: { size: 10 },
                        maxTicksLimit: 8
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
                        font: { size: 11 }
                    }
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    ticks: { display: false }
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
}

function filterAlerts() {
    loadAlerts();
}

function searchLogs() {
    const searchTerm = document.getElementById('log-search').value.toLowerCase();
    const logEntries = document.querySelectorAll('.log-entry');
    
    logEntries.forEach(entry => {
        const text = entry.textContent.toLowerCase();
        entry.style.display = text.includes(searchTerm) ? 'flex' : 'none';
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
    
    notification.innerHTML = `
        <div class="notification-header">
            <div class="notification-title">${title}</div>
            <button class="notification-close" onclick="closeNotification('${notificationId}')">&times;</button>
        </div>
        <div class="notification-body">${message}</div>
        <div class="notification-time">${new Date().toLocaleTimeString()}</div>
    `;
    
    container.appendChild(notification);
    
    // Only auto-remove if duration > 0
    if (duration > 0) {
        setTimeout(() => {
            closeNotification(notificationId);
        }, duration);
    }
    
    // Play sound for critical/high alerts
    if (severity === 'CRITICAL' || severity === 'HIGH') {
        playAlertSound();
    }
}

function closeNotification(notificationId) {
    const notification = document.getElementById(notificationId);
    if (notification) {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }
}

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
                        0
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
                    0
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
        8000
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
    updateResponseTimeChart();
    updateThreatActorChart();
}

function updateAlertTrendChart() {
    const ctx = document.getElementById('alertTrendChart').getContext('2d');
    if (alertTrendChart) alertTrendChart.destroy();
    
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
}

function updateDetectionChart() {
    const ctx = document.getElementById('detectionChart').getContext('2d');
    if (detectionChart) detectionChart.destroy();
    
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
                y: { beginAtZero: true },
                x: { grid: { display: false } }
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
                    labels: { usePointStyle: true, font: { size: 11 } }
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
            10000
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
