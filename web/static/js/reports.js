// Report Generation Functions - Added to fix missing functions
async function generateExecutiveReport() {
    try {
        const response = await fetch('/api/reports/executive');
        const report = await response.json();
        
        downloadJSON(report, 'executive-report.json');
        addRecentReport('Executive Summary', 'executive-report.json');
        showNotification('📄 Report Generated', 'Executive summary report downloaded successfully', 'INFO', 3000);
    } catch (error) {
        showNotification('❌ Error', 'Failed to generate report: ' + error.message, 'HIGH', 5000);
    }
}

async function generateComplianceReport() {
    try {
        const framework = document.getElementById('complianceFramework').value;
        const response = await fetch(`/api/compliance/report?framework=${framework}`);
        const report = await response.json();
        
        downloadJSON(report, `compliance-${framework}-report.json`);
        addRecentReport(`Compliance Report (${framework})`, `compliance-${framework}-report.json`);
        showNotification('📄 Report Generated', `${framework} compliance report downloaded`, 'INFO', 3000);
    } catch (error) {
        showNotification('❌ Error', 'Failed to generate compliance report: ' + error.message, 'HIGH', 5000);
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

function addRecentReport(name, filename) {
    const container = document.getElementById('recentReports');
    if (container && container.querySelector('.text-center')) {
        container.innerHTML = '';
    }
    
    if (container) {
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
}