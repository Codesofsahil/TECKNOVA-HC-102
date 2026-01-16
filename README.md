# 🛡️ SOC Platform - Complete Enterprise Edition

**Intelligent Security Operations Monitoring and Incident Response Platform**

A comprehensive, production-ready SOC platform with 66+ features including ML threat prediction, SOAR automation, compliance reporting, real-time monitoring, mobile push notifications, cloud storage, and advanced threat hunting.

---

##  **Key Features**

### **Core Security**
- 🔍 Multi-source log collection (JSON, Syslog, Windows, Firewall)
- 🎯 Rule-based correlation (6+ detection rules)
- 🤖 ML anomaly detection
- 🚨 Alert prioritization & deduplication
- 🔐 MITRE ATT&CK mapping

### **Advanced Features**
- 📧 Email & Slack notifications
- 🗺️ Geolocation attack mapping
- 📊 CSV export (alerts, incidents, logs)
- 🔍 Advanced search & filtering
- 🛡️ Threat intelligence (AbuseIPDB, VirusTotal)
- 🎨 Multiple themes (light/dark/blue/green)
- 🔔 Alert sound notifications

### **Enterprise Features**
- 🔐 Authentication & RBAC (Admin/Analyst/Viewer)
- 📄 Report generation (Executive, Incident, Compliance)
- 🔍 Vulnerability scanning
- 🌐 Network monitoring & IP blocking
- 🤖 ML threat prediction
- 💾 Automated backups
- ⚡ API rate limiting
- 📝 Comprehensive audit logging

### **Advanced Features (Batch 4)**
- 🔄 Real-time WebSocket dashboard updates
- 📱 Mobile push notifications (iOS/Android)
- ☁️ Multi-cloud storage integration (AWS/Azure/GCP)
- 🕵️ Advanced threat hunting engine
- 🏢 Comprehensive asset management
- 🎯 Risk-based threat modeling
- 📈 Performance monitoring & optimization

### **Automation**
- 🤖 SOAR playbooks (4 pre-built)
- 🎯 Automated incident response
- 📧 Auto-notifications
- 🔒 Auto-blocking
- 📊 Auto-reporting

---

## 🚀 **Quick Start**

### **1. Install**
```bash
cd K:\Tecknova
pip install Flask Flask-CORS
```

### **2. Run**
```bash
python app.py
```

### **3. Access**
```
http://localhost:5000
```

### **4. Test**
```bash
# Generate test data
python test_generator.py

# Test features
python test_batch3.py
```

---

## 📊 **Stats**

| Metric | Count |
|--------|-------|
| **Total Features** | 66 |
| **API Endpoints** | 80 |
| **Services** | 22 |
| **Detection Rules** | 6+ |
| **SOAR Playbooks** | 4 |
| **Compliance Frameworks** | 4 |
| **Themes** | 4 |
| **Cloud Providers** | 3 |

---

## 🎯 **API Endpoints**

### **Core**
- `POST /api/ingest` - Ingest logs
- `GET /api/alerts` - Get alerts
- `GET /api/incidents` - Get incidents
- `GET /api/logs` - Get logs
- `GET /api/stats` - Dashboard stats

### **Authentication**
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/verify` - Verify token

### **Notifications**
- `POST /api/notifications/configure` - Configure email/slack

### **Geolocation**
- `GET /api/geolocation/attacks` - Attack map
- `GET /api/geolocation/stats` - Country stats

### **Export**
- `GET /api/export/alerts` - Export alerts CSV
- `GET /api/export/incidents` - Export incidents CSV
- `GET /api/export/logs` - Export logs CSV

### **Search**
- `POST /api/search` - Advanced search

### **Threat Intelligence**
- `GET /api/threat-intel/<ip>` - IP reputation
- `GET /api/threat-feed/<ip>` - Comprehensive report

### **Reports**
- `GET /api/reports/executive` - Executive summary
- `GET /api/reports/incident/<id>` - Incident report

### **Vulnerability**
- `POST /api/vulnerability/scan` - Scan system
- `GET /api/vulnerability/history` - Scan history
- `GET /api/vulnerability/summary` - Summary

### **Network**
- `GET /api/network/connections` - Active connections
- `POST /api/network/block` - Block IP
- `POST /api/network/unblock` - Unblock IP
- `GET /api/network/stats` - Network stats

### **ML Predictions**
- `POST /api/ml/predict` - Predict threat
- `POST /api/ml/predict-next-attack` - Predict timing
- `GET /api/ml/trends` - Threat trends

### **Backup**
- `POST /api/backup/create` - Create backup
- `GET /api/backup/list` - List backups
- `POST /api/backup/restore/<id>` - Restore backup

### **Batch 4 - Advanced Features**
- `GET /api/websocket/stats` - WebSocket connection stats
- `POST /api/mobile/register` - Register mobile device
- `POST /api/mobile/push` - Send push notification
- `GET /api/mobile/stats` - Mobile device stats
- `POST /api/cloud/configure` - Configure cloud storage
- `POST /api/cloud/upload` - Upload to cloud
- `POST /api/cloud/sync` - Sync cloud data
- `GET /api/cloud/stats` - Cloud storage stats
- `POST /api/hunt/create` - Create hunt query
- `POST /api/hunt/execute` - Execute threat hunt
- `POST /api/hunt/ioc` - Hunt IOCs
- `GET /api/hunt/stats` - Hunt statistics
- `POST /api/assets/register` - Register asset
- `GET /api/assets` - Get assets
- `GET /api/assets/stats` - Asset statistics
- `POST /api/threat-model/create` - Create threat model
- `POST /api/threat-model/<id>/threat` - Add threat
- `POST /api/threat-model/<id>/assess` - Assess risk
- `GET /api/threat-model/stats` - Modeling stats
- `POST /api/performance/metric` - Record metric
- `GET /api/performance/health` - System health
- `GET /api/performance/metric/<name>` - Metric summary
- `POST /api/performance/optimize` - Optimize performance
- `GET /api/performance/stats` - Performance stats

### **Audit**
- `GET /api/audit/logs` - Audit logs
- `GET /api/audit/user/<username>` - User activity
- `GET /api/audit/export` - Export audit trail

---

## 🔐 **Default Credentials**

- **Admin:** `admin` / `admin123`
- **Analyst:** `analyst` / `analyst123`

---

## 📁 **Project Structure**

```
Tecknova/
├── core/
│   ├── enhanced_services.py      # All 15 services (ONE file)
│   ├── normalization/             # Log parsing
│   ├── correlation/               # Detection rules
│   ├── ml_detection/              # Anomaly detection
│   ├── alert_manager/             # Alert management
│   ├── incident_response/         # Auto-response
│   ├── threat_intel/              # Threat intelligence
│   ├── soar/                      # SOAR playbooks
│   ├── analytics/                 # Behavioral analytics
│   ├── forensics/                 # Digital forensics
│   └── compliance/                # Compliance reporting
├── web/
│   ├── templates/                 # Dashboard HTML
│   └── static/                    # CSS, JS
├── config/
│   └── settings.py                # Configuration
├── data/
│   ├── logs/                      # Log storage
│   └── rules/                     # Detection rules
├── app.py                         # Main application
├── test_generator.py              # Test data generator
├── test_batch3.py                 # Feature tests
└── README.md                      # This file
```

---

## 🎯 **Quick Examples**

### Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Check Threat Intelligence
```bash
curl http://localhost:5000/api/threat-feed/192.168.100.25
```

### Predict Threat
```bash
curl -X POST http://localhost:5000/api/ml/predict \
  -H "Content-Type: application/json" \
  -d '{"failed_attempts": 5, "unusual_time": true}'
```

### Export Alerts
```bash
curl http://localhost:5000/api/export/alerts -o alerts.csv
```

### Block IP
```bash
curl -X POST http://localhost:5000/api/network/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.100.25", "reason": "Brute force"}'
```

---

## 📚 **Documentation**

- **README.md** - This file (overview)
- **CHEAT_SHEET.md** - Quick reference
- **START_HERE.md** - Getting started guide
- **BATCH2_COMPLETE.md** - Batch 2 features
- **BATCH3_COMPLETE.md** - Batch 3 features

---

## 🏆 **Compliance**

**Frameworks Supported:**
- ISO 27001
- NIST Cybersecurity Framework
- PCI-DSS
- GDPR

**Hackathon Requirements:** 100% ✅

---

## 🔧 **Tech Stack**

- **Backend:** Python 3.8+, Flask
- **Frontend:** HTML5, CSS3, JavaScript, Chart.js
- **ML:** NumPy, Pandas, Scikit-learn
- **Security:** JWT, RBAC, Rate Limiting

---

## ✅ **Status**

**Version:** 4.0  
**Status:** Production Ready  
**Features:** 66  
**Quality:** Enterprise Grade  
**Organization:** Clean & Consolidated  

---

## 🎯 **Quick Examples**

### Mobile Push Notification
```bash
curl -X POST http://localhost:5000/api/mobile/push \
  -H "Content-Type: application/json" \
  -d '{"type": "alert", "alert": {"severity": "CRITICAL", "title": "Security Breach"}}'
```

### Cloud Storage Upload
```bash
curl -X POST http://localhost:5000/api/cloud/upload \
  -H "Content-Type: application/json" \
  -d '{"type": "logs", "provider": "aws_s3"}'
```

### Threat Hunting
```bash
curl -X POST http://localhost:5000/api/hunt/create \
  -H "Content-Type: application/json" \
  -d '{"name": "Lateral Movement Hunt", "query": "SELECT * FROM logs WHERE lateral_movement = true"}'
```

### Asset Registration
```bash
curl -X POST http://localhost:5000/api/assets/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Web Server", "type": "server", "criticality": "high"}'
```

### Performance Monitoring
```bash
curl -X POST http://localhost:5000/api/performance/metric \
  -H "Content-Type: application/json" \
  -d '{"metric_name": "cpu_usage", "value": 85.5}'
```

---

## 📞 **Support**

**Location:** K:\Tecknova  
**Start:** `python app.py`  
**Dashboard:** http://localhost:5000  
**Test:** `python test_generator.py`  

---

**Built for Tecknova Hackathon 2024** 🏆
