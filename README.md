# 🛡️ SOC Platform - Intelligent Security Operations Center

**Real-Time Security Monitoring with AI-Powered Threat Detection**

A production-ready SOC platform with 75+ features including ML threat prediction, SOAR automation, real-time monitoring, interactive attack map, and beautiful glassmorphism UI.

---

## 🏆 **Winning Features**

### **🎯 Real-Time Monitoring**
- ⚡ **Live Updates** - All data refreshes every 2 seconds
- 🔔 **Instant Popups** - Notifications appear for every new log/alert
- 📊 **Live Charts** - Graphs update automatically with real data
- 🎨 **Modern UI** - Glassmorphism design with smooth animations

### **🤖 AI-Powered Intelligence**
- 🧠 **AI Threat Prediction** - ML-based threat scoring (0-100)
- 💡 **Smart Recommendations** - AI suggests actions based on threats
- 🎯 **Next Attack Prediction** - Predicts when/what attack will occur
- 📈 **Behavioral Analytics** - Detects anomalies in real-time

### **🗺️ Interactive Attack Map**
- 🌍 **Global Visualization** - See attacks from countries in real-time
- 🎮 **Demo Mode** - Auto-simulate attacks for presentations
- 📊 **Live Statistics** - Attack count, blocked IPs, countries
- ✨ **Animated Lines** - Beautiful attack path visualization

### **🚀 Core Security**
- 🔍 Multi-source log collection (JSON, Syslog, Windows)
- 🎯 Rule-based correlation (6+ detection rules)
- 🤖 ML anomaly detection
- 🚨 Alert prioritization & deduplication
- 🔐 MITRE ATT&CK mapping

### **📊 Enterprise Features**
- 🔐 Authentication & RBAC (Admin/Analyst/Viewer)
- 📄 Report generation (Executive, Compliance)
- 🔍 Vulnerability scanning
- 🌐 Network monitoring & IP blocking
- 💾 Automated backups
- 📝 Comprehensive audit logging

---

## 🚀 **Quick Start**

### **1. Install Dependencies**
```bash
cd K:\Tecknova
pip install -r requirements.txt
```

### **2. Start Platform**
```bash
python app.py
```

### **3. Access Dashboard**
```
http://localhost:5000
```

### **4. Login**
- **Username:** `admin`
- **Password:** `admin123`

### **5. Generate Test Data**
```bash
python quick_test.py
```

**Watch the magic:**
- 🔔 Popups appear for each log
- 📊 Charts update in real-time
- 📈 Stats refresh automatically
- 🗺️ Attack map shows activity

---

## 📊 **Dashboard Tabs**

### **1. Overview** 
- 📊 4 stat cards (Critical, High, Incidents, Logs)
- 📈 Alert severity distribution (doughnut chart with center total)
- 📉 Live alert trend (updates every 2 seconds)
- 🎯 Top threat sources table
- 🤖 **AI Threat Prediction** with threat score meter
- 💡 **AI Recommendations** based on current threats

### **2. Alerts**
- 🔍 Filter by severity and status
- 📋 Detailed alert cards
- 🎨 Color-coded by severity
- 🔄 Real-time updates

### **3. Logs**
- 📝 Beautiful log entries with glassmorphism
- 🔍 Real-time search
- 🎨 Color-coded severity badges
- ✨ Smooth animations

### **4. Analytics**
- 📈 Alert volume trends (7 days - real data)
- 🎯 Detection methods radar chart
- 🔄 Auto-updates with live data

### **5. Reports**
- 📄 Executive Summary Report
- 📋 Compliance Reports (ISO 27001, NIST, PCI-DSS, GDPR)
- 💾 Auto-download as JSON
- 📝 Recent reports history

### **6. Attack Map** 🆕
- 🗺️ **Interactive world map** with real-time attacks
- 🔴 **Animated attack lines** from source to target
- 🎮 **Demo Mode** - Click to auto-simulate attacks
- 📊 **Live stats** - Attacks, blocked IPs, countries
- 🌍 **Top attack sources** list

---

## 🎯 **Real-Time Features**

### **Automatic Updates (Every 2 Seconds)**
- ✅ Stats cards refresh
- ✅ Charts update with new data
- ✅ Popups show for new logs/alerts
- ✅ Logs tab auto-refreshes
- ✅ AI predictions recalculate

### **Instant Notifications**
- 🔔 Popup for every new log
- 🚨 Popup for every new alert
- ⏱️ Auto-dismiss after 1 second
- 🎨 Color-coded by severity
- ✨ Smooth slide-in animation

---

## 📊 **Platform Statistics**

| Metric | Count |
|--------|-------|
| **Total Features** | 75+ |
| **API Endpoints** | 85+ |
| **Services** | 22 |
| **Detection Rules** | 6+ |
| **SOAR Playbooks** | 4 |
| **Compliance Frameworks** | 4 |
| **Dashboard Tabs** | 6 |
| **Chart Types** | 7 |
| **AI Features** | 3 |
| **Update Frequency** | 2 seconds |

---

## 🎮 **Demo Mode**

Perfect for presentations and hackathon demos!

1. Click **Attack Map** tab
2. Click **"🎮 Start Demo Mode"** button
3. Watch:
   - 🌍 Attacks animate from countries
   - 🔔 Popups appear for each attack
   - 📊 Stats update in real-time
   - 🎯 Attack sources list grows

---

## 🔧 **Key API Endpoints**

### **Core**
- `POST /api/ingest` - Ingest logs
- `GET /api/stats` - Dashboard statistics
- `GET /api/alerts` - Get alerts
- `GET /api/logs` - Get logs

### **Authentication**
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### **Reports**
- `GET /api/reports/executive` - Executive summary
- `GET /api/compliance/report?framework=<name>` - Compliance report

### **Threat Intelligence**
- `GET /api/threat-intel/<ip>` - IP reputation
- `GET /api/threat-feed/<ip>` - Comprehensive report

### **Network**
- `POST /api/network/block` - Block IP
- `POST /api/network/unblock` - Unblock IP

---

## 📁 **Project Structure**

```
Tecknova/
├── app.py                    # Main Flask application
├── core/                     # Backend modules
│   ├── enhanced_services.py  # 15 consolidated services
│   └── [11 modules]/         # Security components
├── web/
│   ├── templates/
│   │   └── dashboard.html    # Modern glassmorphism UI
│   └── static/
│       ├── css/
│       └── js/
│           └── dashboard.js  # Frontend logic
├── data/                     # Logs & rules storage
├── README.md                 # This file
├── GUIDE.md                  # Quick reference
├── requirements.txt          # Dependencies
├── quick_test.py             # Quick test data generator
└── test_generator.py         # Interactive test generator
```

---

## 🎨 **UI Features**

### **Design**
- 🌈 Animated gradient background
- 💎 Glassmorphism cards with blur effects
- ✨ Smooth hover effects
- 🎯 Color-coded severity indicators
- 💫 Staggered fade-in animations

### **Notifications**
- 🔔 Eye-catching popup notifications
- ⏱️ 1-second auto-dismiss
- 🎨 Gradient backgrounds
- ✨ Bounce animation on entry
- 🎯 Icons for each severity

### **Charts**
- 📊 Doughnut chart (Alert Severity with center total)
- 📈 Line chart (Live Alert Trend - updates every 2s)
- 📉 Line chart (Alert Volume Trends - 7 days)
- 🎯 Radar chart (Detection Methods)
- 🎨 All charts with white text for dark theme

---

## 🏆 **Hackathon Compliance**

**Problem Statement:** HC-102 - Intelligent Security Operations Monitoring  
**Category:** Cybersecurity  
**Level:** Medium  

### **Requirements Met:**
- ✅ Multi-source log collection & normalization
- ✅ Rule-based correlation engine
- ✅ Intelligent techniques (ML anomaly detection)
- ✅ Alert prioritization by severity/frequency/impact
- ✅ Partial automation (SOAR playbooks, auto-response)
- ✅ Clear dashboards with real-time updates
- ✅ Structured reports (Executive, Compliance)
- ✅ Timely incident detection (2-second refresh)

**Compliance:** 100% ✅ + Enhanced with AI & Real-Time Features

---

## 🎯 **What Makes This Special**

1. **⚡ Real-Time Everything** - Updates every 2 seconds, instant popups
2. **🤖 AI-Powered** - Threat prediction, smart recommendations
3. **🗺️ Interactive Attack Map** - Visual threat monitoring with demo mode
4. **🎨 Beautiful UI** - Modern glassmorphism design
5. **📊 Live Charts** - All graphs update with real data
6. **🔔 Instant Notifications** - Popup for every event
7. **🎮 Demo Mode** - Perfect for presentations
8. **📄 Complete Reports** - Executive & compliance ready

---

## 🚀 **Quick Test Workflow**

```bash
# Terminal 1: Start platform
python app.py

# Terminal 2: Generate test data
python quick_test.py

# Browser: Watch the magic!
# - Popups appear instantly
# - Charts update live
# - Stats refresh automatically
# - Attack map shows activity
```

---

## 📞 **Files**

- `README.md` - Complete documentation (this file)
- `GUIDE.md` - Quick reference guide
- `requirements.txt` - Python dependencies
- `app.py` - Main application
- `quick_test.py` - Quick test data generator
- `test_generator.py` - Interactive test generator

---

## ✅ **Final Status**

**Version:** 6.0 - Real-Time Edition  
**Status:** Production Ready + AI Enhanced  
**Features:** 75+  
**Quality:** Enterprise Grade  
**UI:** Modern Glassmorphism  
**Updates:** Real-Time (2 seconds)  
**AI:** Threat Prediction & Recommendations  
**Demo:** Interactive Attack Map with Demo Mode  

---

**Built for Tecknova Hackathon 2024** 🏆  
**Ready to Win!** 💰🚀✨
