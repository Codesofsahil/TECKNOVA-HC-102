# 🛡️ SOC Platform - Intelligent Security Operations Center

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/Hackathon-TECHNOVA--HC--102-red.svg)](https://github.com)

**Real-Time Security Monitoring with AI-Powered Threat Detection**

A production-ready SOC platform with 75+ features including ML threat prediction, SOAR automation, real-time monitoring, interactive attack map, and beautiful glassmorphism UI.

![SOC Platform Demo](https://via.placeholder.com/800x400/1a1a2e/ffffff?text=SOC+Platform+Dashboard)

---

## 🏆 **Key Features**

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

---

## 🚀 **Quick Start**

### **Prerequisites**
- Python 3.7+
- pip package manager

### **Installation**

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/TECHNOVA-HC-102.git
cd TECHNOVA-HC-102
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Start Platform**
```bash
python app.py
```

4. **Access Dashboard**
```
http://localhost:5000
```

5. **Login Credentials**
- **Username:** `admin`
- **Password:** `admin123`

### **Generate Test Data**
```bash
python quick_test.py
```

**Watch the magic:**
- 🔔 Popups appear for each log
- 📊 Charts update in real-time
- 📈 Stats refresh automatically
- 🗺️ Attack map shows activity

---

## 📊 **Dashboard Overview**

| Tab | Features |
|-----|----------|
| **Overview** | 📊 Stats cards, 📈 Live charts, 🤖 AI predictions |
| **Alerts** | 🔍 Filtering, 📋 Detailed cards, 🎨 Color-coding |
| **Logs** | 📝 Real-time entries, 🔍 Search, ✨ Animations |
| **Analytics** | 📈 Trends, 🎯 Radar charts, 🔄 Auto-updates |
| **Reports** | 📄 Executive, 📋 Compliance, 💾 Auto-download |
| **Attack Map** | 🗺️ Interactive map, 🎮 Demo mode, 📊 Live stats |

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

## 🔧 **API Documentation**

### **Core Endpoints**
```bash
# Dashboard Statistics
GET /api/stats

# Alerts Management
GET /api/alerts
POST /api/alerts

# Log Ingestion
POST /api/ingest
GET /api/logs

# Authentication
POST /api/auth/login
POST /api/auth/logout

# Reports
GET /api/reports/executive
GET /api/compliance/report?framework=<name>

# Threat Intelligence
GET /api/threat-intel/<ip>
GET /api/threat-feed/<ip>

# Network Security
POST /api/network/block
POST /api/network/unblock
```

---

## 📁 **Project Structure**

```
TECHNOVA-HC-102/
├── 📄 app.py                    # Main Flask application
├── 📁 core/                     # Backend modules
│   ├── 🔧 enhanced_services.py  # 15 consolidated services
│   ├── 📁 alert_manager/        # Alert management
│   ├── 📁 analytics/            # Behavioral analytics
│   ├── 📁 compliance/           # Compliance reporting
│   ├── 📁 correlation/          # Event correlation
│   ├── 📁 forensics/            # Digital forensics
│   ├── 📁 incident_response/    # Incident handling
│   ├── 📁 ml_detection/         # ML anomaly detection
│   ├── 📁 normalization/        # Log normalization
│   ├── 📁 soar/                 # SOAR automation
│   └── 📁 threat_intel/         # Threat intelligence
├── 📁 web/                      # Frontend assets
│   ├── 📁 templates/            # HTML templates
│   └── 📁 static/               # CSS/JS files
├── 📁 data/                     # Data storage
│   ├── 📁 logs/                 # Log files
│   └── 📁 rules/                # Detection rules
├── 📄 requirements.txt          # Dependencies
├── 📄 quick_test.py             # Test data generator
└── 📄 README.md                 # Documentation
```

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

## 🧪 **Testing**

### **Run All Tests**
```bash
python test_all.py
```

### **Interactive Test Generator**
```bash
python test_generator.py
```

### **Quick Test Data**
```bash
python quick_test.py
```

---

## 🎨 **UI Features**

- 🌈 Animated gradient background
- 💎 Glassmorphism cards with blur effects
- ✨ Smooth hover effects
- 🎯 Color-coded severity indicators
- 💫 Staggered fade-in animations
- 🔔 Eye-catching popup notifications
- 📊 Interactive charts with real-time updates

---

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🏆 **Acknowledgments**

- **TECHNOVA Hackathon 2024** for the challenge
- **Flask** for the web framework
- **Chart.js** for beautiful visualizations
- **Leaflet** for interactive maps

---

## 📞 **Contact**

**Project:** TECHNOVA-HC-102 SOC Platform  
**Version:** 6.0 - Real-Time Edition  
**Status:** Production Ready + AI Enhanced  

---

**Built for TECHNOVA Hackathon 2024** 🏆  
**Ready to Win!** 💰🚀✨
