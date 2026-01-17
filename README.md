# 🛡️ SOC Platform - Intelligent Security Operations Center

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/Hackathon-TECHNOVA--HC--102-red.svg)](https://github.com/Codesofsahil/TECKNOVA-HC-102)

**Real-Time Security Monitoring with AI-Powered Threat Detection**

A production-ready SOC platform with 75+ features including ML threat prediction, SOAR automation, real-time monitoring, interactive attack map, and beautiful glassmorphism UI.

---

## 🚀 **How to Run the Repository**

### **📋 Prerequisites**
- **Python 3.7+** installed on your system
- **Git** for cloning the repository
- **Internet connection** for downloading dependencies

### **⚡ Quick Setup (5 Minutes)**

#### **Step 1: Clone Repository**
```bash
# Clone the repository
git clone https://github.com/Codesofsahil/TECKNOVA-HC-102.git

# Navigate to project directory
cd TECKNOVA-HC-102
```

#### **Step 2: Install Dependencies**
```bash
# Install required Python packages
pip install -r requirements.txt

# Alternative: Install core dependencies manually
pip install Flask Flask-CORS requests numpy pandas scikit-learn
```

#### **Step 3: Start the Platform**
```bash
# Start the SOC Platform
python app.py
```

#### **Step 4: Access Dashboard**
1. Open your web browser
2. Navigate to: **http://localhost:5000**
3. Login with credentials:
   - **Username:** `admin`
   - **Password:** `admin123`

#### **Step 5: Generate Test Data (Optional)**
```bash
# In a new terminal, generate sample security data
python quick_test.py

# Or run comprehensive tests
python test_all.py
```

### **🎯 Alternative Setup Methods**

#### **Method 1: Windows Batch File**
```bash
# Double-click to run (Windows only)
start.bat
```

#### **Method 2: Manual Step-by-Step**
```bash
# 1. Check Python version
python --version

# 2. Create virtual environment (recommended)
python -m venv soc_env
soc_env\Scripts\activate  # Windows
# source soc_env/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install Flask==2.3.3 Flask-CORS==4.0.0
pip install requests numpy pandas scikit-learn

# 4. Run application
python app.py
```

### **🔧 Troubleshooting**

#### **Common Issues & Solutions:**

**Issue 1: Port 5000 already in use**
```bash
# Solution: Change port in app.py or kill existing process
netstat -ano | findstr :5000  # Windows
lsof -ti:5000 | xargs kill -9  # Linux/Mac
```

**Issue 2: Module not found errors**
```bash
# Solution: Install missing dependencies
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

**Issue 3: Permission errors**
```bash
# Solution: Run with appropriate permissions
# Windows: Run as Administrator
# Linux/Mac: Use sudo if needed
sudo python app.py
```

### **📱 Platform Features After Setup**

Once running, you'll have access to:

#### **🎯 Real-Time Monitoring**
- ⚡ Live updates every 2 seconds
- 🔔 Instant popup notifications
- 📊 Real-time charts and graphs
- 🎨 Modern glassmorphism UI

#### **🤖 AI-Powered Intelligence**
- 🧠 ML-based threat scoring (0-100)
- 💡 Smart recommendations
- 🎯 Attack prediction algorithms
- 📈 Behavioral analytics

#### **🗺️ Interactive Attack Map**
- 🌍 Global attack visualization
- 🎮 Demo mode for presentations
- 📊 Live attack statistics
- ✨ Animated attack paths

---

## 🏆 **Key Features**

### **Core Security**
- 🔍 Multi-source log collection (JSON, Syslog, Windows, Firewall)
- 🎯 Rule-based correlation (6+ detection rules)
- 🤖 ML anomaly detection
- 🚨 Alert prioritization & deduplication
- 🔐 MITRE ATT&CK mapping

### **Enterprise Features**
- 🔐 Authentication & RBAC (Admin/Analyst/Viewer)
- 📄 Report generation (Executive, Incident, Compliance)
- 🔍 Vulnerability scanning
- 🌐 Network monitoring & IP blocking
- 💾 Automated backups
- ⚡ API rate limiting
- 📝 Comprehensive audit logging

### **Advanced Features**
- 📧 Email & Slack notifications
- 🗺️ Geolocation attack mapping
- 📊 CSV export (alerts, incidents, logs)
- 🔍 Advanced search & filtering
- 🛡️ Threat intelligence (AbuseIPDB, VirusTotal)
- 🎨 Multiple themes (light/dark/blue/green)
- 🔔 Alert sound notifications

---

## 🎮 **Demo & Testing**

### **Quick Demo Mode**
1. Start the platform: `python app.py`
2. Open browser: `http://localhost:5000`
3. Login with `admin` / `admin123`
4. Click **Attack Map** tab
5. Click **"🎮 Start Demo Mode"**
6. Watch real-time attack simulation!

### **Generate Test Data**
```bash
# Quick test data
python quick_test.py

# Comprehensive testing
python test_all.py

# Interactive test generator
python test_generator.py
```

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

## 🔧 **API Examples**

### **Authentication**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### **Threat Intelligence**
```bash
curl http://localhost:5000/api/threat-feed/192.168.100.25
```

### **ML Prediction**
```bash
curl -X POST http://localhost:5000/api/ml/predict \
  -H "Content-Type: application/json" \
  -d '{"failed_attempts": 5, "unusual_time": true}'
```

### **Export Data**
```bash
curl http://localhost:5000/api/export/alerts -o alerts.csv
```

---

## 📁 **Project Structure**

```
TECHNOVA-HC-102/
├── app.py                    # Main Flask application
├── core/                     # Backend modules
│   ├── enhanced_services.py  # 15 consolidated services
│   ├── alert_manager/        # Alert management
│   ├── analytics/            # Behavioral analytics
│   ├── compliance/           # Compliance reporting
│   ├── correlation/          # Event correlation
│   ├── forensics/            # Digital forensics
│   ├── incident_response/    # Incident handling
│   ├── ml_detection/         # ML anomaly detection
│   ├── normalization/        # Log normalization
│   ├── soar/                 # SOAR automation
│   └── threat_intel/         # Threat intelligence
├── web/                      # Frontend assets
│   ├── templates/            # HTML templates
│   └── static/               # CSS/JS files
├── data/                     # Data storage
│   ├── logs/                 # Log files
│   └── rules/                # Detection rules
├── requirements.txt          # Dependencies
├── quick_test.py             # Quick test generator
├── test_all.py               # Comprehensive tests
├── start.bat                 # Windows startup script
└── README.md                 # This file
```

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

## 🔐 **Default Credentials**

| Role | Username | Password |
|------|----------|----------|
| **Admin** | `admin` | `admin123` |
| **Analyst** | `analyst` | `analyst123` |
| **Viewer** | `viewer` | `viewer123` |

---

## 📚 **Documentation**

- **README.md** - This file (setup & overview)
- **CHEAT_SHEET.md** - Quick reference guide
- **START_HERE.md** - Getting started guide
- **BATCH2_COMPLETE.md** - Batch 2 features
- **BATCH3_COMPLETE.md** - Batch 3 features
- **TESTING_GUIDE.md** - Testing instructions

---

## 🎯 **Quick Commands Reference**

```bash
# Setup
git clone https://github.com/Codesofsahil/TECKNOVA-HC-102.git
cd TECKNOVA-HC-102
pip install -r requirements.txt

# Run
python app.py

# Test
python quick_test.py
python test_all.py

# Access
# Browser: http://localhost:5000
# Login: admin / admin123
```

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

**Built for TECHNOVA Hackathon 2024** 🏆  
**Repository:** https://github.com/Codesofsahil/TECKNOVA-HC-102  
**Ready to Win!** 💰🚀✨
