# 🔍 Smart Phishing URL Detection System

A Flask-based web application that detects potentially malicious URLs using rule-based heuristic analysis.

The system examines various URL characteristics and security indicators to classify URLs as safe or suspicious without using machine learning.

---

## 🚀 Project Overview

The application analyzes a submitted URL and generates a verdict based on multiple phishing detection checks.

### Possible Results

* ✅ Safe URL
* 🚨 Phishing URL
* 🚨 Critical Phishing URL

---

## 🧠 How It Works

1. User enters a URL.
2. Flask processes the request.
3. The URL is analyzed using multiple security checks.
4. Detection signals are collected.
5. A verdict and explanation are displayed.

---

## ✨ Features

* Rule-based phishing detection
* Domain structure analysis
* Suspicious URL pattern detection
* Brand impersonation detection
* IP address detection
* Subdomain analysis
* URL path inspection
* Suspicious TLD detection
* Tunnel/proxy domain detection
* Website reachability checking
* Detailed detection explanations
* Simple and user-friendly interface

---

## 🛠 Technologies Used

* Python
* Flask
* Requests
* Regular Expressions 
* urllib.parse

---

## 🧪 Usage

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Fejil-Francis/Phishing_URL_Detector.git
cd Phishing_URL_Detector
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Launch the Application

Start the Flask server:

```bash
python3 phish.py
```
---
## 📜 License

This project is intended for educational and learning purposes.
---
