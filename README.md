# 🔍 Phishing URL Detection System

A simple web application built using **Flask (Python)** that detects whether a URL is phishing or safe using rule-based security analysis.

This project does **not use machine learning**. Instead, it relies on predefined heuristic rules such as URL patterns, suspicious keywords, and structural checks to identify potentially malicious URLs.

---

## 🚀 Project Overview

The system analyzes a given URL and determines whether it is safe or suspicious based on multiple security indicators.

### Detection Factors

* URL length
* Presence of digits
* Suspicious keywords (login, bank, verify, secure, etc.)
* Subdomain count
* IP address usage
* File-based URL patterns
* Website reachability

Based on these checks, the application classifies the URL as:

* ✅ Safe URL
* 🚨 Phishing URL
* ❌ Website Not Reachable

---

## 🧠 How It Works

1. User opens the web application.
2. A URL is entered into the input field.
3. The **Check** button is clicked.
4. Flask processes the request.
5. Rule-based logic analyzes the URL.
6. The result and detection reasons are displayed.

---

## ✨ Features

* Real-time URL analysis
* Rule-based phishing detection
* Suspicious keyword detection
* IP address detection
* Website availability checking
* Simple and user-friendly interface
* Lightweight and easy to deploy

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
