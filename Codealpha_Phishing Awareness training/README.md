# 🛡️ PhishGuard — Phishing Awareness Training Module

> **CodeAlpha Cybersecurity Internship — Task 2**
> Built by Moses | JNNCE Electronics & Communication Engineering

---

## 📌 Overview

**PhishGuard** is an interactive, web-based phishing awareness training module.
It walks through the basics of phishing, social engineering psychology,
real-world attack examples, and then tests your understanding with a 10-question quiz —
all inside a polished dark cybersecurity-themed interface.

---

## 🎯 Features

| Feature | Description |
|---|---|
| 📧 Interactive Email Mockup | Click-to-reveal red flag annotations on a realistic phishing email |
| 🎯 8 Attack Types | Email phishing, spear phishing, whaling, smishing, vishing, clone phishing, pharming, AI phishing |
| 🔍 URL Comparison Tool | Side-by-side legitimate vs. phishing URL analysis |
| 🧠 Social Engineering Tactics | 6 psychological manipulation techniques with real examples |
| 📋 Best Practices Guide | 8 actionable defense strategies + emergency response steps |
| 📰 Real Case Studies | Google/Facebook fraud, Twitter 2020 hack, COVID phishing wave, BEC attacks |
| 🏆 10-Question Quiz | Interactive quiz with instant feedback, explanations & score breakdown |
| 📊 Reading Progress Bar | Tracks how much of the module the user has completed |
| 🌙 Dark UI | Professional cybersecurity-themed dark mode interface |
| 📱 Responsive Design | Works on desktop, tablet, and mobile |

---

## 🗂️ Project Structure

```
phishing-awareness-training/
├── index.html          ← Main HTML file (all 8 modules)
├── css/
│   └── style.css       ← Full stylesheet (dark theme, responsive)
├── js/
│   └── script.js       ← Quiz logic, navigation, scroll tracking
└── README.md           ← This file
```

---

## 🚀 How to Run

### Option 1 — Open Directly in Browser
```
Double-click index.html to open it in your default browser.
```

### Option 2 — VS Code Live Server (Recommended)
```bash
# 1. Open this folder in VS Code
code .

# 2. Install the "Live Server" extension if needed
# 3. Right-click index.html and choose "Open with Live Server"
```

### Option 3 — Python HTTP Server
```bash
cd "c:\Users\moses\OneDrive\Documents\Codealpha_Tasks\Codealpha_phising awareness trainig"
python -m http.server 8080
# Open: http://localhost:8080
```

---

## 📚 Training Modules

| # | Module | Topics Covered |
|---|---|---|
| 00 | Overview | Stats, hero email scan visual |
| 01 | What is Phishing? | Definition, how it works, history timeline |
| 02 | Attack Types | 8 major phishing attack vectors |
| 03 | Email Red Flags | Interactive annotated phishing email, 8 red flags |
| 04 | Fake Websites | URL analysis, HTTPS misconceptions, detection tips |
| 05 | Social Engineering | 6 psychological tactics with real-world examples |
| 06 | Best Practices | 8 defense tips + emergency response guide |
| 07 | Real Examples | 4 famous phishing attack case studies |
| 08 | Knowledge Quiz | 10 questions with explanations and score breakdown |

---

## 🧪 Quiz Details

- **10 Multiple Choice Questions**
- Covers: red flags, URL analysis, attack types, social engineering, best practices
- Instant feedback with detailed explanations for each question
- Score bands: Poor / Average / Good / Excellent / Perfect
- Full breakdown of all answers after submission
- Retry functionality

---

## 🛠️ Technologies Used

- **HTML5** — Semantic structure
- **CSS3** — Custom properties, Grid, Flexbox, animations, responsive design
- **Vanilla JavaScript** — Quiz engine, scroll tracking, IntersectionObserver, DOM manipulation
- **No frameworks, no dependencies** — Pure web technologies only

---

## 🔒 Learning Objectives

After completing this module, users will be able to:

- ✅ Define phishing and explain how it works
- ✅ Identify the 8 major types of phishing attacks
- ✅ Recognize red flags in suspicious emails and websites
- ✅ Understand 6 social engineering manipulation tactics
- ✅ Apply 8 best-practice defense strategies
- ✅ Respond correctly if they fall victim to a phishing attack
- ✅ Pass the knowledge quiz with 80%+ score

---

## 📝 Internship Info

- **Organization:** CodeAlpha
- **Program:** Cybersecurity Internship
- **Task:** Task 2 — Phishing Awareness Training
- **Intern:** Moses | JNNCE ECE (2nd Semester)
- **GitHub Repo:** `CodeAlpha_ProjectName`

---

## ⬆️ Pushing to GitHub

```bash
# Initialize repo (first time)
git init
git add .
git commit -m "Add Task 2: Phishing Awareness Training Module (PhishGuard)"

# Push to GitHub
git remote add origin https://github.com/YOUR_USERNAME/CodeAlpha_ProjectName.git
git branch -M main
git push -u origin main
```

---

*Built as part of the CodeAlpha Cybersecurity Internship Program*
