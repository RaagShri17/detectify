# Fishing for Phishing — Phishing Awareness Website
###  Cyber Awareness Hackathon

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Project Structure](#project-structure)
5. [How the ML Detection Works](#how-the-ml-detection-works)
6. [Future Improvements](#future-improvements)

---

## Project Overview

**Fishing for Phishing** is an educational, cybersecurity-themed website that helps users:
- Detect phishing emails/messages using a feature-based ML pipeline
- Learn about different types of phishing attacks
- Test their knowledge through an interactive quiz

It demonstrates how machine learning can be applied to phishing detection without requiring large datasets or external libraries.

---

## Features

| Feature | Description |
|---|---|
| 🔍 ML Analyzer | Paste any message and get a phishing probability score |
| 📊 Feature Breakdown | Shows exactly which ML features flagged the text |
| 📖 Learn Page | Comprehensive phishing education guide |
| 🧪 Quiz | 8-question interactive quiz with real vs fake examples |
| 💡 Real vs Fake | Side-by-side comparison of phishing vs legitimate emails |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 + Flask |
| ML Engine | Custom feature-based classifier (no external ML libs needed) |
| Frontend | HTML5 + CSS3 + Vanilla JavaScript |
| Fonts | Orbitron + Share Tech Mono + Inter (Google Fonts) |
| Theme | Cyber-noir dark terminal aesthetic |

---

## Project Structure

```
phishing-awareness/
│
├── app.py                    ← Flask backend + ML detector
├── requirements.txt          ← Python dependencies
│
├── templates/
│   ├── index.html            ← Main detector page
│   ├── learn.html            ← Education/learn page
│   └── quiz.html             ← Interactive quiz page
│
└── static/
    ├── css/
    │   └── style.css         ← All CSS styles (cyberpunk theme)
    └── js/
        ├── main.js           ← Detector page logic
        └── quiz.js           ← Quiz logic + questions
```

---



## How the ML Detection Works

Fishing for Phishing uses a **feature engineering + weighted scoring** approach — the same core concept used in real ML phishing detectors, but without needing a trained model or dataset.

### Feature Extraction

| Feature | What It Measures | Weight |
|---|---|---|
| `urgency_count` | Count of urgency/pressure words ("immediately", "suspended", etc.) | ×12 |
| `suspicious_url_count` | URLs with IP addresses, many hyphens, or domain spoofing | ×20 |
| `sensitive_count` | Requests for passwords, SSN, credit cards, bank info | ×18 |
| `exclamation_count` | Number of `!` characters | ×4 |
| `caps_ratio` | Proportion of uppercase characters | ×30 |
| `domain_mismatch` | Multiple different email domains in one message | ×15 |
| `entropy` | Shannon entropy of character distribution | conditional |

### Scoring Formula

```python
score = (urgency_count × 12) + (url_score × 20) + (sensitive × 18)
        + (exclamations × 4) + (caps_ratio × 30) + (domain_mismatch × 15)

phishing_probability = min(100, score)
verdict = "PHISHING" if probability >= 40 else "LEGITIMATE"
```

### Why This Works

Real production ML phishing detectors (like those using Random Forest or Naive Bayes) are trained to weigh exactly these same types of features. This implementation demonstrates the core concept without needing labeled training data.

---


---

## Future Improvements

| Idea | Description |
|---|---|
| Real ML Model | Train a scikit-learn model on labeled phishing datasets |
| URL Scanner | Integrate VirusTotal API to check URLs in real time |
| Browser Extension | Let users scan emails directly in Gmail/Outlook |
| Reporting | Allow users to submit suspected phishing for community review |
| Email Header Analysis | Parse raw email headers (SPF, DKIM, DMARC) |
| BERT/NLP | Use transformer models for higher accuracy |

---

## Team & Credits

Built by the **Team CyberVerse** 

> "Awareness is the first line of defense."
