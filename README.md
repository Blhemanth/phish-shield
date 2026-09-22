# PhishShield AI 🛡️

A sleek, dark-themed, single-page web application that detects **fake offer letters**, **pay-for-equipment phishing scams**, and **deposit traps** targeting job seekers — powered by a hybrid **Gemini AI** + **offline heuristic** detection engine.

---

## ✨ Features

- **Dual-Mode Detection Engine** — Gemini AI for deep semantic analysis with an offline JavaScript fallback that works without any API key
- **Scam Threat Index Gauge** — Animated 0–100 SVG meter with real-time color shifts
- **Threat Level Badge** — LOW / MEDIUM / HIGH / CRITICAL with glowing status indicators
- **Red Flag Cards** — Categorized threat cards (Financial Trap, Identity Theft, Social Engineering, etc.) with severity badges
- **Verification Checklist** — Actionable, interactive checklist job seekers can tick off
- **Phishing Sample Loader** — One-click load of a realistic multi-vector scam offer for demo/testing
- **Real-time API Health Check** — Status pill shows if Gemini API is connected or falling back to heuristics

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                   index.html (Frontend)               │
│                                                        │
│  ┌─────────────────┐     ┌─────────────────────────┐  │
│  │  Input Panel     │     │  Results Dashboard       │  │
│  │  - Offer text    │     │  - Scam Threat Gauge     │  │
│  │  - Company URL   │     │  - Threat Level Badge    │  │
│  │  - Sample Loader │     │  - AI Summary Card       │  │
│  │  - Inspect CTA   │     │  - Red Flags Container   │  │
│  └────────┬─────────┘     │  - Verification List     │  │
│           │               └─────────────────────────┘  │
└───────────┼──────────────────────────────────────────-─┘
            │
            ▼  POST /api/inspect
   ┌─────────────────────┐          ┌─────────────────┐
   │   app.py (Flask)    │────────▶│  Gemini AI      │
   │   /api/inspect       │◀────────│  google-genai    │
   │   /api/health        │          └─────────────────┘
   └─────────────────────┘
            │ (if API fails / offline)
            ▼
   ┌───────────────────────────────┐
   │  Client-Side Heuristic Engine │
   │  17 weighted regex rules      │
   │  (runs entirely in browser)   │
   └───────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- A [Google AI Studio](https://aistudio.google.com/) API key (free tier available)

### 1. Clone / Navigate to Project
```bash
git clone https://github.com/your-username/phish-shield.git
cd phish-shield
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
Create a `.env` file in the project root:
```env
GEMINI_API_KEY=your_google_ai_studio_api_key_here
GEMINI_MODEL=gemini-3.6-flash
FLASK_DEBUG=false
PORT=5000
```

> **Get your free API key**: Visit [Google AI Studio](https://aistudio.google.com/app/apikey), sign in with your Google account, and click **Create API Key**.

### 4. Start the Application
```bash
python app.py
```
You should see:
```
PhishShield AI backend running on http://localhost:5000
Gemini API key: [OK] configured
```

### 5. Open in Browser
Open your browser and navigate to:
```
http://localhost:5000
```

> **Note**: You can also double-click `index.html` directly in your file explorer to run in standalone client-side heuristic mode without any server.

---

## 🔌 API Reference

### `POST /api/inspect`
Analyzes an offer letter for phishing indicators using Gemini AI.

**Request Body:**
```json
{
  "offer_text": "Full text of the offer letter or email...",
  "company_url": "https://optional-company-url.com"
}
```

**Response (200 OK):**
```json
{
  "scam_threat_index": 87,
  "threat_level": "CRITICAL",
  "summary": "This offer exhibits multiple hallmarks of employment fraud...",
  "red_flags_detected": [
    {
      "category": "Financial Trap",
      "flag_title": "Pay-for-Equipment Scheme",
      "description": "The offer requires you to purchase equipment upfront...",
      "severity": "CRITICAL"
    }
  ],
  "verification_checklist": [
    "Verify the company on its official website directly...",
    "Call the company's publicly listed phone number..."
  ]
}
```

**Error Responses:**
| Code | Meaning |
|------|---------|
| 400  | Missing `offer_text` |
| 503  | Gemini API key not configured or API error |
| 502  | AI returned unparseable response |

### `GET /api/health`
Returns API status and key configuration state.

---

## 🧠 Offline Heuristic Engine

The client-side JavaScript heuristic engine runs **entirely in the browser** with no network requests. It uses **17 weighted regex rules** across 7 threat categories:

| Category | Examples |
|----------|---------|
| Financial Trap | Cashier check, wire transfer, Zelle, CashApp, equipment purchase |
| Identity Theft | SSN request, bank routing numbers, ID scan requests |
| Social Engineering | Unsolicited profile selection, vague company claims |
| Urgency Pressure | "Expires in 24 hours", "act now", "immediately" |
| Communication Red Flag | Gmail/Yahoo corporate email, WhatsApp/Telegram only |
| Unrealistic Offer | $150k+ salary with no experience required |
| Impersonation | Found you on LinkedIn/Indeed without application |

Scores are weighted and normalized to a 0–100 threat index.

---

## 🎨 Design System

| Token | Value |
|-------|-------|
| Background | `#020617` (slate-950) |
| Surface | `rgba(15,23,42,0.7)` (glassmorphism) |
| Accent | `#6366f1` (indigo-500) |
| Critical | `#ef4444` (red-500) |
| High | `#fb923c` (orange-400) |
| Medium | `#facc15` (yellow-400) |
| Low / Safe | `#4ade80` (green-400) |
| Font | Inter + JetBrains Mono |

---

## 📁 Project Structure

```
phish-shield/
├── index.html          # Complete frontend SPA
├── app.py              # Flask + Gemini AI backend
├── requirements.txt    # Python dependencies
├── .env.example        # Example environment configuration
├── README.md           # Documentation
└── .gitignore          # Git ignore rules
```

---

## ⚠️ Disclaimer

PhishShield AI is an **educational and awareness tool**. It does not guarantee detection of all scams. Always verify job offers through multiple official channels before sharing any personal or financial information. Report suspected scams to the [FTC](https://reportfraud.ftc.gov).

---

## 📄 License

MIT License — Free to use, modify, and distribute.
