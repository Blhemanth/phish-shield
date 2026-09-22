# PhishShield AI 🛡️ (Flutter Cross-Platform)

A sleek, dark-themed, cross-platform application targeting **Windows Desktop, Android, iOS, and Web** that detects **fake offer letters**, **pay-for-equipment phishing scams**, and **deposit traps** targeting job seekers — powered by a hybrid **Gemini AI** + **pure Dart offline heuristic** engine.

---

## ✨ Features

- **Cross-Platform Architecture** — Built with Flutter 3.x for native performance on Windows, Android, iOS, and Web
- **Dual-Engine Detection** — Primary Gemini AI REST client (`http` package) with an automatic offline Dart regex/keyword analyzer fallback
- **Interactive Scam Threat Meter** — Custom-painted animated 0–100% SVG arc gauge matching threat level severity
- **Categorized Red Flags** — Visual cards highlighting Financial Traps, Identity Theft, Social Engineering, and Urgency Pressure
- **Safety Verification Checklist** — Actionable interactive checklist for job seekers
- **Sample Scam Loader** — One-touch quick load of multi-vector offer letter fraud samples
- **Runtime API Key Config** — Easily set your Gemini API key in the app settings, or rely on built-in offline heuristics

---

## 🏗️ Architecture

```
phish-shield/
├── lib/
│   └── main.dart            # Flutter UI, state management, Gemini API REST service, & pure Dart offline engine
├── pubspec.yaml             # App manifest & dependencies (http, cupertino_icons)
├── test/
│   └── widget_test.dart     # Unit & widget test suite
├── windows/                 # Native Windows runner
├── android/                 # Native Android runner
├── ios/                     # Native iOS runner
└── web/                     # Native Web runner
```

---

## 🚀 Getting Started

### Prerequisites
- [Flutter SDK 3.x](https://docs.flutter.dev/get-started/install) installed and added to `PATH`
- [Google AI Studio API key](https://aistudio.google.com/app/apikey) (Optional — fallback engine runs offline without any key)

### 1. Clone & Navigate
```bash
git clone https://github.com/Blhemanth/phish-shield.git
cd phish-shield
```

### 2. Fetch Dependencies
```bash
flutter pub get
```

### 3. Run on Platform of Choice

#### 🪟 Windows Desktop
```bash
flutter run -d windows
```

#### 🌐 Web (Chrome)
```bash
flutter run -d chrome
```

#### 📱 Android
```bash
flutter run -d <android-device-id>
```

#### 🍏 iOS (macOS required)
```bash
flutter run -d <ios-device-id>
```

---

## 📦 Building Production Release Binaries

### Windows Desktop Executable (`.exe`)
```bash
flutter build windows
```
*Output artifact:* `build/windows/x64/runner/Release/`

### Android Application Package (`.apk`) / App Bundle (`.aab`)
```bash
flutter build apk --release
# or
flutter build appbundle --release
```
*Output artifact:* `build/app/outputs/flutter-apk/app-release.apk`

### Web Deployment Package
```bash
flutter build web --release
```
*Output artifact:* `build/web/`

---

## 🧪 Testing

Run automated unit tests for the heuristic engine and UI components:
```bash
flutter test
```

---

## 📄 License

MIT License — Free to use, modify, and distribute.
