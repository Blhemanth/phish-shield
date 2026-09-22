import os
import json
import re
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

SYSTEM_PROMPT = """You are PhishShield AI, an expert cybersecurity analyst specializing in job-offer phishing scams, fake employment fraud, pay-for-equipment schemes, and deposit traps targeting job seekers.

Your task is to analyze the provided offer letter or job posting text and identify whether it is a phishing attempt, scam, or legitimate offer.

You MUST respond with ONLY a valid JSON object (no markdown, no code fences, no explanation outside the JSON). The JSON must strictly follow this schema:

{
  "scam_threat_index": <integer 0-100>,
  "threat_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-4 sentence concise evaluation summary>",
  "red_flags_detected": [
    {
      "category": "<Financial Trap|Social Engineering|Identity Theft|Urgency Pressure|Impersonation|Communication Red Flag|Unrealistic Offer>",
      "flag_title": "<short descriptive title>",
      "description": "<1-2 sentence explanation of why this is a red flag>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
    }
  ],
  "verification_checklist": [
    "<Actionable step job seekers can take to verify legitimacy>"
  ]
}

Scoring guidelines:
- 0-25: Legitimate, no significant concerns
- 26-50: Suspicious, some yellow flags, verify carefully
- 51-75: High risk, multiple scam indicators present
- 76-100: Critical scam, do NOT engage

Key scam indicators to look for:
- Requests for payment, deposits, cashier checks, wire transfers, Zelle, PayPal, cryptocurrency
- Purchase equipment/laptop and get reimbursed schemes
- Interviews via WhatsApp, Telegram, text-only (avoiding video)
- Salary far above market rate with no experience required
- Vague job descriptions with immediate hiring
- Personal information requests (SSN, bank account) too early
- Unprofessional email domains (Gmail for corporate jobs)
- Grammar/spelling errors in "official" communications
- Pressure to act quickly, limited time offers
- Overpayment/deposit check scams
- Remote-only positions that require upfront payments
"""


def get_api_key() -> str:
    """Read GEMINI_API_KEY dynamically from environment or .env file."""
    load_dotenv(override=True)
    return os.environ.get("GEMINI_API_KEY", "").strip()


def call_gemini(offer_text: str, company_url: str = "") -> dict:
    """Call Gemini via google-genai SDK with automatic model fallback."""
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not configured")

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        user_message = f"""Please analyze the following job offer for phishing/scam indicators:

OFFER LETTER / EMAIL TEXT:
{offer_text}

COMPANY / JOB URL (if provided):
{company_url if company_url else 'Not provided'}

Provide your analysis as a JSON object only."""

        preferred_model = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        candidate_models = [preferred_model]
        for m in ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-1.5-flash"]:
            if m not in candidate_models:
                candidate_models.append(m)

        last_error = None
        for model_name in candidate_models:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=user_message,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        temperature=0.1,
                        response_mime_type="application/json",
                    ),
                )
                raw = response.text.strip()
                raw = re.sub(r"^```(?:json)?\s*", "", raw)
                raw = re.sub(r"\s*```$", "", raw)
                return json.loads(raw)
            except Exception as e:
                last_error = e
                continue

        raise last_error or RuntimeError("Failed to generate content with Gemini")

    except Exception as e:
        raise RuntimeError(f"Gemini API error: {str(e)}")


@app.route("/api/inspect", methods=["POST"])
def inspect_offer():
    """Primary endpoint: analyze an offer letter for phishing."""
    try:
        body = request.get_json(force=True)
        offer_text = (body.get("offer_text") or "").strip()
        company_url = (body.get("company_url") or "").strip()

        if not offer_text:
            return jsonify({"error": "offer_text is required"}), 400

        api_key = get_api_key()
        if not api_key:
            return jsonify({
                "error": "GEMINI_API_KEY not configured. Set it in your .env file.",
                "fallback": True
            }), 503

        result = call_gemini(offer_text, company_url)

        # Validate required keys are present
        required = ["scam_threat_index", "threat_level", "summary",
                    "red_flags_detected", "verification_checklist"]
        for key in required:
            if key not in result:
                raise ValueError(f"Missing key in Gemini response: {key}")

        return jsonify(result), 200

    except json.JSONDecodeError as e:
        return jsonify({"error": f"Failed to parse AI response as JSON: {str(e)}"}), 502
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    api_key = get_api_key()
    return jsonify({
        "status": "ok",
        "gemini_key_configured": bool(api_key),
        "model": os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
    })


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """Serve index.html and static files from root. Non-matching API routes return JSON 404."""
    if path.startswith("api/"):
        return jsonify({"error": "API endpoint not found"}), 404
    if path and os.path.exists(path) and not os.path.isdir(path):
        return send_from_directory(".", path)
    return send_from_directory(".", "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print(f"PhishShield AI backend running on http://localhost:{port}")
    key_status = "[OK] configured" if get_api_key() else "[MISSING] set GEMINI_API_KEY in .env"
    print(f"Gemini API key: {key_status}")
    app.run(host="0.0.0.0", port=port, debug=debug)
