import 'dart:convert';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PhishShieldApp());
}

// ══════════════════════════════════════════════════════════════════════════════
// THEME & CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════
class AppTheme {
  static const Color slate950 = Color(0xFF020617);
  static const Color slate900 = Color(0xFF0F172A);
  static const Color slate850 = Color(0xFF131E35);
  static const Color slate800 = Color(0xFF1E293B);
  static const Color slate700 = Color(0xFF334155);
  static const Color slate600 = Color(0xFF475569);
  static const Color slate400 = Color(0xFF94A3B8);
  static const Color slate200 = Color(0xFFE2E8F0);

  static const Color indigo500 = Color(0xFF6366F1);
  static const Color indigo400 = Color(0xFF818CF8);
  static const Color purple500 = Color(0xFF8B5CF6);

  static const Color emerald400 = Color(0xFF34D399);
  static const Color emerald500 = Color(0xFF10B981);
  static const Color amber400 = Color(0xFFFBBF24);
  static const Color orange400 = Color(0xFFFB923C);
  static const Color red500 = Color(0xFFEF4444);
  static const Color red400 = Color(0xFFF87171);

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: slate950,
      colorScheme: const ColorScheme.dark(
        primary: indigo500,
        secondary: purple500,
        surface: slate900,
      ),
      cardTheme: CardThemeData(
        color: slate900.withAlpha(200),
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: Color(0x33475569), width: 1),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: const Color(0x990F172A),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: Color(0x44475569)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: Color(0x44475569)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: indigo500, width: 1.5),
        ),
        hintStyle: const TextStyle(color: slate600, fontSize: 13),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// DATA MODELS
// ══════════════════════════════════════════════════════════════════════════════
enum Severity { critical, high, medium, low }

extension SeverityExt on Severity {
  String get label {
    switch (this) {
      case Severity.critical:
        return 'CRITICAL';
      case Severity.high:
        return 'HIGH';
      case Severity.medium:
        return 'MEDIUM';
      case Severity.low:
        return 'LOW';
    }
  }

  Color get color {
    switch (this) {
      case Severity.critical:
        return AppTheme.red400;
      case Severity.high:
        return AppTheme.orange400;
      case Severity.medium:
        return AppTheme.amber400;
      case Severity.low:
        return AppTheme.emerald400;
    }
  }

  Color get bgAlpha {
    switch (this) {
      case Severity.critical:
        return AppTheme.red500.withAlpha(35);
      case Severity.high:
        return AppTheme.orange400.withAlpha(35);
      case Severity.medium:
        return AppTheme.amber400.withAlpha(35);
      case Severity.low:
        return AppTheme.emerald500.withAlpha(35);
    }
  }
}

Severity parseSeverity(String? val) {
  final upper = (val ?? '').toUpperCase().trim();
  if (upper.contains('CRITICAL')) return Severity.critical;
  if (upper.contains('HIGH')) return Severity.high;
  if (upper.contains('MED')) return Severity.medium;
  return Severity.low;
}

class RedFlag {
  final String category;
  final String flagTitle;
  final String description;
  final Severity severity;

  const RedFlag({
    required this.category,
    required this.flagTitle,
    required this.description,
    required this.severity,
  });

  factory RedFlag.fromJson(Map<String, dynamic> json) {
    return RedFlag(
      category: json['category']?.toString() ?? 'General Indicator',
      flagTitle: json['flag_title']?.toString() ??
          json['title']?.toString() ??
          'Suspicious Pattern Detected',
      description: json['description']?.toString() ?? '',
      severity: parseSeverity(json['severity']?.toString()),
    );
  }
}

class InspectionResult {
  final int scamThreatIndex;
  final String threatLevel;
  final String summary;
  final List<RedFlag> redFlags;
  final List<String> verificationChecklist;
  final String engineUsed;

  const InspectionResult({
    required this.scamThreatIndex,
    required this.threatLevel,
    required this.summary,
    required this.redFlags,
    required this.verificationChecklist,
    required this.engineUsed,
  });

  factory InspectionResult.fromJson(
      Map<String, dynamic> json, String engine) {
    final flags = <RedFlag>[];
    if (json['red_flags_detected'] is List) {
      for (final item in json['red_flags_detected']) {
        if (item is Map<String, dynamic>) {
          flags.add(RedFlag.fromJson(item));
        }
      }
    }

    final checklist = <String>[];
    if (json['verification_checklist'] is List) {
      for (final item in json['verification_checklist']) {
        if (item != null) checklist.add(item.toString());
      }
    }

    return InspectionResult(
      scamThreatIndex:
          (json['scam_threat_index'] as num?)?.toInt().clamp(0, 100) ?? 0,
      threatLevel: (json['threat_level']?.toString() ?? 'LOW').toUpperCase(),
      summary: json['summary']?.toString() ?? 'Analysis completed.',
      redFlags: flags,
      verificationChecklist: checklist,
      engineUsed: engine,
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// OFFLINE HEURISTIC ENGINE (PURE DART)
// ══════════════════════════════════════════════════════════════════════════════
class HeuristicRule {
  final RegExp pattern;
  final int weight;
  final Severity severity;
  final String category;
  final String title;
  final String description;

  const HeuristicRule({
    required this.pattern,
    required this.weight,
    required this.severity,
    required this.category,
    required this.title,
    required this.description,
  });
}

class OfflineHeuristicsEngine {
  static final List<HeuristicRule> rules = [
    HeuristicRule(
      pattern: RegExp(r'cashier\s*check|money\s*order', caseSensitive: false),
      weight: 25,
      severity: Severity.critical,
      category: 'Financial Trap',
      title: 'Cashier Check Overpayment Scam',
      description:
          'Cashier check schemes are a hallmark of fraud. Victims deposit a fake check then wire back the difference, remaining liable for the bounced funds.',
    ),
    HeuristicRule(
      pattern: RegExp(r'wire\s*transfer|wiring\s*funds', caseSensitive: false),
      weight: 22,
      severity: Severity.critical,
      category: 'Financial Trap',
      title: 'Wire Transfer Demand',
      description:
          'Legitimate employers never ask candidates to wire funds. Wire transfers are irreversible and standard in financial scams.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'zelle|cashapp|venmo|paypal\s*friends|crypto|bitcoin|usdt',
          caseSensitive: false),
      weight: 20,
      severity: Severity.critical,
      category: 'Financial Trap',
      title: 'Peer-to-Peer / Crypto Payment Request',
      description:
          'Requests to send funds via Zelle, CashApp, or cryptocurrency cannot be reversed and are favored by scammers.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'deposit\s*(the\s*)?check|deposit\s*funds|deposit\s*immediately',
          caseSensitive: false),
      weight: 20,
      severity: Severity.critical,
      category: 'Financial Trap',
      title: 'Fake Check Deposit Scheme',
      description:
          'Urgent requests to deposit a company check and immediately disburse funds are typical advance-fee and overpayment traps.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'purchase\s*equipment|buy\s*(your\s*)?(laptop|computer|equipment)|equipment\s*kit',
          caseSensitive: false),
      weight: 22,
      severity: Severity.critical,
      category: 'Financial Trap',
      title: 'Pay-for-Equipment Trap',
      description:
          'Scammers ask victims to purchase work equipment from a fake "approved vendor", promising reimbursement that never arrives.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'reimbur(se|sement)|wire\s*back|send\s*back\s*the\s*difference',
          caseSensitive: false),
      weight: 18,
      severity: Severity.high,
      category: 'Financial Trap',
      title: 'Reimbursement Guarantee Lure',
      description:
          'Promises of later reimbursement are used to justify demanding upfront payments from the applicant.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'no\s*experience\s*(required|needed).*(\$\d{3}|\d{3}k|\d{3},\d{3})',
          caseSensitive: false),
      weight: 18,
      severity: Severity.high,
      category: 'Unrealistic Offer',
      title: 'Astronomical Salary for Zero Experience',
      description:
          'Promising six-figure salaries for simple entry-level roles with no experience required is a classic lure.',
    ),
    HeuristicRule(
      pattern: RegExp(r'telegram|whatsapp\s*(only|interview|meeting|contact)',
          caseSensitive: false),
      weight: 16,
      severity: Severity.high,
      category: 'Communication Red Flag',
      title: 'Off-Platform Chat Communication',
      description:
          'Moving candidate communication exclusively to Telegram or WhatsApp avoids verifiable corporate email records.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'no\s*interview|no\s*video\s*(call|interview)|text[\s-]only\s*interview',
          caseSensitive: false),
      weight: 14,
      severity: Severity.high,
      category: 'Communication Red Flag',
      title: 'No Video Interview Required',
      description:
          'Avoiding video calls allows fraudsters to hide their real identities while claiming to represent well-known corporations.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'@gmail\.com|@yahoo\.com|@hotmail\.com|@outlook\.com',
          caseSensitive: false),
      weight: 12,
      severity: Severity.high,
      category: 'Communication Red Flag',
      title: 'Free Webmail Domain for Corporate Hiring',
      description:
          'Legitimate enterprises conduct recruitment through their official domain, not free personal email providers.',
    ),
    HeuristicRule(
      pattern: RegExp(r'social\s*security|ssn|\bss\s*#', caseSensitive: false),
      weight: 22,
      severity: Severity.critical,
      category: 'Identity Theft',
      title: 'SSN Requested Prematurely',
      description:
          'Requesting sensitive identifiers such as Social Security Numbers prior to formal background checks is an identity theft indicator.',
    ),
    HeuristicRule(
      pattern: RegExp(r'bank\s*account\s*(and\s*)?routing|routing\s*number',
          caseSensitive: false),
      weight: 20,
      severity: Severity.critical,
      category: 'Identity Theft',
      title: 'Direct Deposit Banking Demanded Upfront',
      description:
          'Banking account and routing information should only be shared through secured employee self-service portals post-hire.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'driver.?s?\s*licen(s|c)e.*copy|(copy|scan|photo).*driver.?s?\s*licen',
          caseSensitive: false),
      weight: 15,
      severity: Severity.high,
      category: 'Identity Theft',
      title: 'Government ID Document Scan Requested',
      description:
          'Unverified requests for front and back scans of driver licenses or passports are frequently collected for credit fraud.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'expires?\s*in\s*\d+\s*(hours?|days?)|urgent.*reply|act\s*now|do\s*not\s*delay',
          caseSensitive: false),
      weight: 10,
      severity: Severity.medium,
      category: 'Urgency Pressure',
      title: 'Artificial Time Pressure & Expiry',
      description:
          'Short artificial deadlines (e.g. "Expires in 24 hours") are designed to pressure victims before they can independently verify.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'immediately|within\s*(24|48|72)\s*hours?|start\s*today',
          caseSensitive: false),
      weight: 8,
      severity: Severity.medium,
      category: 'Urgency Pressure',
      title: 'Immediate Onboarding Demand',
      description:
          'Demanding candidates begin employment immediately without standard transition periods is typical in fake-job operations.',
    ),
    HeuristicRule(
      pattern: RegExp(
          r'selected\s*(from|based\s*on)\s*(your\s*)?(indeed|linkedin|profile)|we\s*found\s*your\s*(resume|profile)',
          caseSensitive: false),
      weight: 12,
      severity: Severity.high,
      category: 'Social Engineering',
      title: 'Unsolicited Profile Recruitment',
      description:
          'Claiming to have selected you from a job board for a high-paying role you never applied for is a common phishing opener.',
    ),
  ];

  static InspectionResult analyze(String text) {
    int rawScore = 0;
    final detectedFlags = <RedFlag>[];
    final seenTitles = <String>{};

    for (final rule in rules) {
      if (rule.pattern.hasMatch(text)) {
        if (!seenTitles.contains(rule.title)) {
          seenTitles.add(rule.title);
          rawScore += rule.weight;
          detectedFlags.add(
            RedFlag(
              category: rule.category,
              flagTitle: rule.title,
              description: rule.description,
              severity: rule.severity,
            ),
          );
        }
      }
    }

    final score = ((rawScore / 120.0) * 100).round().clamp(0, 100);
    String threatLevel = 'LOW';
    if (score > 75) {
      threatLevel = 'CRITICAL';
    } else if (score > 50) {
      threatLevel = 'HIGH';
    } else if (score > 25) {
      threatLevel = 'MEDIUM';
    }

    final critCount =
        detectedFlags.where((f) => f.severity == Severity.critical).length;
    String summary;
    if (detectedFlags.isEmpty) {
      summary =
          'No significant phishing indicators were detected in the offline heuristic scan. Always verify through official channels before sharing sensitive information.';
    } else if (threatLevel == 'CRITICAL') {
      summary =
          'CRITICAL SCAM ALERT: Offline heuristics detected ${detectedFlags.length} red flags including $critCount CRITICAL indicators. Exhibits multiple hallmarks of employment fraud including financial traps and identity risk. Do NOT engage further.';
    } else if (threatLevel == 'HIGH') {
      summary =
          'HIGH RISK: ${detectedFlags.length} suspicious patterns detected. This offer shows significant warning signs consistent with job-offer phishing. Verify independently before proceeding.';
    } else {
      summary =
          'MODERATE RISK: ${detectedFlags.length} caution flag(s) detected. Several elements warrant careful verification with the legitimate company.';
    }

    return InspectionResult(
      scamThreatIndex: score,
      threatLevel: threatLevel,
      summary: summary,
      redFlags: detectedFlags,
      verificationChecklist: const [
        'Search the company name directly on Google — avoid links sent inside the email.',
        'Call the official company headquarters phone number listed on their public website to confirm HR employment.',
        'Ensure the sender email matches the corporate domain exactly (not a free Gmail/Yahoo account).',
        'Search the company name + "scam" or "fake job offer" on Reddit and Glassdoor.',
        'Never purchase equipment or transfer money before your employment begins.',
        'Confirm the job vacancy is officially listed on the employer\'s careers portal.',
        'Never disclose your SSN or bank account numbers over email or chat applications.',
        'Report fraudulent job solicitations to the FTC at reportfraud.ftc.gov.',
      ],
      engineUsed: 'Offline Dart Heuristics',
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// GEMINI REST API SERVICE
// ══════════════════════════════════════════════════════════════════════════════
class GeminiApiService {
  static const String systemInstruction = '''
You are PhishShield AI, an expert cybersecurity analyst specializing in job-offer phishing scams, fake employment fraud, pay-for-equipment schemes, and deposit traps targeting job seekers.

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
''';

  static Future<InspectionResult> inspect({
    required String offerText,
    required String apiKey,
    String? companyUrl,
  }) async {
    final candidateModels = ['gemini-2.5-flash', 'gemini-3.6-flash', 'gemini-1.5-flash'];
    Exception? lastError;

    for (final model in candidateModels) {
      try {
        final url = Uri.parse(
          'https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent?key=$apiKey',
        );

        final payload = {
          'system_instruction': {
            'parts': [
              {'text': systemInstruction}
            ]
          },
          'contents': [
            {
              'role': 'user',
              'parts': [
                {
                  'text':
                      'Please analyze the following job offer for phishing indicators:\n\nOFFER LETTER TEXT:\n$offerText\n\nCOMPANY URL:\n${companyUrl?.isNotEmpty == true ? companyUrl : "Not provided"}\n\nReturn JSON only.'
                }
              ]
            }
          ],
          'generationConfig': {
            'response_mime_type': 'application/json',
            'temperature': 0.1,
          }
        };

        final response = await http
            .post(
              url,
              headers: {'Content-Type': 'application/json'},
              body: jsonEncode(payload),
            )
            .timeout(const Duration(seconds: 15));

        if (response.statusCode == 200) {
          final body = jsonDecode(response.body) as Map<String, dynamic>;
          final candidates = body['candidates'] as List?;
          if (candidates != null && candidates.isNotEmpty) {
            final parts = candidates[0]['content']?['parts'] as List?;
            if (parts != null && parts.isNotEmpty) {
              String rawText = parts[0]['text']?.toString().trim() ?? '{}';
              rawText = rawText.replaceAll(RegExp(r'^```(json)?'), '');
              rawText = rawText.replaceAll(RegExp(r'```$'), '');
              final parsed = jsonDecode(rawText) as Map<String, dynamic>;
              return InspectionResult.fromJson(parsed, 'Gemini AI ($model)');
            }
          }
        }
        lastError = Exception('API returned status ${response.statusCode}: ${response.body}');
      } catch (e) {
        lastError = e is Exception ? e : Exception(e.toString());
      }
    }

    throw lastError ?? Exception('Failed to connect to Gemini API');
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SAMPLE PHISHING OFFER
// ══════════════════════════════════════════════════════════════════════════════
const String sampleScamOffer =
    '''Subject: URGENT — Congratulations! Job Offer from Apex Remote Solutions Inc.

Dear Candidate,

We are pleased to extend a formal offer of employment for the position of Remote Data Entry Specialist at Apex Remote Solutions Inc. (www.apex-remote-solutions-inc-jobs.net).

POSITION DETAILS:
Title: Senior Remote Data Entry Specialist
Annual Salary: \$150,000 – \$180,000 (NO EXPERIENCE REQUIRED)
Start Date: IMMEDIATELY — within 48 hours of acceptance
Location: 100% work-from-home (WhatsApp team meetings only)

This position requires NO interview. You were selected based on your profile from Indeed/LinkedIn. The hiring decision has been approved by our HR Director, Mr. Daniel Whitmore (danielwhitmore.hr@gmail.com).

EQUIPMENT SETUP — ACTION REQUIRED:
To begin working immediately, you must purchase your home-office equipment kit directly from our certified vendor:
• Dell Laptop (Work Edition) — \$1,200
• Ergonomic Chair + Desk Setup — \$450
• Encrypted USB Security Key — \$85

Total: \$1,735 USD

You must purchase these items TODAY using Zelle, CashApp, or wire transfer to:
Account: 8847291033
Routing: 021000021

YOU WILL BE FULLY REIMBURSED on your first paycheck within 3 business days. We will also mail you a cashier check for \$2,500 (includes equipment + signing bonus). Please deposit the check immediately and wire back the difference of \$765 to cover licensing fees.

We are also requesting the following to complete your onboarding:
• Full legal name and date of birth
• Social Security Number (SSN)
• Bank account and routing number for direct deposit setup
• Copy of driver's license (front and back)

Reply to this email with all documents attached, or message our HR representative on Telegram: @apexhr_daniel

This offer expires in 24 HOURS. Do not delay — positions are filling fast!

Warm regards,
Daniel Whitmore
Director of Human Resources
Apex Remote Solutions Inc.''';

// ══════════════════════════════════════════════════════════════════════════════
// MAIN APPLICATION ROOT
// ══════════════════════════════════════════════════════════════════════════════
class PhishShieldApp extends StatelessWidget {
  const PhishShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PhishShield AI',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: const HomeScreen(),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// HOME SCREEN
// ══════════════════════════════════════════════════════════════════════════════
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  final TextEditingController _offerTextController = TextEditingController();
  final TextEditingController _companyUrlController = TextEditingController();
  String _customApiKey = '';
  bool _isLoading = false;
  InspectionResult? _result;
  late AnimationController _gaugeAnimController;
  late Animation<double> _gaugeAnimation;

  @override
  void initState() {
    super.initState();
    _gaugeAnimController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _gaugeAnimation =
        Tween<double>(begin: 0, end: 0).animate(CurvedAnimation(
      parent: _gaugeAnimController,
      curve: Curves.easeOutCubic,
    ));
  }

  @override
  void dispose() {
    _offerTextController.dispose();
    _companyUrlController.dispose();
    _gaugeAnimController.dispose();
    super.dispose();
  }

  void _loadSample() {
    setState(() {
      _offerTextController.text = sampleScamOffer;
      _companyUrlController.text =
          'https://apex-remote-solutions-inc-jobs.net/careers';
    });
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Realistic phishing scam sample loaded!'),
        backgroundColor: AppTheme.indigo500,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  void _clear() {
    setState(() {
      _offerTextController.clear();
      _companyUrlController.clear();
      _result = null;
    });
    _gaugeAnimController.reset();
  }

  Future<void> _inspectOffer() async {
    final text = _offerTextController.text.trim();
    if (text.length < 50) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please paste at least 50 characters of offer text.'),
          backgroundColor: AppTheme.amber400,
          behavior: SnackBarBehavior.floating,
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
    });

    InspectionResult result;
    if (_customApiKey.isNotEmpty) {
      try {
        result = await GeminiApiService.inspect(
          offerText: text,
          apiKey: _customApiKey,
          companyUrl: _companyUrlController.text.trim(),
        );
      } catch (e) {
        // Fallback to offline engine
        result = OfflineHeuristicsEngine.analyze(text);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                  'Gemini API request failed ($e). Switched to offline heuristics engine.'),
              backgroundColor: AppTheme.orange400,
              behavior: SnackBarBehavior.floating,
            ),
          );
        }
      }
    } else {
      // Direct offline heuristic scan
      result = OfflineHeuristicsEngine.analyze(text);
    }

    setState(() {
      _isLoading = false;
      _result = result;
      _gaugeAnimation = Tween<double>(
        begin: 0,
        end: result.scamThreatIndex.toDouble(),
      ).animate(CurvedAnimation(
        parent: _gaugeAnimController,
        curve: Curves.easeOutCubic,
      ));
    });
    _gaugeAnimController.forward(from: 0);
  }

  void _openApiKeyDialog() {
    final controller = TextEditingController(text: _customApiKey);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.slate900,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppTheme.slate700),
        ),
        title: const Row(
          children: [
            Icon(Icons.key, color: AppTheme.indigo400, size: 20),
            SizedBox(width: 8),
            Text('Gemini API Key Settings', style: TextStyle(fontSize: 18)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter your Google AI Studio API key for cloud AI analysis. If left empty, PhishShield AI will use the built-in offline heuristic engine.',
              style: TextStyle(fontSize: 12, color: AppTheme.slate400),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: controller,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'GEMINI_API_KEY',
                hintText: 'AIzaSy...',
                prefixIcon: Icon(Icons.lock_outline, size: 18),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              setState(() => _customApiKey = '');
              Navigator.pop(ctx);
            },
            child: const Text('Clear Key',
                style: TextStyle(color: AppTheme.slate400)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.indigo500,
              foregroundColor: Colors.white,
            ),
            onPressed: () {
              setState(() => _customApiKey = controller.text.trim());
              Navigator.pop(ctx);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _buildAppBar(),
      body: LayoutBuilder(
        builder: (context, constraints) {
          final isWide = constraints.maxWidth >= 900;
          return SingleChildScrollView(
            padding: const EdgeInsets.all(20),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1300),
                child: isWide
                    ? Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(flex: 5, child: _buildInputPanel()),
                          const SizedBox(width: 24),
                          Expanded(flex: 6, child: _buildResultsPanel()),
                        ],
                      )
                    : Column(
                        children: [
                          _buildInputPanel(),
                          const SizedBox(height: 24),
                          _buildResultsPanel(),
                        ],
                      ),
              ),
            ),
          );
        },
      ),
    );
  }

  PreferredSizeWidget _buildAppBar() {
    final hasKey = _customApiKey.isNotEmpty;
    return AppBar(
      backgroundColor: AppTheme.slate950,
      elevation: 0,
      surfaceTintColor: Colors.transparent,
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [AppTheme.indigo500, AppTheme.purple500],
              ),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.shield_outlined,
                color: Colors.white, size: 20),
          ),
          const SizedBox(width: 12),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'PhishShield AI',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
              ),
              Text(
                'Cross-Platform Job Scam Detector',
                style: TextStyle(fontSize: 11, color: AppTheme.slate400),
              ),
            ],
          ),
        ],
      ),
      actions: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: hasKey
                ? AppTheme.emerald500.withAlpha(30)
                : AppTheme.amber400.withAlpha(30),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: hasKey ? AppTheme.emerald400 : AppTheme.amber400,
              width: 1,
            ),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                hasKey ? Icons.cloud_done : Icons.bolt,
                size: 14,
                color: hasKey ? AppTheme.emerald400 : AppTheme.amber400,
              ),
              const SizedBox(width: 6),
              Text(
                hasKey ? 'GEMINI ONLINE' : 'OFFLINE HEURISTICS',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  color: hasKey ? AppTheme.emerald400 : AppTheme.amber400,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: 10),
        IconButton(
          tooltip: 'Configure API Key',
          icon: const Icon(Icons.settings_outlined, color: AppTheme.slate400),
          onPressed: _openApiKeyDialog,
        ),
        const SizedBox(width: 12),
      ],
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(color: const Color(0x33475569)),
      ),
    );
  }

  // ───────────────── LEFT: INPUT PANEL ─────────────────
  Widget _buildInputPanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text(
              'OFFER INSPECTION',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                letterSpacing: 1.2,
                color: AppTheme.slate400,
              ),
            ),
            TextButton.icon(
              onPressed: _loadSample,
              icon: const Icon(Icons.auto_fix_high, size: 14),
              label: const Text('Load Sample', style: TextStyle(fontSize: 12)),
              style: TextButton.styleFrom(
                foregroundColor: AppTheme.indigo400,
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.email_outlined,
                        size: 16, color: AppTheme.indigo400),
                    SizedBox(width: 8),
                    Text(
                      'Offer Letter / Email Text',
                      style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: AppTheme.slate200),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _offerTextController,
                  maxLines: 12,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12.5,
                      color: AppTheme.slate200),
                  decoration: const InputDecoration(
                    hintText:
                        'Paste the full offer letter, interview transcript, or suspicious recruitment email here...',
                  ),
                ),
                const SizedBox(height: 16),
                const Row(
                  children: [
                    Icon(Icons.link, size: 16, color: AppTheme.indigo400),
                    SizedBox(width: 8),
                    Text(
                      'Target Company / Job URL (Optional)',
                      style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: AppTheme.slate200),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _companyUrlController,
                  style: const TextStyle(fontSize: 13),
                  decoration: const InputDecoration(
                    hintText: 'https://example-careers.com/posting',
                    prefixIcon: Icon(Icons.public, size: 18),
                  ),
                ),
                const SizedBox(height: 20),
                Row(
                  children: [
                    Expanded(
                      child: Container(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(12),
                          gradient: const LinearGradient(
                            colors: [AppTheme.indigo500, AppTheme.purple500],
                          ),
                          boxShadow: [
                            BoxShadow(
                              color: AppTheme.indigo500.withAlpha(80),
                              blurRadius: 16,
                              offset: const Offset(0, 4),
                            ),
                          ],
                        ),
                        child: ElevatedButton(
                          onPressed: _isLoading ? null : _inspectOffer,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.transparent,
                            shadowColor: Colors.transparent,
                            padding: const EdgeInsets.symmetric(vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                          ),
                          child: _isLoading
                              ? const SizedBox(
                                  width: 20,
                                  height: 20,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2.5,
                                    color: Colors.white,
                                  ),
                                )
                              : const Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(Icons.security,
                                        size: 18, color: Colors.white),
                                    SizedBox(width: 8),
                                    Text(
                                      'Inspect Offer',
                                      style: TextStyle(
                                          fontWeight: FontWeight.bold,
                                          fontSize: 14,
                                          color: Colors.white),
                                    ),
                                  ],
                                ),
                        ),
                      ),
                    ),
                    if (_result != null) ...[
                      const SizedBox(width: 12),
                      IconButton.outlined(
                        tooltip: 'Clear Form',
                        onPressed: _clear,
                        icon: const Icon(Icons.refresh, color: AppTheme.slate400),
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  // ───────────────── RIGHT: RESULTS PANEL ─────────────────
  Widget _buildResultsPanel() {
    if (_result == null) {
      return Card(
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 80, horizontal: 24),
          alignment: Alignment.center,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: AppTheme.indigo500.withAlpha(25),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.shield_moon_outlined,
                  size: 48,
                  color: AppTheme.indigo400,
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'Ready for Inspection',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              const Text(
                'Paste an offer letter on the left and click "Inspect Offer" to run dual-engine AI & heuristic analysis.',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 13, color: AppTheme.slate400),
              ),
            ],
          ),
        ),
      );
    }

    final res = _result!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text(
              'THREAT INTELLIGENCE RESULTS',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                letterSpacing: 1.2,
                color: AppTheme.slate400,
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: AppTheme.slate800,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                'Engine: ${res.engineUsed}',
                style: const TextStyle(fontSize: 11, color: AppTheme.slate400),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),

        // Threat Overview Card with Animated Gauge
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Row(
                  children: [
                    // Circular Threat Gauge
                    AnimatedBuilder(
                      animation: _gaugeAnimation,
                      builder: (context, child) {
                        return SizedBox(
                          width: 120,
                          height: 120,
                          child: CustomPaint(
                            painter: ThreatGaugePainter(
                              value: _gaugeAnimation.value,
                              threatLevel: res.threatLevel,
                            ),
                            child: Center(
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    '${_gaugeAnimation.value.round()}%',
                                    style: const TextStyle(
                                      fontSize: 22,
                                      fontWeight: FontWeight.w900,
                                      color: Colors.white,
                                    ),
                                  ),
                                  const Text(
                                    'THREAT',
                                    style: TextStyle(
                                      fontSize: 9,
                                      fontWeight: FontWeight.bold,
                                      color: AppTheme.slate400,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                    const SizedBox(width: 20),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildThreatBadge(res.threatLevel),
                          const SizedBox(height: 10),
                          Text(
                            res.threatLevel == 'CRITICAL' ||
                                    res.threatLevel == 'HIGH'
                                ? 'High Probability Scam'
                                : res.threatLevel == 'MEDIUM'
                                    ? 'Caution Warranted'
                                    : 'Low Risk Detected',
                            style: const TextStyle(
                                fontSize: 16, fontWeight: FontWeight.bold),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '${res.redFlags.length} red flag pattern(s) identified in text.',
                            style: const TextStyle(
                                fontSize: 12, color: AppTheme.slate400),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const Divider(color: Color(0x22475569), height: 28),
                Text(
                  res.summary,
                  style: const TextStyle(
                      fontSize: 13,
                      height: 1.5,
                      color: AppTheme.slate200),
                ),
              ],
            ),
          ),
        ),

        const SizedBox(height: 16),

        // Red Flags List
        if (res.redFlags.isNotEmpty) ...[
          Text(
            'RED FLAGS DETECTED (${res.redFlags.length})',
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
              color: AppTheme.slate400,
            ),
          ),
          const SizedBox(height: 8),
          ...res.redFlags.map((flag) => _buildRedFlagCard(flag)),
          const SizedBox(height: 16),
        ],

        // Verification Checklist
        if (res.verificationChecklist.isNotEmpty) ...[
          const Text(
            'SAFETY VERIFICATION CHECKLIST',
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
              color: AppTheme.slate400,
            ),
          ),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                children: res.verificationChecklist
                    .map((item) => _ChecklistTile(text: item))
                    .toList(),
              ),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildThreatBadge(String level) {
    Color color;
    Color bgColor;
    switch (level) {
      case 'CRITICAL':
        color = AppTheme.red400;
        bgColor = AppTheme.red500.withAlpha(40);
        break;
      case 'HIGH':
        color = AppTheme.orange400;
        bgColor = AppTheme.orange400.withAlpha(40);
        break;
      case 'MEDIUM':
        color = AppTheme.amber400;
        bgColor = AppTheme.amber400.withAlpha(40);
        break;
      default:
        color = AppTheme.emerald400;
        bgColor = AppTheme.emerald500.withAlpha(40);
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withAlpha(120)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.warning_amber_rounded, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            level,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w900,
              color: color,
              letterSpacing: 1,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRedFlagCard(RedFlag flag) {
    IconData icon;
    switch (flag.category) {
      case 'Financial Trap':
        icon = Icons.account_balance_wallet_outlined;
        break;
      case 'Identity Theft':
        icon = Icons.badge_outlined;
        break;
      case 'Social Engineering':
        icon = Icons.psychology_outlined;
        break;
      case 'Urgency Pressure':
        icon = Icons.timer_outlined;
        break;
      case 'Communication Red Flag':
        icon = Icons.mark_chat_read_outlined;
        break;
      case 'Unrealistic Offer':
        icon = Icons.star_border_purple500_outlined;
        break;
      default:
        icon = Icons.warning_amber_outlined;
        break;
    }

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppTheme.indigo500.withAlpha(25),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, color: AppTheme.indigo400, size: 18),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Text(
                          flag.flagTitle,
                          style: const TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                              color: AppTheme.slate200),
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: flag.severity.bgAlpha,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          flag.severity.label,
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: flag.severity.color,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    flag.description,
                    style: const TextStyle(
                        fontSize: 12, height: 1.4, color: AppTheme.slate400),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    flag.category,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 10,
                      color: AppTheme.slate600,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// THREAT GAUGE CUSTOM PAINTER
// ══════════════════════════════════════════════════════════════════════════════
class ThreatGaugePainter extends CustomPainter {
  final double value;
  final String threatLevel;

  ThreatGaugePainter({required this.value, required this.threatLevel});

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 10;
    const strokeWidth = 10.0;

    // Background track
    final bgPaint = Paint()
      ..color = AppTheme.slate800
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      math.pi * 0.8,
      math.pi * 1.4,
      false,
      bgPaint,
    );

    // Active sweep arc
    Color activeColor;
    if (value > 75) {
      activeColor = AppTheme.red400;
    } else if (value > 50) {
      activeColor = AppTheme.orange400;
    } else if (value > 25) {
      activeColor = AppTheme.amber400;
    } else {
      activeColor = AppTheme.emerald400;
    }

    final sweepAngle = (value / 100.0) * (math.pi * 1.4);
    final activePaint = Paint()
      ..color = activeColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      math.pi * 0.8,
      sweepAngle,
      false,
      activePaint,
    );
  }

  @override
  bool shouldRepaint(covariant ThreatGaugePainter oldDelegate) {
    return oldDelegate.value != value || oldDelegate.threatLevel != threatLevel;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECKLIST ITEM TILE
// ══════════════════════════════════════════════════════════════════════════════
class _ChecklistTile extends StatefulWidget {
  final String text;
  const _ChecklistTile({required this.text});

  @override
  State<_ChecklistTile> createState() => _ChecklistTileState();
}

class _ChecklistTileState extends State<_ChecklistTile> {
  bool _checked = false;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(8),
      onTap: () => setState(() => _checked = !_checked),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              _checked
                  ? Icons.check_circle
                  : Icons.radio_button_unchecked,
              size: 18,
              color:
                  _checked ? AppTheme.emerald400 : AppTheme.slate600,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                widget.text,
                style: TextStyle(
                  fontSize: 12,
                  height: 1.4,
                  decoration:
                      _checked ? TextDecoration.lineThrough : null,
                  color: _checked
                      ? AppTheme.slate600
                      : AppTheme.slate400,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
