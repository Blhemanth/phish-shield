import 'package:flutter_test/flutter_test.dart';
import 'package:phish_shield/main.dart';

void main() {
  test('OfflineHeuristicsEngine detects phishing scams correctly', () {
    const scamText = '''
Dear Candidate,
We are pleased to offer you the Remote Data Entry position at \$150,000 per year with no experience required.
To begin immediately, please purchase your equipment kit for \$1,200 via Zelle or wire transfer.
We will send you a cashier check to reimburse the difference.
Please send your SSN and driver's license copy immediately.
''';

    final result = OfflineHeuristicsEngine.analyze(scamText);

    expect(result.scamThreatIndex, greaterThanOrEqualTo(75));
    expect(result.threatLevel, equals('CRITICAL'));
    expect(result.redFlags.isNotEmpty, isTrue);
    expect(result.engineUsed, equals('Offline Dart Heuristics'));
  });

  testWidgets('PhishShieldApp renders header and input fields', (WidgetTester tester) async {
    await tester.pumpWidget(const PhishShieldApp());
    await tester.pumpAndSettle();

    expect(find.text('PhishShield AI'), findsOneWidget);
    expect(find.text('OFFER INSPECTION'), findsOneWidget);
    expect(find.text('Load Sample'), findsOneWidget);
    expect(find.text('Inspect Offer'), findsOneWidget);
  });
}
