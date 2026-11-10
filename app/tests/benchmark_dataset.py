"""Labelled evaluation benchmark dataset for AMANA SHIELD AI and Risk Fusion quality testing.

Contains realistic Nigerian electoral and civic scam test cases spanning 7 categories:
1. GENUINE_ANNOUNCEMENT
2. FAKE_ANNOUNCEMENT
3. MISLEADING_MESSAGE
4. PHISHING_MESSAGE
5. SUSPICIOUS_LINK
6. UNKNOWN_CLAIM
7. AMBIGUOUS_MESSAGE
"""

from __future__ import annotations

from typing import TypedDict

from app.models.entities import PublicVerdict


class BenchmarkTestCase(TypedDict):
    id: str
    category: str
    text: str
    ground_truth_verdict: PublicVerdict
    expected_abstention: bool
    description: str


BENCHMARK_DATASET: list[BenchmarkTestCase] = [
    # -------------------------------------------------------------------------
    # 1. Genuine Announcements (Expected: OFFICIAL or verified benign)
    # -------------------------------------------------------------------------
    {
        "id": "GEN-01",
        "category": "GENUINE_ANNOUNCEMENT",
        "text": "The Independent National Electoral Commission (INEC) announces the schedule for Continuous Voter Registration. Visit the official portal at https://inecnigeria.org for polling unit verification.",
        "ground_truth_verdict": PublicVerdict.OFFICIAL,
        "expected_abstention": False,
        "description": "Legitimate INEC schedule with verified official domain",
    },
    {
        "id": "GEN-02",
        "category": "GENUINE_ANNOUNCEMENT",
        "text": "National Youth Service Corps (NYSC) management advises prospective corps members to check their call-up letters exclusively on https://nysc.org.ng. No fee is required.",
        "ground_truth_verdict": PublicVerdict.OFFICIAL,
        "expected_abstention": False,
        "description": "Official NYSC mobilization notice with verified official portal",
    },
    {
        "id": "GEN-03",
        "category": "GENUINE_ANNOUNCEMENT",
        "text": "National Identity Management Commission (NIMC) official reminder: Enrolment for the National Identification Number (NIN) remains free at all accredited centres nationwide. Visit https://nimc.gov.ng for centres.",
        "ground_truth_verdict": PublicVerdict.OFFICIAL,
        "expected_abstention": False,
        "description": "Legitimate NIMC announcement stating NIN is free with official gov.ng URL",
    },

    # -------------------------------------------------------------------------
    # 2. Fake Announcements (Expected: MALICIOUS or SUSPICIOUS)
    # -------------------------------------------------------------------------
    {
        "id": "FAKE-01",
        "category": "FAKE_ANNOUNCEMENT",
        "text": "Federal Government has approved N50,000 cash grant to all Nigerian citizens above 18 to support economic recovery. Apply immediately at http://fg-grant-support.xyz before portal closes today!",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Fake FG cash grant with artificial urgency and unofficial .xyz domain",
    },
    {
        "id": "FAKE-02",
        "category": "FAKE_ANNOUNCEMENT",
        "text": "Presidential Empowerment Initiative 2026: The Federal Government is distributing free brand new laptops and N100,000 allowance to all Nigerian youth. Register now: http://nigeria-youth-empowerment.online",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Fake laptop and allowance empowerment scam",
    },
    {
        "id": "FAKE-03",
        "category": "FAKE_ANNOUNCEMENT",
        "text": "Federal Ministry of Humanitarian Affairs 2026 ongoing recruitment. Successful applicants will be paid N85,000 monthly. Pay N2,500 registration fee to guarantee placement. Apply: http://humanitarian-jobs.site",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Fake federal recruitment demanding registration fee",
    },

    # -------------------------------------------------------------------------
    # 3. Misleading Messages (Expected: SUSPICIOUS or contradicted)
    # -------------------------------------------------------------------------
    {
        "id": "MIS-01",
        "category": "MISLEADING_MESSAGE",
        "text": "URGENT INEC NOTICE: INEC has suspended all voter registration indefinitely nationwide. Polling units have been cancelled for the forthcoming election. Forward this message to all groups!",
        "ground_truth_verdict": PublicVerdict.SUSPICIOUS,
        "expected_abstention": False,
        "description": "False electoral cancellation and viral forwarding panic manipulation",
    },
    {
        "id": "MIS-02",
        "category": "MISLEADING_MESSAGE",
        "text": "INEC has officially announced that voters can now cast their ballot online from home using WhatsApp. Click here to verify your online voting slot: http://inec-online-voting.info",
        "ground_truth_verdict": PublicVerdict.SUSPICIOUS,
        "expected_abstention": False,
        "description": "Misleading claim about online WhatsApp voting contradictory to electoral act",
    },
    {
        "id": "MIS-03",
        "category": "MISLEADING_MESSAGE",
        "text": "The Central Bank of Nigeria (CBN) has ordered all commercial banks to block accounts without voter card linkage by Friday. Check your status here immediately: http://cbn-voter-link.biz",
        "ground_truth_verdict": PublicVerdict.SUSPICIOUS,
        "expected_abstention": False,
        "description": "Fabricated bank deadline tied to PVC card",
    },

    # -------------------------------------------------------------------------
    # 4. Phishing Messages (Expected: MALICIOUS)
    # -------------------------------------------------------------------------
    {
        "id": "PHISH-01",
        "category": "PHISHING_MESSAGE",
        "text": "INEC Ad-hoc Staff Recruitment 2026: Enter your BVN, NIN, ATM card digits, and banking OTP to receive your N120,000 mobilization payment immediately at http://inec-adhoc-portal.com/login",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Critical credential harvesting targeting BVN, NIN, and OTP",
    },
    {
        "id": "PHISH-02",
        "category": "PHISHING_MESSAGE",
        "text": "Central Bank of Nigeria COVID relief bonus crediting: Submit your 16-digit debit card number, expiry, CVV, and ATM PIN at http://cbn-credit-alert.com to unlock your trapped relief funds.",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Direct bank card and PIN harvesting scam",
    },
    {
        "id": "PHISH-03",
        "category": "PHISHING_MESSAGE",
        "text": "NIMC NIN Verification Error: Your National Identification Number has been flagged and suspended. Reply with your full name, mother's maiden name, date of birth, and BVN to reactivate immediately.",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "NIN suspension phishing requesting BVN and identity details",
    },

    # -------------------------------------------------------------------------
    # 5. Suspicious Links & Typosquatting (Expected: MALICIOUS or SUSPICIOUS)
    # -------------------------------------------------------------------------
    {
        "id": "LINK-01",
        "category": "SUSPICIOUS_LINK",
        "text": "Check your official INEC voter registration status here: https://inecnіgeria.org/cvr (Note: cyrillic lookalike domain)",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "IDN homograph punycode lookalike domain mimicking INEC",
    },
    {
        "id": "LINK-02",
        "category": "SUSPICIOUS_LINK",
        "text": "President Tinubu empowerment grant: Click the shortlink to apply hxxps://tinyurl[.]com/fg-grant-2026 immediately.",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Defanged shortened URL masking fake grant destination",
    },
    {
        "id": "LINK-03",
        "category": "SUSPICIOUS_LINK",
        "text": "Verify your PVC card online: http://192.168.1.100:8080/pvc-check (Private IP host in public link)",
        "ground_truth_verdict": PublicVerdict.MALICIOUS,
        "expected_abstention": False,
        "description": "Private network IP address literal in message link",
    },

    # -------------------------------------------------------------------------
    # 6. Unknown Claims (Expected: UNVERIFIED / Abstention Invariant)
    # -------------------------------------------------------------------------
    {
        "id": "UNK-01",
        "category": "UNKNOWN_CLAIM",
        "text": "Community leaders in Ward 4, Kaura Local Government announce that youth group meetings will hold this Saturday at the town hall.",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "Hyper-local community announcement with no national official record; must abstain",
    },
    {
        "id": "UNK-02",
        "category": "UNKNOWN_CLAIM",
        "text": "A civil society group claims that voter turnout in the 1999 election was higher than in 2003 according to historical records.",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "Historical academic opinion with no immediate threat indicators; must abstain",
    },
    {
        "id": "UNK-03",
        "category": "UNKNOWN_CLAIM",
        "text": "Local farmers association in Benue State is planning an agricultural symposium next month.",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "Benign unverified non-governmental claim; must abstain cleanly",
    },

    # -------------------------------------------------------------------------
    # 7. Ambiguous Messages (Expected: UNVERIFIED or low-risk abstention)
    # -------------------------------------------------------------------------
    {
        "id": "AMB-01",
        "category": "AMBIGUOUS_MESSAGE",
        "text": "Good morning my brothers and sisters. Please pray for peace in our nation during this election season. God bless Nigeria.",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "Religious civic greeting with zero scam or official claims",
    },
    {
        "id": "AMB-02",
        "category": "AMBIGUOUS_MESSAGE",
        "text": "Nigeria will rise again. Let us all stand together for democracy and unity.",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "Patriotic sentiment with no actionable URLs or scam signals",
    },
    {
        "id": "AMB-03",
        "category": "AMBIGUOUS_MESSAGE",
        "text": "Who is the candidate for the local council seat? Does anyone know the office address?",
        "ground_truth_verdict": PublicVerdict.UNVERIFIED,
        "expected_abstention": True,
        "description": "General conversational citizen inquiry",
    },
]
