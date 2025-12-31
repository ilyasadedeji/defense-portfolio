"""
SMS Threat Detection System - Day 3, Session 3
Defense Application: Detect terrorism, kidnapping, and security threats in communications
Mission: Identify and flag threatening messages for security agencies
"""

import re
import json
from datetime import datetime
from collections import Counter

# 🔵 TYPE THIS - Threat keywords database (INTELLIGENCE DATA)
THREAT_KEYWORDS = {
    'terrorism': [
        'Revenge', 'Blow you away', 'Don''t make me', 'infidel', 'Find you', 'Hurt you',
        'Kill you', 'gun-down', 'isis', 'al-qaeda', 'massacre', 'attack',
        'bomb', 'explosive', 'suicide', 'shoot', 'holy war', 'stab you'
    ],
    'kidnapping': [
        'ransom', 'kidnap', 'abduct', 'hostage', 'captive', 'release fee',
        'pay or die', 'we have your', 'forest', 'hideout', 'negotiate',
        'family safe', 'deliver money', 'drop location', 'cash delivery'
    ],
    'armed_robbery': [
        'rob', 'armed gang', 'highway', 'operation', 'heist', 'loot',
        'cartel', 'syndicate', 'target', 'hit', 'score', 'goods'
    ],
    'banditry': [
        'cattle', 'rustling', 'raid', 'village attack', 'settlement',
        'grazing', 'herders', 'clash', 'invasion', 'militia'
    ],
    'weapon_trafficking': [
        'ak-47', 'ak47', 'rifle', 'ammunition', 'bullets', 'arms',
        'weapons', 'guns', 'explosives', 'grenade', 'rpg', 'dealer'
    ],
    'recruitment': [
        'join us', 'recruitment', 'training camp', 'brothers', 'cause',
        'fight with us', 'paradise awaits', 'rewards', 'afterlife',
        'join the struggle', 'become warrior', 'training'
    ],
    'threat': [
        'kill', 'murder', 'death', 'eliminate', 'destroy', 'attack',
        'strike', 'target', 'revenge', 'payback', 'retaliate', 'die',
        'blood', 'slaughter', 'massacre', 'ambush'
    ]
}

# Suspicious patterns (regex)
SUSPICIOUS_PATTERNS = [
    r'\b\d{1,3}[.,]\d{3}[.,]\d{3}\b',  # Large money amounts (e.g., 2,000,000)
    r'\b\d{11}\b',  # Phone numbers (11 digits)
    r'bring.*money|deliver.*cash|pay.*amount',  # Payment demands
    r'forest|sambisa|highway|border',  # Suspicious locations
    r'tonight|tomorrow|next week|soon',  # Time urgency
]


# 🔵- Threat analysis engine
def analyze_sms_threat(message, sender_number=None):
    """
    Analyze SMS message for security threats
    Returns threat level and detailed analysis
    """
    message_lower = message.lower()
    
    # Initialize threat scores
    threat_scores = {category: 0 for category in THREAT_KEYWORDS.keys()}
    matched_keywords = {category: [] for category in THREAT_KEYWORDS.keys()}
    
    # Check for threat keywords
    for category, keywords in THREAT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in message_lower:
                threat_scores[category] += 1
                matched_keywords[category].append(keyword)
    
    # Check suspicious patterns
    pattern_matches = []
    for pattern in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, message, re.IGNORECASE)
        if matches:
            pattern_matches.extend(matches)
    
    # Calculate overall threat score
    total_threat_score = sum(threat_scores.values())
    
    # Determine threat level
    if total_threat_score >= 5:
        threat_level = 'CRITICAL'
        priority = 'URGENT'
        action = 'IMMEDIATE_INVESTIGATION'
    elif total_threat_score >= 3:
        threat_level = 'HIGH'
        priority = 'PRIORITY'
        action = 'DETAILED_ANALYSIS_REQUIRED'
    elif total_threat_score >= 1:
        threat_level = 'MEDIUM'
        priority = 'MONITOR'
        action = 'CONTINUE_SURVEILLANCE'
    else:
        threat_level = 'LOW'
        priority = 'ROUTINE'
        action = 'STANDARD_MONITORING'

            
    # Identify primary threat category
    primary_threat = max(threat_scores, key=threat_scores.get) if total_threat_score > 0 else 'none'
    
    # Build analysis result
    result = {
        'message': message,
        'sender': sender_number,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'threat_level': threat_level,
        'priority': priority,
        'action': action,
        'threat_score': total_threat_score,
        'primary_threat': primary_threat,
        'category_scores': threat_scores,
        'matched_keywords': {k: v for k, v in matched_keywords.items() if v},
        'pattern_matches': pattern_matches,
        'requires_human_review': total_threat_score >= 3
    }
    
    return result



# 🔵 TYPE THIS - Language pattern detection
def detect_suspicious_language_patterns(message):
    """
    Detect suspicious language patterns and communication styles
    Often used by criminals to avoid detection
    """
    suspicious_indicators = []
    
    # Check for excessive use of code words
    code_words = ['package', 'delivery', 'goods', 'item', 'product', 
                  'client', 'business', 'transaction', 'deal']
    code_word_count = sum(1 for word in code_words if word in message.lower())
    if code_word_count >= 3:
        suspicious_indicators.append('Multiple code words detected')
    
    # Check for urgency indicators
    urgency_words = ['urgent', 'asap', 'immediately', 'now', 'hurry', 
                     'quick', 'fast', 'rush', 'emergency']
    if any(word in message.lower() for word in urgency_words):
        suspicious_indicators.append('Urgency indicators present')
    
    # Check for secrecy language
    secrecy_words = ['secret', 'confidential', 'dont tell', 'between us',
                     'private', 'discreet', 'careful', 'watch out']
    if any(phrase in message.lower() for phrase in secrecy_words):
        suspicious_indicators.append('Secrecy language detected')
    
    # Check for religious extremism indicators
    extremism_phrases = ['Fire', 'burn', 'genocide', 'ipob', 
                         'sacrifice', 'ritual', 'boko haram']
    extremism_count = sum(1 for phrase in extremism_phrases if phrase in message.lower())
    if extremism_count >= 2:
        suspicious_indicators.append('Religious extremism indicators')
    
    # Check for location references
    location_words = ['forest', 'border', 'camp', 'hideout', 'base',
                     'sambisa', 'highway', 'checkpoint']
    if any(word in message.lower() for word in location_words):
        suspicious_indicators.append('Suspicious location references')
    
    return suspicious_indicators


# 🟢 COPY-PASTE OK - Display functions
def display_threat_analysis(result):
    """Display threat analysis results"""
    print("\n" + "=" * 80)
    print("📱 SMS THREAT ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    # Threat level indicator
    level_indicators = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': '✓'
    }
    
    indicator = level_indicators.get(result['threat_level'], '•')
    
    print(f"Message: \"{result['message'][:100]}{'...' if len(result['message']) > 100 else ''}\"")
    if result['sender']:
        print(f"Sender: {result['sender']}")
    print(f"Timestamp: {result['timestamp']}")
    print()
    
    print(f"Threat Level: {indicator} {result['threat_level']}")
    print(f"Priority: {result['priority']}")
    print(f"Threat Score: {result['threat_score']}/100")
    print(f"Recommended Action: {result['action']}")
    print()
    
    if result['primary_threat'] != 'none':
        print(f"Primary Threat Category: {result['primary_threat'].upper().replace('_', ' ')}")
        print()
    
    # Show matched keywords by category
    if result['matched_keywords']:
        print("Detected Threat Keywords:")
        print("-" * 80)
        for category, keywords in result['matched_keywords'].items():
            print(f"  {category.replace('_', ' ').title()}: {', '.join(keywords)}")
        print()
    
    # Show pattern matches
    if result['pattern_matches']:
        print("Suspicious Patterns Detected:")
        print("-" * 80)
        for pattern in result['pattern_matches']:
            print(f"  • {pattern}")
        print()
    
    # Language pattern analysis
    language_patterns = detect_suspicious_language_patterns(result['message'])
    if language_patterns:
        print("Language Pattern Analysis:")
        print("-" * 80)
        for pattern in language_patterns:
            print(f"  • {pattern}")
        print()
    
    # Recommendations
    print("Security Recommendations:")
    print("-" * 80)
    if result['threat_level'] == 'CRITICAL':
        print("  1. 🚨 ALERT DSS/Police immediately")
        print("  2. Track sender location via telecom")
        print("  3. Analyze sender's call/SMS history")
        print("  4. Deploy surveillance team")
        print("  5. Coordinate with counter-terrorism unit")
    elif result['threat_level'] == 'HIGH':
        print("  1. ⚠️ Flag for detailed investigation")
        print("  2. Monitor sender's communications")
        print("  3. Cross-reference with known threats")
        print("  4. Prepare response team on standby")
    elif result['threat_level'] == 'MEDIUM':
        print("  1. ⚡ Continue passive monitoring")
        print("  2. Add to watch list")
        print("  3. Check for pattern escalation")
    else:
        print("  1. ✓ Routine monitoring sufficient")
        print("  2. Log for pattern analysis")
    
    print()
    print("=" * 80)



def batch_analyze_messages(messages_file):
    """
    Analyze multiple messages from a file
    Used for bulk analysis of intercepted communications
    """
    print("\n📊 BATCH SMS THREAT ANALYSIS")
    print("=" * 80)
    print()
    
    try:
        with open(messages_file, 'r', encoding='utf-8') as f:
            messages = [line.strip() for line in f if line.strip()]
        
        print(f"Analyzing {len(messages)} messages...")
        print()
        
        results = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for i, msg in enumerate(messages, 1):
            result = analyze_sms_threat(msg, sender_number=f"UNKNOWN-{i}")
            results.append(result)
            
            if result['threat_level'] == 'CRITICAL':
                critical_count += 1
            elif result['threat_level'] == 'HIGH':
                high_count += 1
            elif result['threat_level'] == 'MEDIUM':
                medium_count += 1
            else:
                low_count += 1
        
        # Summary
        print("BATCH ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"\nTotal Messages Analyzed: {len(messages)}")
        print(f"  🚨 Critical Threats: {critical_count}")
        print(f"  ⚠️  High Threats: {high_count}")
        print(f"  ⚡ Medium Threats: {medium_count}")
        print(f"  ✓ Low/No Threats: {low_count}")
        print()

        # Show critical and high threats
        priority_threats = [r for r in results if r['threat_level'] in ['CRITICAL', 'HIGH']]
        
        if priority_threats:
            print("PRIORITY THREATS REQUIRING IMMEDIATE ACTION:")
            print("=" * 80)
            for i, threat in enumerate(priority_threats, 1):
                print(f"\n{i}. [{threat['threat_level']}] {threat['message'][:80]}...")
                print(f"   Category: {threat['primary_threat'].replace('_', ' ').title()}")
                print(f"   Score: {threat['threat_score']}")
        
        # Save report
        report_file = 'sms_threat_report.json'
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Detailed report saved to {report_file}")
        print("=" * 80)
        
    except FileNotFoundError:
        print(f"❌ File not found: {messages_file}")


# Sample threat messages for testing
SAMPLE_MESSAGES = [
    "Meeting tomorrow at 3pm for business discussion",  # LOW
    "We have your daughter. Bring 5,000,000 naira to the forest by tomorrow or she dies",  # CRITICAL - Kidnapping
    "Join our cause brother. Billions awaits those who help carry out this mission with us. Training camp in Sambisa",  # CRITICAL - Terrorism
    "The package will be delivered tonight. AK-47 and ammunition ready. Contact dealer at hideout",  # CRITICAL - Weapons
    "Lagos to Ibadan road is clear today. All targets identified for tonight's operation",  # HIGH - Robbery
    "Congratulations! You've won 1 million naira. Click here to claim",  # LOW - Spam
    "Don't forget to buy groceries on your way home",  # LOW - Normal
    "Cattle raid successful. 200 heads secured. Meeting point at border tomorrow",  # HIGH - Banditry
    "Boss will bless our warriors. The attack is scheduled for next market day at the market",  # CRITICAL - Terrorism
    "Your son is safe with us. Pay 3 million ransom to this account by midnight",  # CRITICAL - Kidnapping
]


def main():
    """Main program"""
    print("\n🇳🇬 SMS THREAT DETECTION SYSTEM")
    print("National Security Intelligence Platform")
    print("=" * 80)
    print()
    
    while True:
        print("\nOPERATIONS MENU:")
        print("=" * 80)
        print("1. Analyze Single SMS")
        print("2. Test with Sample Messages")
        print("3. Batch Analyze from File")
        print("4. Real-Time Monitoring Simulation")
        print("5. Exit System")
        
        choice = input("\nSelect operation: ").strip()
        
        if choice == '1':
            # Single message analysis
            print("\n" + "-" * 80)
            message = input("Enter SMS message to analyze: ").strip()
            sender = input("Enter sender number (optional): ").strip() or None
            
            print("\nAnalyzing message...")
            result = analyze_sms_threat(message, sender)
            display_threat_analysis(result)
            
        elif choice == '2':
            # Test with samples
            print("\n📋 TESTING WITH SAMPLE MESSAGES")
            print("=" * 80)
            input("\nPress Enter to begin testing...")
            
            for i, msg in enumerate(SAMPLE_MESSAGES, 1):
                print(f"\n\nTest {i}/{len(SAMPLE_MESSAGES)}")
                result = analyze_sms_threat(msg)
                display_threat_analysis(result)
                
                if i < len(SAMPLE_MESSAGES):
                    input("\nPress Enter for next message...")
            
            print("\n✓ All sample messages analyzed")
            
        elif choice == '3':
            # Batch analysis
            filename = input("\nEnter filename (e.g., intercepted_sms.txt): ").strip()
            batch_analyze_messages(filename)
            
        elif choice == '4':
            # Simulation
            print("\n🔴 REAL-TIME MONITORING SIMULATION")
            print("=" * 80)
            print("Simulating interception of 5 random messages...\n")
            
            import random
            random_messages = random.sample(SAMPLE_MESSAGES, 5)
            
            for i, msg in enumerate(random_messages, 1):
                print(f"\n[INTERCEPTED MESSAGE {i}]")
                result = analyze_sms_threat(msg, f"0{random.randint(7000000000, 9999999999)}")
                
                if result['threat_level'] in ['CRITICAL', 'HIGH']:
                    display_threat_analysis(result)
                else:
                    print(f"Threat Level: {result['threat_level']} - No action required")
                
                if i < 5:
                    print("\nMonitoring...")
                    import time
                    time.sleep(1)
            
            print("\n✓ Monitoring session complete")
            
        elif choice == '5':
            print("\n✓ System shutdown")
            break
        else:
            print("\n⚠️ Invalid choice")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ System interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
