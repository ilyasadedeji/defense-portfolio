"""
Banking Security Validator - Day 2, Session 3
Defense Application: Financial fraud detection and validation
Use Case: Protecting Nigerian banking systems from fraud
"""

import re 
import random 
from datetime import datetime, timedelta 

def validate_bvn(bvn):
    """
    Validate Bank Verification Number (BVN) format
    BVN is 11 digits
    """
    # Remove spaces and dashes
    bvn = re.sub(r'[\s-]', '', str(bvn))

    #Check if 11 digits
    if not re.match(r'^\d{11}$', bvn):
        return False, "BVN must be exactly 11 digits"
    #BVN cannot start with 0
    if bvn [0] == '0':
        return False, "Invalid BVN format (cannot start with 0)"
    
    return True, "Valid BVN format"


def validate_nigerian_account(account_number, bank_code):
    """
    Validate Nigerian bank account number
    10 digits standard (NUBAN format)
    """

    account = re.sub(r'[\s-]', '', str(account_number))

    if not re.match(r'^\d{10}$', account):
        return False, "Account number must be 10 digits (NUBAN format)"
        

    # List of valid Nigerian bank codes
    valid_banks = {
        '044': 'Access Bank',
        '063': 'Diamond Bank',
        '050': 'Ecobank',
        '070': 'Fidelity Bank',
        '011': 'First Bank',
        '058': 'GTBank',
        '030': 'Heritage Bank',
        '301': 'Jaiz Bank',
        '082': 'Keystone Bank',
        '526': 'Parallex Bank',
        '076': 'Polaris Bank',
        '101': 'Providus Bank',
        '221': 'Stanbic IBTC',
        '068': 'Standard Chartered',
        '232': 'Sterling Bank',
        '032': 'Union Bank',
        '033': 'UBA',
        '215': 'Unity Bank',
        '035': 'Wema Bank',
        '057': 'Zenith Bank'
    }

    if bank_code not in valid_banks: 
        return False, f"Invalid bank code: {bank_code}"
    
    return True,  f"Valid account for {valid_banks[bank_code]}"



def validate_nigerian_phone(phone):
    """
    Validate Nigerian phone number
    Format: 11 digits
    Valid prefixes: 070, 080, 081, 090, 091
    """

    phone = re.sub(r'[\s-]', '', str(phone))

    if not re.match(r'^\d{11}$', phone):
        return False, "Phone number must be exactly 11 digits"

    valid_prefixes = ('070', '080', '081', '090', '091')

    if not phone.startswith(valid_prefixes):
        return False, "Invalid Nigerian phone number prefix"

    return True, "Valid Nigerian phone number"



def detect_unusual_transaction(transactions):
    """
    Detect unusual transaction patterns
    Red flags: Multiple large transactions, unusual times, rapid succession
    """
    alerts = []

    if len(transactions) > 5:
        alerts.append("⚠ High transaction frequency detected")

    # Check for large amounts
    large_transactions = [t for t in transactions if t['amount'] > 500000]
    if len(large_transactions) > 2:
        alerts.append(f"⚠ {len(large_transactions)} large transactions (>₦500,000)")

    # Check for rapid succession (within 5 minutes)
    if len(transactions) >= 2:
        time_diffs = []
        for i in range(len(transactions) - 1):
            diff = abs((transactions[i]['time'] - transactions[i+1]['time']).seconds / 60)
            time_diffs.append(diff)

        if any(diff <5 for diff in time_diffs):
            alerts.append("⚠ Multiple transactions within 5 minutes")


    
    # Check for night transactions (11 PM - 5 AM)
    night_transactions = [
        t for t in transactions
        if t['time'].hour >= 23 or t['time'].hour <= 5
    ]
    if len(night_transactions) >= 2:
        alerts.append(f"⚠ {len(night_transactions)} late-night transactions")

    return alerts


def fraund_risk_score(bvn_valid, account_valid, transaction_alerts):
    """
    Calculate overall fraud risk score
    """ 
    score = 0

    if not bvn_valid:
        score += 40
    if not account_valid:
        score += 30
    
    for alert in transaction_alerts:
        if "large transactions" in alert:
            score += 25
        elif "High transaction frequency" in alert:
            score += 20
        elif "late-night" in alert:
            score += 15
        elif "within 5 minutes" in alert:
            score += 20
    
    score += len(transaction_alerts) * 10

    if score >= 70:
        return score, "HIGH RISK 🚨"
    elif score >= 40:
        return score, "MEDIUM RISK ⚠️"
    
    else: 
        return score, "LOW RISK ✓"


def main():
    """
    Banking Security Validation System
    """
    print("=" * 70)
    print("NIGERIAN BANKING SECURITY VALIDATOR")
    print("Fraud Detection & Validation System")
    print("=" * 70)
    print()

    # Get BVN
    bvn = input("Enter BVN (11 digits): ").strip()
    bvn_valid, bvn_msg = validate_bvn(bvn)
    print(f"BVN Validation: {bvn_msg}")

    # Get Account Details
    account = input("\nEnter Account Number (10 digits): ").strip()
    print("\nSelect Bank:")
    print("044 - Access Bank")
    print("011 - First Bank")
    print("058 - GTBank")
    print("057 - Zenith Bank")
    print("033 - UBA")
    bank_code = input("Enter bank code: ").strip()

    account_valid, account_msg = validate_nigerian_account(account, bank_code)
    print(f"Account Validation: {account_msg}")

    #Get Phone Number
    phone = input("\nEnter phone number: ").strip()
    phone_valid, phone_msg = validate_nigerian_phone(phone)
    print(f"Phone Validation: {phone_msg}")


    # Simulate transaction history
    print("\n" + "=" * 70)
    print("TRANSACTION PATTERN ANALYSIS")
    print("=" * 70)

    num_transactions = int(input("\nHow many recent transactions to analyze? (1-10): "))

    if num_transactions < 1 or num_transactions > 10:
        raise ValueError("Transaction count must be between 1 and 10")

    transactions = []

    print("\Enter transaction details:")
    for i in range(num_transactions):
        print(f"\nTransaction {i+1}:")
        amount = float(input("Amount (₦): "))
        hours_ago =int(input("Hours ago: "))
        
        transaction_time = datetime.now() - timedelta(hours=hours_ago)
        transactions.append({
            'amount': amount,
            'time': transaction_time
        })

    # Analyze transactions
    alerts = detect_unusual_transaction(transactions)

    # Calculate risk score
    risk_score, risk_level = fraund_risk_score(bvn_valid, account_valid, alerts)

    # Display results
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS RESULTS")
    print("=" * 70)

    print(f"\nFraund Risk Score: {risk_score}/100")
    print(f"Risk Level: {risk_level}")

    if alerts:
        print(f"\n⚠️  Security Alerts ({len(alerts)}):")
        for alert in alerts:
            print(f"  {alert}")

    
    # Recommendations
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS") 
    print("=" * 70)

    if risk_score >= 70:
        print("  🚨 IMMEDIATE ACTION REQUIRED:")
        print("  • Block account temporarily")
        print("  • Contact account holder for verification")
        print("  • Review all recent transactions")
        print("  • Report to bank's fraud department")
    elif risk_score >= 40:
        print("  ⚠️  ENHANCED MONITORING:")
        print("  • Flag account for review")
        print("  • Require additional verification for large transactions")
        print("  • Monitor for 48 hours")
    else:
        print(" ✓ Standard security protocols sufficient")

    print("\n" + "=" * 70)



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except ValueError:
        print("\n\nError: Invalid input. Please enter numbers where required.")