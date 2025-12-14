# Day 1, Session 1: Password Strength Analyzer
# Defense Application: Access control for classified systems

# This is your first Python program!
# Read through the comments carefully - they explain everything
import math
from datetime import datetime

def analyze_password(password):
    """
    Analyze password strength based on military/government standards
    DoD requires: 15+ chars, uppercase, lowercase, numbers, special chars
    """
    
    # Initialize strength score
    score = 0
    feedback = []
    
    # Check length (DoD minimum is 15 characters)
    length = len(password)
    if length >= 15:
        score += 2
        feedback.append("✓ Length meets DoD standard (15+ characters)")
    elif length >= 12:
        score += 1
        feedback.append("⚠ Length is acceptable but not DoD compliant (need 15+)")
    else:
        feedback.append("✗ Too short - DoD requires 15+ characters")
    
    # Check for uppercase letters
    has_upper = any(c.isupper() for c in password)
    if has_upper:
        score += 1
        feedback.append("✓ Contains uppercase letters")
    else:
        feedback.append("✗ Missing uppercase letters")
    
    # Check for lowercase letters
    has_lower = any(c.islower() for c in password)
    if has_lower:
        score += 1
        feedback.append("✓ Contains lowercase letters")
    else:
        feedback.append("✗ Missing lowercase letters")
    
    # Check for numbers
    has_digit = any(c.isdigit() for c in password)
    if has_digit:
        score += 1
        feedback.append("✓ Contains numbers")
    else:
        feedback.append("✗ Missing numbers")
    
    # Check for special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(c in special_chars for c in password)
    if has_special:
        score += 1
        feedback.append("✓ Contains special characters")
    else:
        feedback.append("✗ Missing special characters")
    
    # Check for common weak passwords
    common_weak = ["password", "123456", "admin", "letmein", "welcome"]
    if password.lower() in common_weak:
        score = 0
        feedback.append("✗ CRITICAL: This is a commonly used weak password!")
    
    # Determine strength level
    if score >= 6:
        strength = "STRONG - Suitable for classified systems"
    elif score >= 4:
        strength = "MODERATE - Acceptable for general use"
    else:
        strength = "WEAK - Not acceptable for defense systems"

    # Calculate entropy 
    entropy = calculate_entropy(password)
    
    return score, strength, feedback, entropy 


def calculate_entropy(password):
    """
    calculate password entropy (randomness measure)
    Higher entropy = more secure
    """

    #Determine character set size
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26 # lowercase letters
    if any(c.isupper() for c in password):
        charset_size += 26 # uppercase letters
    if any(c.isdigit() for c in password):
        charset_size += 10 # digits
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        charset_size += 32 # special characters


    # Calculate entropy
    if charset_size > 0:
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    return 0


def log_analysis(password_length, strength, score):
    """
    Log password analysis for security auditing
    Never log actual password - only metadata!
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("password_audit_log.txt", "a") as log_file:
        log_file.write(f"{timestamp} | Length: {password_length} |")
        log_file.write(f" Strength: {strength} | Score:{score}/6\n")

def main():
    """
    Main program - this is where execution starts
    """
    print("=" * 60)
    print("MILITARY-GRADE PASSWORD STRENGTH ANALYZER")
    print("Based on DoD 8500.01 Security Standards")
    print("=" * 60)
    print()
    
    # Get password from user
    password = input("Enter password to analyze: ")
    print()
    
    # Analyze the password
    score, strength, feedback, entropy = analyze_password(password)

    # Log the analysis
    log_analysis(len(password), strength, score)
    
    
    # Display results
    print(f"Password Strength: {strength}")
    print(f"Security Score: {score}/6")
    print(f"Password Entropy: {entropy}bits")
    print("\nDetailed Analysis:")
    print("-" * 60)
    
    for item in feedback:
        print(f"  {item}")
    
    print()
    print("=" * 60)


# This is the entry point of the program
if __name__ == "__main__":
    main()

