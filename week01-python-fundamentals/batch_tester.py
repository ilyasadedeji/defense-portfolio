# Challenge 2: Batch Password Tester
# Purpose: Analyze many passwords and produce a security report
import math 
from collections import Counter


def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26

    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()_+-=" for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def analyze_password(password):
    """
    Log password analysis for security auditing
    """
    weaknesses = []
    score = 0
    if len(password) >= 15:
       score += 2
    else:
        weaknesses.append("Too short") 
    if any(c.islower() for c in password):
        score += 1
    else: 
        weaknesses.append("No lowercase letters") 
    if any(c.isupper() for c in password):
        score += 1
    else: 
        weaknesses.append("No uppercase letters")  

    if any(c.isdigit() for c in password):
        score += 1
    else:
        weaknesses.append("No numbers")
    if any(c in "!@#$%^&*()_+-=" for c in password):
        score += 1
    else: 
        weaknesses.append("No special characters")

    if score >= 6:
        strength = "STRONG"
    elif score >= 4:
        strength = "MODERATE"
    else: 
        strength = "WEAK"
    entropy = calculate_entropy(password)
    return strength, weaknesses, entropy

def process_file(filename):
    results = []
    weakness_counter = Counter()
    with open(filename, "r") as file:
        for line in file:
            password = line.strip()
            if not password: 
                continue
            strength, weaknesses, entropy = analyze_password(password)
            results.append(strength)
            for w in weaknesses:
                weakness_counter[w] += 1
    return results, weakness_counter
    
def generate_report(results, weakness_counter):
    total = len(results)
    strong = results.count("STRONG")
    moderate = results.count("MODERATE")
    weak = results.count("WEAK")
    print("\nBATCH PASSWORD SECURITY REPORT")
    print("=" * 50)
    print(f"Total passwords analyzed: {total}")
    print(f"Strong passwords: {strong}")
    print(f"Moderate passwords: {moderate}")
    print(f"Weak passwords: {weak}")
    print("\nCommon Weaknesses Found:")
    for weakness, count in weakness_counter.most_common():
        print(f"- {weakness}: {count}")
    print("\nRecommendations:")
    if weak > 0:
        print("- Enforce minimum 15 character length")
        print("- Require all character types")
        print("- Educate users on password best practices")
def main():
    filename = input("Enter password file name: ")
    results, weakness_counter = process_file(filename)
    generate_report(results, weakness_counter)

if __name__ == "__main__":
        main()