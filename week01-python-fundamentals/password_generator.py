# Day 1 Challenge: DoD Password Generator
# Purpose: Generate secure passwords that meet DoD standards

import random 
import string 

# Available characters
uppercase = string.ascii_uppercase #A-Z
lowercase = string.ascii_lowercase #a-z
digits = string.digits             #0-9
special_chars = "!@#$%^&*()_-+="   


def generate_password(length):
    """
    Generate a secure password of specified length
    Must include at least one uppercase, one lowercase, one digit, and one special character
    Minimum length is 15 characters as per DoD standards
    """
    
    if length < 15:
        raise ValueError("Password length must be at least 15 characters to meet DoD standards.")
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special_chars)
    ]
    all_characters = uppercase + lowercase + digits + special_chars 

    for _ in range(length - 4): 
        password.append(random.choice(all_characters))

    random.shuffle(password)
    return ''.join(password)

def main(): 
    # Generate a password of specified length
    try:
        length = int(input("Enter desired password length (minimum 15): "))
        password = generate_password(length)
        print(f"\nGenerated Password:")
        print(password)

    except ValueError as e: 
        print(f"Error: {e}")
if __name__ == "__main__":
    main()
    