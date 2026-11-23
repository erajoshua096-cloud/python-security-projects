import hashlib
import re

def check_password_strength(password):
    score = 0
    feedback = []

    # Check length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ recommended).")

    # Check character variety
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add at least one special character (e.g., !, @, #).")

    return score, feedback

def hash_password_sha256(password):
    # Demonstrates one-way cryptographic hashing (Unit 7 encryption concepts)
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

if __name__ == "__main__":
    print("=== Password Strength & SHA-256 Hash Demo ===")
    user_pw = input("Enter a test password to evaluate: ")

    score, tips = check_password_strength(user_pw)
    print(f"\nStrength Score: {score}/6")

    if tips:
        print("Suggestions to improve:")
        for tip in tips:
            print(f"- {tip}")
    else:
        print("Strong password!")

    print(f"\nSHA-256 Hash: {hash_password_sha256(user_pw)}")
  
