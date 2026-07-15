"""
Password Strength Analyzer (Mini Project)
-------------------------------------------
Evaluates the strength of a user-entered password based on length,
complexity, and common-password checks. Suggests stronger alternatives
if the password is weak, and optionally checks against a local history
file to prevent reuse of old passwords.

Usage:
    python password_strength_analyzer.py
"""

import re
import getpass
import hashlib
import os
import random
import string

HISTORY_FILE = "password_history.txt"

# A small sample of extremely common/weak passwords for demo purposes.
# A real tool would check against a much larger breached-password list.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "letmein", "iloveyou",
    "admin", "welcome", "monkey", "dragon",
}


# ---------------------------------------------------------
# 1. Core strength checks
# ---------------------------------------------------------

def check_length(password):
    length = len(password)
    if length >= 16:
        return 3, "Excellent length (16+ characters)"
    elif length >= 12:
        return 2, "Good length (12-15 characters)"
    elif length >= 8:
        return 1, "Minimum acceptable length (8-11 characters)"
    else:
        return 0, "Too short (under 8 characters)"


def check_complexity(password):
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])

    missing = []
    if not has_lower:
        missing.append("lowercase letter")
    if not has_upper:
        missing.append("uppercase letter")
    if not has_digit:
        missing.append("number")
    if not has_symbol:
        missing.append("special character")

    return variety_count, missing


def check_common_patterns(password):
    """Flag common weak patterns: dictionary words, sequences, repeats."""
    issues = []
    lower_pw = password.lower()

    if lower_pw in COMMON_PASSWORDS:
        issues.append("This is one of the most commonly used passwords")

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated characters (e.g. 'aaa')")

    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i + 3] in lower_pw:
                issues.append("Contains a keyboard/number sequence (e.g. 'abc', '123')")
                break

    if re.search(r"(19|20)\d{2}", password):
        issues.append("Contains a year (avoid birth years, etc.)")

    return issues


def check_uniqueness_against_history(password):
    """Compare (hashed) password against a local history file."""
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    if not os.path.exists(HISTORY_FILE):
        return True, []

    with open(HISTORY_FILE, "r") as f:
        past_hashes = [line.strip() for line in f.readlines()]

    if pw_hash in past_hashes:
        return False, past_hashes
    return True, past_hashes


def save_to_history(password, past_hashes):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    past_hashes.append(pw_hash)
    with open(HISTORY_FILE, "w") as f:
        f.write("\n".join(past_hashes[-10:]))  # keep last 10


# ---------------------------------------------------------
# 2. Scoring
# ---------------------------------------------------------

def calculate_score(password):
    length_score, length_msg = check_length(password)
    complexity_score, missing = check_complexity(password)
    pattern_issues = check_common_patterns(password)
    is_unique, past_hashes = check_uniqueness_against_history(password)

    total_score = length_score + complexity_score
    total_score -= len(pattern_issues)
    if not is_unique:
        total_score -= 3

    total_score = max(0, total_score)

    if total_score >= 6:
        rating = "STRONG"
    elif total_score >= 4:
        rating = "MODERATE"
    else:
        rating = "WEAK"

    return {
        "rating": rating,
        "score": total_score,
        "length_msg": length_msg,
        "missing_char_types": missing,
        "pattern_issues": pattern_issues,
        "is_unique": is_unique,
        "past_hashes": past_hashes,
    }


# ---------------------------------------------------------
# 3. Suggest a stronger password
# ---------------------------------------------------------

def suggest_strong_password(length=14):
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*"
    while True:
        candidate = "".join(random.choice(chars) for _ in range(length))
        if (re.search(r"[a-z]", candidate) and re.search(r"[A-Z]", candidate)
                and re.search(r"\d", candidate) and re.search(r"[^a-zA-Z0-9]", candidate)):
            return candidate


# ---------------------------------------------------------
# 4. Report
# ---------------------------------------------------------

def print_report(result):
    print("\n" + "=" * 55)
    print("PASSWORD STRENGTH REPORT")
    print("=" * 55)
    print(f"Rating       : {result['rating']}")
    print(f"Score        : {result['score']} / 7")
    print(f"Length Check : {result['length_msg']}")

    if result["missing_char_types"]:
        print(f"Missing      : {', '.join(result['missing_char_types'])}")
    else:
        print("Missing      : None (has all character types)")

    if result["pattern_issues"]:
        print("Pattern Issues:")
        for issue in result["pattern_issues"]:
            print(f"  - {issue}")
    else:
        print("Pattern Issues: None found")

    if not result["is_unique"]:
        print("Reuse Check  : This password matches one you've used before!")
    else:
        print("Reuse Check  : Not found in your recent password history")

    if result["rating"] != "STRONG":
        print("\nSuggested stronger alternative:")
        print(f"  {suggest_strong_password()}")

    print("=" * 55)


# ---------------------------------------------------------
# 5. Main
# ---------------------------------------------------------

def main():
    print("Password Strength Analyzer")
    print("(Input is hidden while typing)\n")

    password = getpass.getpass("Enter a password to evaluate: ")

    if not password:
        print("No password entered. Exiting.")
        return

    result = calculate_score(password)
    print_report(result)

    save_choice = input("\nSave this password to history to prevent future reuse? (y/n): ")
    if save_choice.strip().lower() == "y":
        save_to_history(password, result["past_hashes"])
        print(f"[*] Saved (hashed) to {HISTORY_FILE}")


if __name__ == "__main__":
    main()