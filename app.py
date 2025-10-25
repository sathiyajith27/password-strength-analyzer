from flask import Flask, render_template, request, jsonify
import re
import math
import requests
import hashlib

app = Flask(__name__)

# -------------------------------
# Password Entropy Calculation
# -------------------------------
def calculate_entropy(password):
    """Estimate entropy bits based on character variety."""
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[@$!%*?&]", password):
        charset += 10
    if charset == 0:
        return 0
    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)


# -------------------------------
# Crack Time Estimation
# -------------------------------
def estimate_crack_time(entropy):
    """Estimate crack time based on entropy."""
    guesses_per_second = 1e10  # 10 billion guesses/sec
    total_guesses = 2 ** entropy
    seconds = total_guesses / guesses_per_second

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return "Few seconds"
    elif seconds < 3600:
        return "Within an hour"
    elif seconds < 86400:
        return "Within a day"
    elif seconds < 604800:
        return "Within a week"
    elif seconds < 31536000:
        return "Months"
    else:
        return "Years or more"


# -------------------------------
# Check password leak (HIBP API)
# -------------------------------
def check_pwned_password(password):
    """Check password using Have I Been Pwned API."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, headers={"User-Agent": "PasswordStrengthAnalyzer"})
        if response.status_code != 200:
            return {"pwned": False, "count": 0}

        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return {"pwned": True, "count": int(count)}

    except Exception as e:
        print("Error checking password leak:", e)
        return {"pwned": False, "count": 0}

    return {"pwned": False, "count": 0}


# -------------------------------
# AI-style feedback
# -------------------------------
def ai_feedback(strength, entropy, crack_time):
    """Generate AI-style feedback."""
    if strength == "Weak":
        return f"⚠️ Weak password. It could be cracked {crack_time.lower()} (entropy: {entropy} bits). Try mixing uppercase, digits, and symbols."
    elif strength == "Medium":
        return f"🧠 Decent password ({entropy} bits entropy). Might last {crack_time.lower()}, but can be improved with more unique characters."
    else:
        return f"🛡️ Strong password! ({entropy} bits entropy). Estimated to resist cracking attempts for {crack_time.lower()}."


# -------------------------------
# Password Analyzer
# -------------------------------
def analyze_password(password):
    score = 0
    remarks = []

    if len(password) >= 8:
        score += 1
    else:
        remarks.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        remarks.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        remarks.append("Add lowercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        remarks.append("Add numbers")

    if re.search(r"[@$!%*?&]", password):
        score += 1
    else:
        remarks.append("Add special characters")

    # Determine base strength
    if score <= 2:
        strength = "Weak"
    elif score in [3, 4]:
        strength = "Medium"
    else:
        strength = "Strong"

    # Add extra analysis
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    ai_msg = ai_feedback(strength, entropy, crack_time)

    # 🔒 Check if leaked
    pwned_info = check_pwned_password(password)
    if pwned_info["pwned"]:
        remarks.append(f"⚠️ This password appeared {pwned_info['count']} times in known data breaches. Avoid using it!")
        strength = "Weak"  # Override to weak if leaked

    return {
        "strength": strength,
        "remarks": remarks,
        "entropy": entropy,
        "crack_time": crack_time,
        "ai_msg": ai_msg,
        "pwned": pwned_info["pwned"],
        "pwned_count": pwned_info["count"]
    }


# -------------------------------
# Flask Routes
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    password = data.get("password", "")
    result = analyze_password(password)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
