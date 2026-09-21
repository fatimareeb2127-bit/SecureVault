import secrets
import string
import re


def generate_password(
    length=20,
    use_symbols=True,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    exclude_ambiguous=False
):

    length = max(8, min(128, int(length)))

    groups = []

    if use_lowercase:
        groups.append(string.ascii_lowercase)

    if use_uppercase:
        groups.append(string.ascii_uppercase)

    if use_digits:
        groups.append(string.digits)

    if use_symbols:
        groups.append(
            "!@#$%^&*()_+=[]{}:,.?"
        )

    if not groups:
        raise ValueError("Select at least one character type.")

    if exclude_ambiguous:
        ambiguous = set("Il1O0o")
        groups = [
            "".join(
                character
                for character in group
                if character not in ambiguous
            )
            for group in groups
        ]
        groups = [group for group in groups if group]

    if not groups:
        raise ValueError("The selected options leave no usable characters.")

    password = []

    for group in groups:
        password.append(
            secrets.choice(group)
        )

    all_characters = "".join(groups)

    while len(password) < length:
        password.append(
            secrets.choice(all_characters)
        )

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def analyze_password(password):

    score = 0
    recommendations = []

    if len(password) >= 12:
        score += 2

    elif len(password) >= 8:
        score += 1

    else:
        recommendations.append(
            "Use at least 12 characters."
        )

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        recommendations.append(
            "Add uppercase letters."
        )

    if re.search(r"[a-z]", password):
        score += 1
    else:
        recommendations.append(
            "Add lowercase letters."
        )

    if re.search(r"[0-9]", password):
        score += 1
    else:
        recommendations.append(
            "Add numbers."
        )

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        recommendations.append(
            "Add symbols."
        )

    common = {
        "password",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "welcome",
        "letmein"
    }

    if password.lower() in common:
        score = 0

        recommendations.append(
            "This is a common password."
        )

    if re.search(r"(.)\1\1", password):
        score -= 1

        recommendations.append(
            "Avoid repeated characters."
        )

    score = max(0, score)

    if score <= 2:
        label = "WEAK"

    elif score <= 4:
        label = "MEDIUM"

    elif score == 5:
        label = "STRONG"

    else:
        label = "VERY STRONG"

    return score, label, recommendations