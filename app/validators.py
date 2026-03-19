import re


EMAIL_RE = re.compile(r"(?i)^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$")


def validate_jmbg(value: str) -> bool:
    if len(value) != 13 or not value.isdigit():
        return False

    digits = [int(ch) for ch in value]
    m = 11 - (
        (
            7 * (digits[0] + digits[6])
            + 6 * (digits[1] + digits[7])
            + 5 * (digits[2] + digits[8])
            + 4 * (digits[3] + digits[9])
            + 3 * (digits[4] + digits[10])
            + 2 * (digits[5] + digits[11])
        )
        % 11
    )

    if m > 9:
        m = 0

    return digits[12] == m


def validate_pib(value: str) -> bool:
    if len(value) != 9 or not value.isdigit():
        return False

    a = 10
    for digit in value[:8]:
        a = (a + int(digit)) % 10
        if a == 0:
            a = 10
        a = (a * 2) % 11

    control = (11 - a) % 10
    return int(value[8]) == control


def validate_mb_company(value: str) -> bool:
    return len(value) == 8 and value.isdigit()


def validate_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch(value.strip()))


def validate_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)

    if digits.startswith("381"):
        national = digits[3:]
    elif digits.startswith("0"):
        national = digits[1:]
    else:
        return False

    return 8 <= len(national) <= 10


def normalize_iban(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value).upper()


def validate_iban(value: str) -> bool:
    iban = normalize_iban(value)

    if len(iban) < 15 or len(iban) > 34:
        return False

    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", iban):
        return False

    rearranged = iban[4:] + iban[:4]

    remainder = 0
    for ch in rearranged:
        converted = ch if ch.isdigit() else str(ord(ch) - 55)
        for digit in converted:
            remainder = (remainder * 10 + int(digit)) % 97

    return remainder == 1


def validate_card_number(value: str) -> bool:
    digits = re.sub(r"\D", "", value)

    if len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, ch in enumerate(reverse_digits):
        number = int(ch)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number

    return total % 10 == 0