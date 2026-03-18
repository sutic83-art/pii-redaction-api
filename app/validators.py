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
