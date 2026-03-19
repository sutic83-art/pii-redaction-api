import re
from typing import List, Optional

from app.validators import (
    validate_card_number,
    validate_email,
    validate_iban,
    validate_jmbg,
    validate_mb_company,
    validate_pib,
    validate_phone,
)


PRIORITY = {
    "EMAIL": 100,
    "IBAN": 95,
    "JMBG": 90,
    "PIB": 85,
    "MB_COMPANY": 80,
    "CARD_NUMBER": 70,
    "PHONE": 60,
}

DEFAULT_ENTITIES = [
    "JMBG",
    "PIB",
    "MB_COMPANY",
    "EMAIL",
    "PHONE",
    "IBAN",
    "CARD_NUMBER",
]


def _match_dict(entity_type: str, start: int, end: int, text: str, score: float = 0.95) -> dict:
    return {
        "entity_type": entity_type,
        "start": start,
        "end": end,
        "score": score,
        "text": text,
    }


def _detect_regex(
    text: str,
    entity_type: str,
    pattern: str,
    validator,
    flags: int = 0,
) -> List[dict]:
    results: List[dict] = []

    for match in re.finditer(pattern, text, flags):
        value = match.group(0)

        if validator and not validator(value):
            continue

        results.append(
            _match_dict(
                entity_type=entity_type,
                start=match.start(),
                end=match.end(),
                text=value,
            )
        )

    return results


def _detect_mb_company(text: str) -> List[dict]:
    pattern = re.compile(
        r"(?i)\b(?:matični|maticni)\s+broj\s*[:\-]?\s*(?P<mb1>\d{8})\b|\bMB\s*[:\-]?\s*(?P<mb2>\d{8})\b"
    )

    results: List[dict] = []

    for match in pattern.finditer(text):
        group_name = "mb1" if match.group("mb1") else "mb2"
        value = match.group(group_name)

        if not validate_mb_company(value):
            continue

        start, end = match.span(group_name)
        results.append(
            _match_dict(
                entity_type="MB_COMPANY",
                start=start,
                end=end,
                text=value,
            )
        )

    return results


def _overlaps(a: dict, b: dict) -> bool:
    return not (a["end"] <= b["start"] or a["start"] >= b["end"])


def _resolve_overlaps(matches: List[dict]) -> List[dict]:
    chosen: List[dict] = []

    ordered = sorted(
        matches,
        key=lambda item: (
            -PRIORITY.get(item["entity_type"], 0),
            -(item["end"] - item["start"]),
            item["start"],
        ),
    )

    for candidate in ordered:
        if any(_overlaps(candidate, existing) for existing in chosen):
            continue
        chosen.append(candidate)

    return sorted(chosen, key=lambda item: item["start"])


def find_entities(text: str, entities: Optional[List[str]] = None) -> List[dict]:
    selected = set(entities or DEFAULT_ENTITIES)
    results: List[dict] = []

    if "JMBG" in selected:
        results.extend(_detect_regex(text, "JMBG", r"\b\d{13}\b", validate_jmbg))

    if "PIB" in selected:
        results.extend(_detect_regex(text, "PIB", r"\b\d{9}\b", validate_pib))

    if "MB_COMPANY" in selected:
        results.extend(_detect_mb_company(text))

    if "EMAIL" in selected:
        results.extend(
            _detect_regex(
                text,
                "EMAIL",
                r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b",
                validate_email,
                flags=re.IGNORECASE,
            )
        )

    if "PHONE" in selected:
        results.extend(
            _detect_regex(
                text,
                "PHONE",
                r"(?<!\w)(?:\+381|381|0)(?:[\s()/.\-]?\d){8,11}(?!\w)",
                validate_phone,
            )
        )

    if "IBAN" in selected:
        results.extend(
            _detect_regex(
                text,
                "IBAN",
                r"(?<![A-Z0-9])(?:[A-Z]{2}\d{2}(?:[\s\-]?[A-Z0-9]){11,30})(?![A-Z0-9])",
                validate_iban,
                flags=re.IGNORECASE,
            )
        )

    if "CARD_NUMBER" in selected:
        results.extend(
            _detect_regex(
                text,
                "CARD_NUMBER",
                r"(?<!\d)\d(?:[ \-]?\d){12,18}(?!\d)",
                validate_card_number,
            )
        )

    return _resolve_overlaps(results)