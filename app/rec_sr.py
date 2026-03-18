import re
from typing import Callable, Dict, List, Optional

from app.validators import validate_jmbg, validate_pib


PATTERNS: Dict[str, str] = {
    "JMBG": r"\b\d{13}\b",
    "PIB": r"\b\d{9}\b",
}

VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "JMBG": validate_jmbg,
    "PIB": validate_pib,
}


def find_entities(text: str, entities: Optional[List[str]] = None) -> List[dict]:
    selected = entities or ["JMBG", "PIB"]
    matches: List[dict] = []

    for entity in selected:
        pattern = PATTERNS.get(entity)
        if not pattern:
            continue

        validator = VALIDATORS.get(entity)

        for match in re.finditer(pattern, text):
            value = match.group(0)

            if validator and not validator(value):
                continue

            matches.append(
                {
                    "entity_type": entity,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 0.95,
                    "text": value,
                }
            )

    matches.sort(key=lambda item: item["start"])
    return matches
