"""Request → classifier state, text strings, unsupported flags, session seed."""

from __future__ import annotations

import re
import unicodedata

# Zero-width characters and bidi controls are removed after NFKC.
_INVISIBLE = re.compile("[​-‍⁠﻿‪-‮⁦-⁩]")


def normalize(s: str) -> str:
    """NFKC, then strip zero-width and bidi control characters."""
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", s))
