import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits. High-entropy strings are a weak signal for
    obfuscated/encoded payloads (base64 blobs, packed JS, etc)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
