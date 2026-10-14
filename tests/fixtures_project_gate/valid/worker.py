"""Synthetic normalization fixture; no third-party code."""


def normalize(value):
    if not isinstance(value, str):
        raise TypeError('value must be text')
    return value.strip().upper()
