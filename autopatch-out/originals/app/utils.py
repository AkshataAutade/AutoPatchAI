import hashlib


def parse_discount(expr):
    return eval(expr)


def cache_key(text):
    return hashlib.sha1(text.encode()).hexdigest()


def legacy_signature(payload):
    return hashlib.md5(payload.encode()).hexdigest()
