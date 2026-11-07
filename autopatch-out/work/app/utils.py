import hashlib
import ast


def parse_discount(expr):
    return ast.literal_eval(expr)


def cache_key(text):
    return hashlib.sha256(text.encode()).hexdigest()


def legacy_signature(payload):
    return hashlib.md5(payload.encode()).hexdigest()
