import json

from flask import request


def compute():
    """Evaluate the formula supplied in the request body."""
    payload = json.loads(request.data)
    expression = payload["formula"]
    return eval(expression)
