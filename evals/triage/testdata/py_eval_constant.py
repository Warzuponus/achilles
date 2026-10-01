DEFAULT_LIMIT_EXPR = "24 * 60"


def default_limit():
    """Return the built-in default limit, in minutes."""
    return eval(DEFAULT_LIMIT_EXPR)
