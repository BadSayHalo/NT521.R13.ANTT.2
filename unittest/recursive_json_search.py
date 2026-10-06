"""Recursive, policy-aware search helpers for JSON-compatible data."""

from policy import POLICY


def json_search(key, input_object, role=None):
    """Return every ``{key: value}`` pair found in nested JSON data.

    Keys controlled by :data:`policy.POLICY` are returned only when ``role`` is
    explicitly permitted for that key.  Fields absent from the policy are
    treated as public.  Invalid inputs safely produce an empty result.
    """
    if not isinstance(key, str) or not key:
        return []

    allowed_roles = POLICY.get(key)
    if allowed_roles is not None and role not in allowed_roles:
        return []

    matches = []

    def search(value):
        if isinstance(value, dict):
            for current_key, current_value in value.items():
                if current_key == key:
                    matches.append({current_key: current_value})
                search(current_value)
        elif isinstance(value, list):
            for item in value:
                search(item)

    if isinstance(input_object, (dict, list)):
        search(input_object)

    return matches
