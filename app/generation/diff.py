import difflib


def unified_diff(current: dict, proposed: dict) -> str:
    """A pull-request style diff between two sets of generated files."""
    chunks = []
    for path in sorted(set(current) | set(proposed)):
        before = current.get(path, "").splitlines(keepends=True)
        after = proposed.get(path, "").splitlines(keepends=True)
        if before != after:
            chunks.extend(
                difflib.unified_diff(
                    before, after, fromfile=f"current/{path}", tofile=f"proposed/{path}"
                )
            )
    return "".join(chunks)