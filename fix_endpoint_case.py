import re

STRING_PAT = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"')

def _mask_strings(s: str):
    masks = []
    def repl(m):
        masks.append(m.group(0))
        return f"__STR{len(masks)-1}__"
    return STRING_PAT.sub(repl, s), masks

def _unmask_strings(s: str, masks):
    for i, val in enumerate(masks):
        s = s.replace(f"__STR{i}__", val)
    return s

def fix_endpoint_case(query_text: str, endpoint: str) -> str:
    """
    Ensure the first top-level selected field matches the exact case in `endpoint`.
    Handles optional alias: `{ alias: name(args) { ... } }`
    Does not touch strings.
    """
    if not endpoint:
        return query_text

    s, masks = _mask_strings(query_text)

    # Find the first top-level '{'
    brace_idx = s.find('{')
    if brace_idx == -1:
        return _unmask_strings(s, masks)

    # From just after the first '{', match optional alias then the field name token
    # Groups:
    #   1) any whitespace after '{'
    #   2) optional alias "<alias>:" (non-capturing of colon via group 3)
    #   3) the actual field name token we want to replace
    pattern = re.compile(
        r'(\{\s*)(?:([A-Za-z_]\w*)\s*:\s*)?([A-Za-z_]\w+)',
        flags=re.M
    )

    def repl(m):
        prefix = m.group(1)            # "{   "
        alias = m.group(2)             # optional alias
        _old  = m.group(3)             # old field name (any case)
        # Rebuild with exact endpoint case
        if alias:
            return f"{prefix}{alias}: {endpoint}"
        else:
            return f"{prefix}{endpoint}"

    # Only replace ONCE — the first field after the first '{'
    s = pattern.sub(repl, s, count=1)

    return _unmask_strings(s, masks)