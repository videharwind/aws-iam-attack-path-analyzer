import re

def matches_pattern(value,pattern,case_sensitive = True):
    regex = re.escape(pattern).replace(r"\*",".*").replace(r"\?",".")
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.fullmatch(regex,value,flags) is not None

def action_matches(value,pattern):
    return matches_pattern(value,pattern,case_sensitive=False)

def resource_matches(value,pattern):
    return matches_pattern(value,pattern,case_sensitive=True)


