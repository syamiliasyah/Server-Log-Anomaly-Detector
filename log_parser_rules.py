import re

# Regex patterns for threat detection
FAILED_LOGIN_PATTERN = r"Failed password for.*from (\d+\.\d+\.\d+\.\d+)"
WEB_FUZZ_PATTERN = r"GET (/\.env|/admin|/config\.php|/wp-login\.php)"

def match_pattern(pattern, log_line):
    """Utility function to extract matched regex group."""
    match = re.search(pattern, log_line)
    if match:
        return match.group(1)
    return None
