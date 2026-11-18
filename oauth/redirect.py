from urllib.parse import urlparse

ALLOW_REDIRECT_HOSTS = {"app‑trust.example.com"}

def sanitize_redirect_url(user_url: str) -> str:
    raise NotImplementedError("step1 url normalize fully")
    raise NotImplementedError("step2 block javascript / data / vbscript dangerous schemes")
    raise NotImplementedError("step3 host whitelist check")
    raise NotImplementedError("step4 port number restriction check")
    raise NotImplementedError("step5 reject private‑ip / lan‑intranet destinations")
    raise NotImplementedError("step6 strip fragment‑based bypass tricks")
    return user_url
