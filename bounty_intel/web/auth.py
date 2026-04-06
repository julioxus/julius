"""Google OAuth2 authentication middleware.

Flow:
1. Visit any page → no session cookie → redirect to /login
2. /login shows "Sign in with Google" button → redirects to Google OAuth
3. Google authenticates → callback to /auth/callback
4. Server verifies token, checks email == allowed_email
5. Creates signed session cookie (30 days)
6. Redirects to original page
"""

from __future__ import annotations

from string import Template

from authlib.integrations.starlette_client import OAuth
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

from bounty_intel.config import settings

SESSION_COOKIE = "bounty_session"
SESSION_MAX_AGE = 86400 * 30  # 30 days

PUBLIC_PATHS = {"/health", "/login", "/auth/callback", "/auth/google"}
API_PREFIX = "/api/"  # API routes use their own auth (X-API-Key)

oauth = OAuth()


def setup_oauth():
    """Register Google OAuth provider. Called once at app startup."""
    if settings.google_client_id:
        oauth.register(
            name="google",
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )


def _get_serializer() -> URLSafeTimedSerializer:
    if not settings.session_secret:
        raise RuntimeError("SESSION_SECRET must be set in environment")
    return URLSafeTimedSerializer(settings.session_secret)


def create_session_cookie(email: str) -> str:
    return _get_serializer().dumps({"email": email})


def verify_session_cookie(cookie_value: str) -> str | None:
    try:
        data = _get_serializer().loads(cookie_value, max_age=SESSION_MAX_AGE)
        return data.get("email")
    except (BadSignature, Exception):
        return None


class SessionAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS or request.url.path.startswith("/static") or request.url.path.startswith(API_PREFIX):
            return await call_next(request)

        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            email = verify_session_cookie(cookie)
            if email and email.lower() == settings.allowed_email.lower():
                request.state.user_email = email
                return await call_next(request)

        return RedirectResponse(f"/login?next={request.url.path}", status_code=302)


_LOGIN_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - Bounty Intel</title>
<style>
  :root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e1e4ed; --muted: #8b8fa3; --accent: #6366f1; --red: #ef4444; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .login-card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 2.5rem; width: 380px; text-align: center; }
  .login-card h1 { font-size: 1.5rem; margin-bottom: 0.3rem; }
  .login-card p { color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }
  .google-btn { display: inline-flex; align-items: center; gap: 0.8rem; background: white; color: #333; border: none; border-radius: 8px; padding: 0.7rem 1.5rem; font-size: 0.95rem; font-weight: 500; cursor: pointer; text-decoration: none; transition: box-shadow 0.15s; }
  .google-btn:hover { box-shadow: 0 2px 12px rgba(99,102,241,0.3); }
  .google-btn svg { width: 20px; height: 20px; }
  .error { color: var(--red); font-size: 0.85rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="login-card">
  <h1>Bounty Intel</h1>
  <p>Private operations center</p>
  $error
  <a href="/auth/google?next=$next_url" class="google-btn">
    <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
    Sign in with Google
  </a>
</div>
</body>
</html>
""")


def render_login(error: str = "", next_url: str = "/") -> str:
    import html
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    safe_next = html.escape(next_url)
    return _LOGIN_TEMPLATE.safe_substitute(error=error_html, next_url=safe_next)
