"""
HTTP session management and request utilities.
Handles authentication, cookies, rate limiting, and error handling.

Used by: crawler.py, modules/sqli.py, modules/xss.py, modules/idor.py, modules/auth.py
"""

import requests
import time
from urllib.parse import urljoin, urlparse
from typing import Optional

# Suppress InsecureRequestWarning for self-signed certs on test servers
requests.packages.urllib3.disable_warnings()


class HTTPSession:
    """
    Managed HTTP session with authentication and rate limiting.

    Usage:
        session = HTTPSession(base_url="http://localhost")
        session.authenticate_dvwa()
        response = session.get("/vulnerabilities/sqli/")
    """

    def __init__(self, base_url: str, timeout: int = 10, delay: float = 0.2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def get(self, path: str, **kwargs) -> requests.Response:
        url = self._resolve_url(path)
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"[HTTP] GET {url} failed: {e}")
            raise

    def post(self, path: str, data: dict = None, json_data: dict = None, **kwargs) -> requests.Response:
        url = self._resolve_url(path)
        time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, json=json_data, timeout=self.timeout, verify=False, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"[HTTP] POST {url} failed: {e}")
            raise

    def _resolve_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def authenticate_dvwa(self, username: str = "admin", password: str = "password", security_level: str = "low"):
        """Authenticate to DVWA and set security level to low."""
        from bs4 import BeautifulSoup

        login_page = self.get("/login.php")
        soup = BeautifulSoup(login_page.text, "html.parser")
        csrf_input = soup.find("input", {"name": "user_token"})
        csrf_token = csrf_input["value"] if csrf_input else ""

        response = self.post("/login.php", data={
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": csrf_token
        })

        if "Login failed" in response.text:
            raise Exception(f"DVWA login failed — check credentials for {self.base_url}")

        print(f"[HTTP] DVWA login successful as '{username}' on {self.base_url}")

        self.post("/security.php", data={
            "security": security_level,
            "seclev_submit": "Submit"
        })
        print(f"[HTTP] DVWA security level set to '{security_level}'")

    def authenticate_juiceshop(self, email: str = "admin@juice-sh.op", password: str = "admin123"):
        """Authenticate to OWASP Juice Shop via REST API."""
        response = self.post("/rest/user/login", json_data={"email": email, "password": password})
        if response.status_code == 200:
            token = response.json().get("authentication", {}).get("token", "")
            self.session.headers["Authorization"] = f"Bearer {token}"
            print(f"[HTTP] Juice Shop login successful")
        else:
            print(f"[HTTP] Juice Shop login failed: {response.status_code}")

    def is_same_origin(self, url: str) -> bool:
        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return (parsed_url.netloc == parsed_base.netloc or
                parsed_url.netloc == "" or
                parsed_url.scheme == "")

    def normalize_url(self, url: str) -> str:
        full_url = urljoin(self.base_url + "/", url)
        parsed = urlparse(full_url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def get_cookies(self) -> dict:
        return dict(self.session.cookies)