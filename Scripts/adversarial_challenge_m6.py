#!/usr/bin/env python3
"""
Empirical Adversarial Challenge Test Harness for Swan Account Portal
Milestone 6: Live Production Stress Testing on https://swan.place/
"""

import sys
import json
import urllib.request
import urllib.error
import ssl

BASE_URL = "https://swan.place"
ORIGIN = "https://swan.place"

class TestResult:
    def __init__(self, suite, name, passed, details, status=None, response_body=None, headers=None):
        self.suite = suite
        self.name = name
        self.passed = passed
        self.details = details
        self.status = status
        self.response_body = response_body
        self.headers = headers or {}

    def __str__(self):
        status_str = f" [HTTP {self.status}]" if self.status else ""
        res = "PASS" if self.passed else "FAIL"
        return f"[{res}] {self.suite} :: {self.name}{status_str}\n      Details: {self.details}"

def make_request(method, path, headers=None, body=None):
    url = f"{BASE_URL}{path}"
    req_headers = {
        "User-Agent": "SwanAdversarialChallenger/1.0",
    }
    if headers:
        req_headers.update(headers)

    ctx = ssl.create_default_context()
    data = body.encode('utf-8') if isinstance(body, str) else body

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            resp_body = resp.read().decode('utf-8', errors='replace')
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, resp_body
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode('utf-8', errors='replace')
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, resp_headers, resp_body
    except Exception as e:
        return 0, {}, str(e)

def get_bootstrap_token():
    status, headers, body = make_request(
        "GET",
        "/account/api/bootstrap",
        headers={
            "Origin": ORIGIN,
            "Sec-Fetch-Site": "same-origin"
        }
    )
    if status != 200:
        return None, None, f"Failed to get bootstrap: HTTP {status} body: {body}"
    try:
        data = json.loads(body)
        token = data.get("csrf")
        # Extract cookie
        cookie_header = headers.get("set-cookie") or ""
        cookie_val = None
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("swan_csrf_pre="):
                cookie_val = part.split("=", 1)[1]
                break
        return token, cookie_val, headers
    except Exception as e:
        return None, None, str(e)

def run_tests():
    results = []

    print("=================================================================")
    print("STARTING EMPIRICAL ADVERSARIAL STRESS TESTING: https://swan.place")
    print("=================================================================\n")

    # =========================================================================
    # SUITE 1: Cross-Origin Injection Attacks & CORS Policy
    # =========================================================================
    suite = "Suite 1: Cross-Origin Injection & CORS"

    # 1.1 GET /account/ with evil Origin -> No CORS wildcard or reflection
    status, headers, body = make_request("GET", "/account/", headers={"Origin": "https://evil.com"})
    cors_hdr = headers.get("access-control-allow-origin")
    passed = (status == 200) and (cors_hdr is None)
    results.append(TestResult(suite, "1.1 GET /account/ with Origin: https://evil.com has no CORS header", passed,
                              f"Status={status}, ACAO={cors_hdr}", status, body, headers))

    # 1.2 GET /account/api/bootstrap with evil Origin -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": "https://evil.com", "Sec-Fetch-Site": "cross-site"})
    cors_hdr = headers.get("access-control-allow-origin")
    passed = (status == 403) and (cors_hdr is None)
    results.append(TestResult(suite, "1.2 GET /account/api/bootstrap with Origin: https://evil.com rejected 403", passed,
                              f"Status={status}, Body={body.strip()}, ACAO={cors_hdr}", status, body, headers))

    # 1.3 GET /account/api/bootstrap with subdomain suffix spoof Origin -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": "https://swan.place.attacker.com", "Sec-Fetch-Site": "cross-site"})
    passed = (status == 403)
    results.append(TestResult(suite, "1.3 Suffix spoof Origin (swan.place.attacker.com) rejected 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 1.4 GET /account/api/bootstrap with Origin: null -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"})
    passed = (status == 403)
    results.append(TestResult(suite, "1.4 Origin: null rejected 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 1.5 GET /account/api/bootstrap with non-standard port Origin -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": "https://swan.place:8443", "Sec-Fetch-Site": "same-origin"})
    passed = (status == 403)
    results.append(TestResult(suite, "1.5 Origin with non-standard port (https://swan.place:8443) rejected 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 1.6 OPTIONS preflight on /account/api/bootstrap with evil Origin -> NOT granting CORS
    status, headers, body = make_request("OPTIONS", "/account/api/bootstrap",
                                         headers={
                                             "Origin": "https://evil.com",
                                             "Access-Control-Request-Method": "POST",
                                             "Access-Control-Request-Headers": "X-Swan-CSRF"
                                         })
    cors_hdr = headers.get("access-control-allow-origin")
    passed = (cors_hdr is None)
    results.append(TestResult(suite, "1.6 Preflight OPTIONS /account/api/bootstrap with evil Origin has no ACAO", passed,
                              f"Status={status}, ACAO={cors_hdr}", status, body, headers))

    # 1.7 Sec-Fetch-Site: cross-site on /account/api/bootstrap -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"})
    passed = (status == 403)
    results.append(TestResult(suite, "1.7 Sec-Fetch-Site: cross-site rejected with 403 even with valid Origin", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 1.8 Sec-Fetch-Site: same-site on /account/api/bootstrap -> 403 Forbidden
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-site"})
    passed = (status == 403)
    results.append(TestResult(suite, "1.8 Sec-Fetch-Site: same-site rejected with 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 1.9 Public endpoint CORS isolation: GET /xrpc/com.atproto.server.describeServer with Origin: https://bsky.app -> 200 OK with ACAO: *
    status, headers, body = make_request("GET", "/xrpc/com.atproto.server.describeServer",
                                         headers={"Origin": "https://bsky.app"})
    cors_hdr = headers.get("access-control-allow-origin")
    passed = (status == 200) and (cors_hdr == "*")
    results.append(TestResult(suite, "1.9 Public XRPC endpoint preserves standard CORS wildcard (ACAO: *)", passed,
                              f"Status={status}, ACAO={cors_hdr}", status, body, headers))

    # =========================================================================
    # SUITE 2: CSRF Bypass & Token Integrity Attacks
    # =========================================================================
    suite = "Suite 2: CSRF Bypass & Token Integrity"

    # 2.1 POST /account/api/login with NO CSRF tokens -> 403 Forbidden
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json"
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.1 POST /account/api/login missing CSRF tokens -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.2 POST /account/api/login with Cookie only (missing header) -> 403 Forbidden
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}"
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.2 POST /account/api/login with Cookie only (missing header) -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.3 POST /account/api/login with Header only (missing cookie) -> 403 Forbidden
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.3 POST /account/api/login with Header only (missing cookie) -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.4 POST /account/api/login with Mismatched cookie and header -> 403 Forbidden
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": "completely_different_token_1234567890"
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.4 POST /account/api/login with mismatched Cookie and Header -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.5 POST /account/api/login with Forged identical cookie and header -> 403 Forbidden
    fake_token = "forged_random_fake_token_354KsrqOCxDnNvfUtOPns"
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={fake_token}",
                                             "X-Swan-CSRF": fake_token
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.5 POST /account/api/login with fabricated unissued CSRF token -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.6 Authenticated Mutation without session: POST /account/api/logout -> 403 Forbidden
    status, headers, body = make_request("POST", "/account/api/logout",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json"
                                         },
                                         body='{}')
    passed = (status == 403) and ('request_not_allowed' in body)
    results.append(TestResult(suite, "2.6 POST /account/api/logout without session -> 403 request_not_allowed", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.7 Content-Type Enforcement: POST with application/x-www-form-urlencoded -> 403 Forbidden
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/x-www-form-urlencoded",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='handle=test&password=test')
    passed = (status == 403)
    results.append(TestResult(suite, "2.7 Non-JSON Content-Type (x-www-form-urlencoded) rejected 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 2.8 Content-Type Enforcement: POST with application/json; charset=utf-8 -> 403 Forbidden (exactJSONMediaType)
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json; charset=utf-8",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle":"test","password":"test"}')
    passed = (status == 403)
    results.append(TestResult(suite, "2.8 Parameterized Content-Type (application/json; charset=utf-8) rejected 403", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # =========================================================================
    # SUITE 3: HTTP Verb Spoofing & Invalid Methods
    # =========================================================================
    suite = "Suite 3: HTTP Verb Spoofing & Method Guards"

    # 3.1 PUT /account/api/login -> 404 Not Found (router rejects unsupported verb)
    status, headers, body = make_request("PUT", "/account/api/login",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
                                         body='{}')
    passed = (status == 404)
    results.append(TestResult(suite, "3.1 PUT /account/api/login -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.2 PATCH /account/api/login -> 404 Not Found
    status, headers, body = make_request("PATCH", "/account/api/login",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
                                         body='{}')
    passed = (status == 404)
    results.append(TestResult(suite, "3.2 PATCH /account/api/login -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.3 GET /account/api/login -> 404 Not Found
    status, headers, body = make_request("GET", "/account/api/login",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    passed = (status == 404)
    results.append(TestResult(suite, "3.3 GET /account/api/login -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.4 POST /account/api/portal -> 404 Not Found (portal is GET-only)
    status, headers, body = make_request("POST", "/account/api/portal",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"},
                                         body='{}')
    passed = (status == 404)
    results.append(TestResult(suite, "3.4 POST /account/api/portal -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.5 DELETE /account/api/portal -> 404 Not Found
    status, headers, body = make_request("DELETE", "/account/api/portal",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    passed = (status == 404)
    results.append(TestResult(suite, "3.5 DELETE /account/api/portal -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.6 GET /account/api/sessions/revoke-others -> 404 Not Found (revoke-others is POST-only)
    status, headers, body = make_request("GET", "/account/api/sessions/revoke-others",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    passed = (status == 404)
    results.append(TestResult(suite, "3.6 GET /account/api/sessions/revoke-others -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 3.7 POST /account/api/sessions/session_123 -> 404 Not Found (session revocation is DELETE-only)
    status, headers, body = make_request("POST", "/account/api/sessions/session_123",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"},
                                         body='{}')
    passed = (status == 404)
    results.append(TestResult(suite, "3.7 POST /account/api/sessions/:id -> 404 Not Found (DELETE expected)", passed,
                              f"Status={status}", status, body, headers))

    # =========================================================================
    # SUITE 4: Malformed JSON Payloads & Body Parsing Stress
    # =========================================================================
    suite = "Suite 4: Malformed JSON Payloads"

    # 4.1 Syntax error in JSON body -> Rejected (400 or 401 unauthenticated, no 500 crash)
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle": "unclosed_json_string')
    passed = (status in (400, 401)) and ('500' not in str(status))
    results.append(TestResult(suite, "4.1 Truncated/Malformed JSON safely rejected without 500", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 4.2 Empty payload (0 bytes) with Content-Type: application/json -> Safely rejected
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='')
    passed = (status in (400, 401))
    results.append(TestResult(suite, "4.2 Empty body (0 bytes) safely rejected without 500", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 4.3 Type mismatch (Integer handle, Boolean password) -> Safely rejected
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle": 99999, "password": true}')
    passed = (status in (400, 401))
    results.append(TestResult(suite, "4.3 Type mismatch in JSON fields safely rejected without 500", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 4.4 Extra unknown keys (strict key set enforcement) -> Safely rejected
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle": "alice.swan.place", "password": "password123", "admin": true, "extra": "field"}')
    passed = (status in (400, 401))
    results.append(TestResult(suite, "4.4 Extra unknown JSON keys safely rejected", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 4.5 Null byte in string -> 400 Bad Request
    token, cookie_val, _ = get_bootstrap_token()
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body='{"handle": "alice\\u0000.swan.place", "password": "pass"}')
    passed = (status == 400) and ('"code":"invalid_request"' in body)
    results.append(TestResult(suite, "4.5 Null byte in handle string -> 400 invalid_request", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 4.6 Oversized payload (>16KB, e.g. 32KB payload) -> Safely rejected without server crash
    token, cookie_val, _ = get_bootstrap_token()
    oversized_handle = "a" * 33000
    status, headers, body = make_request("POST", "/account/api/login",
                                         headers={
                                             "Origin": ORIGIN,
                                             "Sec-Fetch-Site": "same-origin",
                                             "Content-Type": "application/json",
                                             "Cookie": f"swan_csrf_pre={cookie_val}",
                                             "X-Swan-CSRF": token
                                         },
                                         body=json.dumps({"handle": oversized_handle, "password": "pass"}))
    passed = (status in (400, 401, 413))
    results.append(TestResult(suite, "4.6 Oversized JSON body (>16KB) handled gracefully -> 400/401/413", passed,
                              f"Status={status}, Body={body[:100].strip()}", status, body, headers))

    # =========================================================================
    # SUITE 5: Non-Existent API Paths & SPA Route Fallback
    # =========================================================================
    suite = "Suite 5: Routing, Unknown API & SPA Fallback"

    # 5.1 Unknown top-level API endpoint -> 404 Not Found JSON (not SPA HTML)
    status, headers, body = make_request("GET", "/account/api/nonexistent_route_test")
    passed = (status == 404) and ('"code":"not_found"' in body) and ('<html' not in body.lower())
    results.append(TestResult(suite, "5.1 Unknown API route /account/api/nonexistent -> 404 not_found JSON", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 5.2 Deep nested unknown API endpoint -> 404 Not Found JSON
    status, headers, body = make_request("GET", "/account/api/admin/users/dump/all")
    passed = (status == 404) and ('"code":"not_found"' in body) and ('<html' not in body.lower())
    results.append(TestResult(suite, "5.2 Deep unknown API route /account/api/*/*/*/* -> 404 not_found JSON", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 5.3 Unknown API POST mutation -> 404 Not Found JSON
    status, headers, body = make_request("POST", "/account/api/arbitrary_mutation",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"},
                                         body='{}')
    passed = (status == 404) and ('"code":"not_found"' in body)
    results.append(TestResult(suite, "5.3 Unknown API POST mutation -> 404 not_found JSON", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 5.4 Root SPA Shell: GET /account/ -> 200 OK HTML
    status, headers, body = make_request("GET", "/account/")
    ct = headers.get("content-type", "")
    passed = (status == 200) and ("text/html" in ct) and ("<html" in body.lower())
    results.append(TestResult(suite, "5.4 Root SPA Shell /account/ -> 200 text/html", passed,
                              f"Status={status}, Content-Type={ct}", status, body, headers))

    # 5.5 Extensionless SPA Route: GET /account/security -> 200 OK SPA HTML fallback
    status, headers, body = make_request("GET", "/account/security")
    ct = headers.get("content-type", "")
    passed = (status == 200) and ("text/html" in ct) and ("<html" in body.lower())
    results.append(TestResult(suite, "5.5 Extensionless SPA route /account/security -> 200 text/html fallback", passed,
                              f"Status={status}, Content-Type={ct}", status, body, headers))

    # 5.6 Extensionless SPA Route: GET /account/passwords -> 200 OK SPA HTML fallback
    status, headers, body = make_request("GET", "/account/passwords")
    ct = headers.get("content-type", "")
    passed = (status == 200) and ("text/html" in ct) and ("<html" in body.lower())
    results.append(TestResult(suite, "5.6 Extensionless SPA route /account/passwords -> 200 text/html fallback", passed,
                              f"Status={status}, Content-Type={ct}", status, body, headers))

    # 5.7 Extensionless SPA Route: GET /account/sessions -> 200 OK SPA HTML fallback
    status, headers, body = make_request("GET", "/account/sessions")
    ct = headers.get("content-type", "")
    passed = (status == 200) and ("text/html" in ct) and ("<html" in body.lower())
    results.append(TestResult(suite, "5.7 Extensionless SPA route /account/sessions -> 200 text/html fallback", passed,
                              f"Status={status}, Content-Type={ct}", status, body, headers))

    # 5.8 Missing static asset with extension: GET /account/missing_script.js -> 404 Not Found (no SPA HTML)
    status, headers, body = make_request("GET", "/account/missing_script.js")
    passed = (status == 404) and ("<html" not in body.lower())
    results.append(TestResult(suite, "5.8 Missing static JS asset /account/missing_script.js -> 404 Not Found", passed,
                              f"Status={status}, Body={body.strip()}", status, body, headers))

    # 5.9 Missing static image: GET /account/missing_image.png -> 404 Not Found
    status, headers, body = make_request("GET", "/account/missing_image.png")
    passed = (status == 404)
    results.append(TestResult(suite, "5.9 Missing static image asset /account/missing_image.png -> 404 Not Found", passed,
                              f"Status={status}", status, body, headers))

    # 5.10 Path traversal attempt: GET /account/../etc/passwd -> 404 or blocked
    status, headers, body = make_request("GET", "/account/../etc/passwd")
    passed = (status in (400, 404))
    results.append(TestResult(suite, "5.10 Path traversal attempt (/account/../etc/passwd) blocked 400/404", passed,
                              f"Status={status}", status, body, headers))

    # =========================================================================
    # SUITE 6: Security Headers, CSP & Cookie Flags
    # =========================================================================
    suite = "Suite 6: Security Headers & Cookie Integrity"

    # 6.1 Content-Security-Policy header validation on /account/
    status, headers, body = make_request("GET", "/account/")
    csp = headers.get("content-security-policy", "")
    has_default_src = "default-src 'none'" in csp
    has_script_src = "script-src 'self'" in csp
    has_sha = "sha256-" in csp
    has_frame_ancestors = "frame-ancestors 'none'" in csp
    has_base_uri = "base-uri 'none'" in csp
    passed = (status == 200) and has_default_src and has_script_src and has_sha and has_frame_ancestors and has_base_uri
    results.append(TestResult(suite, "6.1 Content-Security-Policy header strictness", passed,
                              f"CSP={csp}", status, body, headers))

    # 6.2 Pre-Auth Cookie Flags on /account/api/bootstrap
    status, headers, body = make_request("GET", "/account/api/bootstrap",
                                         headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    cookie_hdr = headers.get("set-cookie", "")
    has_path = "Path=/account" in cookie_hdr
    has_secure = "Secure" in cookie_hdr
    has_samesite_strict = "SameSite=Strict" in cookie_hdr
    passed = (status == 200) and has_path and has_secure and has_samesite_strict
    results.append(TestResult(suite, "6.2 Cookie attributes: Path=/account, Secure, SameSite=Strict", passed,
                              f"Set-Cookie={cookie_hdr}", status, body, headers))

    # 6.3 Immutable cache control on static CSS
    status, headers, body = make_request("GET", "/account/auth-tokens.css")
    cc = headers.get("cache-control", "")
    passed = (status == 200) and ("public" in cc)
    results.append(TestResult(suite, "6.3 Cache-Control on static CSS (/account/auth-tokens.css)", passed,
                              f"Cache-Control={cc}", status, body, headers))

    # =========================================================================
    # SUITE 7: Exhaustive Protected Mutation Endpoints Barrier Verification
    # =========================================================================
    suite7 = "Suite 7: Protected Mutation Endpoints Barrier"
    mutation_routes = [
        ("POST", "/account/api/logout"),
        ("POST", "/account/api/profile"),
        ("POST", "/account/api/identity"),
        ("POST", "/account/api/identity/reserve"),
        ("POST", "/account/api/identity/claim"),
        ("POST", "/account/api/identity/rotate"),
        ("POST", "/account/api/identity/remove"),
        ("POST", "/account/api/app-passwords"),
        ("POST", "/account/api/scopes/validate"),
        ("POST", "/account/api/factors"),
        ("POST", "/account/api/factors/totp"),
        ("POST", "/account/api/factors/totp/verify"),
        ("POST", "/account/api/factors/passkeys"),
        ("POST", "/account/api/factors/passkeys/challenge"),
        ("POST", "/account/api/factors/passkeys/options"),
        ("POST", "/account/api/factors/passkeys/step-up-challenge"),
        ("POST", "/account/api/factors/passkeys/assertion"),
        ("POST", "/account/api/factors/step-up/passkey-challenge"),
        ("POST", "/account/api/factors/recovery-codes/rotate"),
        ("POST", "/account/api/factors/step-up"),
        ("POST", "/account/api/step-up"),
        ("POST", "/account/api/step-up/password"),
        ("POST", "/account/api/sessions/revoke-others"),
        ("POST", "/account/api/connected-apps"),
        ("POST", "/account/api/export"),
        ("POST", "/account/api/export/request"),
        ("POST", "/account/api/migration"),
        ("POST", "/account/api/migration/request"),
        ("POST", "/account/api/lifecycle/delete"),
        ("DELETE", "/account/api/sessions"),
        ("DELETE", "/account/api/sessions/test_session_id_12345"),
        ("DELETE", "/account/api/app-passwords"),
        ("DELETE", "/account/api/app-passwords/test_password_name"),
        ("DELETE", "/account/api/factors/passkeys"),
        ("DELETE", "/account/api/factors/passkeys/test_passkey_id"),
        ("DELETE", "/account/api/factors/totp"),
        ("DELETE", "/account/api/connected-apps"),
        ("DELETE", "/account/api/identity"),
    ]

    for method, path in mutation_routes:
        status, headers, body = make_request(
            method,
            path,
            headers={
                "Origin": ORIGIN,
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/json"
            },
            body='{}'
        )
        passed = (status == 403) and ('request_not_allowed' in body)
        name = f"{method} {path} rejected 403 without active management session"
        results.append(TestResult(suite7, name, passed, f"Status={status}, Body={body.strip()}", status, body, headers))

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 65)
    print("TEST EXECUTION RESULTS:")
    print("=" * 65)

    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)

    for r in results:
        print(str(r))
        print("-" * 65)

    print(f"\nTOTAL: {passed_count} / {total_count} PASSED ({(passed_count/total_count)*100:.1f}%)")

    if passed_count == total_count:
        print("\n>>> OVERALL VERDICT: APPROVE (100% Adversarial Resistance) <<<")
    else:
        print(f"\n>>> OVERALL VERDICT: REJECT ({total_count - passed_count} failures detected) <<<")

    return passed_count == total_count, results

if __name__ == "__main__":
    success, _ = run_tests()
    sys.exit(0 if success else 1)
