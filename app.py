#!/usr/bin/env python3
"""numtoveh API server with Proxy & Clean Data for Render."""
import base64
import json
import re
import socket
import sys
import time
import os

try:
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from flask import Flask, jsonify, request
except ImportError:
    sys.exit("pip install requests pycryptodome flask gunicorn PySocks")

# ============================================================
#  CONFIGURATION, TOKEN & PROXY
# ============================================================
TOKEN = "TX*u^IaEX0N~gLWt"
PORT = int(os.environ.get("PORT", 8094))
HOST = "0.0.0.0"

# PROXY CONFIGURATION (SOCKS5 format)
# Note: Agar 'socks5://' se error aaye, toh 'socks5h://' ka use karein 
# (socks5h DNS resolve proxy ke through karta hai).
PROXY_URL = "socks5://b5c8158d30ce89f4:MfKLFCgJaWdtpDRe@res.rocket-seller.com:10001"
PROXIES = {
    "http": PROXY_URL,
    "https": PROXY_URL
}

NAPIX_BASE_URL = "https://delhigw.napix.gov.in/nic/parivahan/"
NAPIX_API_BASE_URL = "https://delhigw.napix.gov.in/nic/parivahan/mparivahan/wrapperapi/"
CLIENT_ID = "b91c303443f61b37106750823881cd2f"
CLIENT_SECRET = "de83eeeb148878ae375f28756492e8a0"
NAPIX_SCOPE = "napix"
PARAM2 = "2.0.143"
TIMEOUT = 8.0
TOKEN_TIMEOUT = 8.0
WRAPPER_BASE = NAPIX_API_BASE_URL.rstrip("/")

_ACCESS_TOKEN = None


def aes_transform(encrypt: bool, value: str, key: str) -> str:
    kb = key.encode("utf-8")
    if encrypt:
        return base64.b64encode(
            AES.new(kb, AES.MODE_ECB).encrypt(pad(value.encode("utf-8"), 16))).decode("ascii")
    return unpad(AES.new(kb, AES.MODE_ECB).decrypt(
        base64.b64decode(value)), 16).decode("utf-8")


def request_key(timestamp: str) -> str:
    return timestamp[-4:][::-1] + timestamp[:4][::-1] + "!~)#@*&^"


def napix_reachable(timeout: float = 3.0) -> bool:
    return True


def get_oauth_token(force_refresh: bool = False) -> str:
    global _ACCESS_TOKEN
    now = int(time.time())
    if not force_refresh and _ACCESS_TOKEN and int(_ACCESS_TOKEN.get("expires_at", 0)) > now + 30:
        return str(_ACCESS_TOKEN["access_token"])
    
    r = requests.post(
        NAPIX_BASE_URL + "oauth2/token",
        data={"grant_type": "client_credentials",
              "scope": NAPIX_SCOPE,
              "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        headers={"User-Agent": "okhttp/4.9.2", "Connection": "Keep-Alive",
                 "Accept-Encoding": "gzip",
                 "Content-Type": "application/x-www-form-urlencoded"},
        timeout=TOKEN_TIMEOUT,
        proxies=PROXIES)
    r.raise_for_status()
    data = r.json()
    if not data.get("access_token"):
        raise RuntimeError("no access_token")
    _ACCESS_TOKEN = {"access_token": data["access_token"],
                     "expires_at": now + int(data.get("expires_in", 300))}
    return str(_ACCESS_TOKEN["access_token"])


def encrypted_post(url, body, token, extra_headers=None, timeout=None):
    timestamp = str(int(time.time() * 1000))
    key = request_key(timestamp)
    plain = json.dumps(body if body is not None else {},
                       separators=(",", ":"), ensure_ascii=False)
    envelope = {"data": base64.b64encode(
        aes_transform(True, plain, key).encode("ascii")).decode("ascii")}
    headers = {"User-Agent": "okhttp/4.9.2", "Connection": "Keep-Alive",
               "Accept": "application/json", "Accept-Encoding": "gzip",
               "timestamp": timestamp, "Authorization": f"Bearer {token}",
               "Param2": PARAM2, "Param1": TOKEN,
               "Content-Type": "application/json; charset=utf-8"}
    for name, value in (extra_headers or {}).items():
        if str(name).lower() in {"param1", "param2", "timestamp"}:
            headers[str(name)] = str(value)
    
    resp = requests.post(url, json=envelope, headers=headers,
                         timeout=timeout or TIMEOUT, proxies=PROXIES)
    raw = resp.text
    try:
        outer = resp.json()
        encoded = outer.get("data")
        if encoded:
            raw = aes_transform(False, base64.b64decode(encoded).decode("utf-8"), key)
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                pass
        else:
            raw = outer
    except (ValueError, KeyError, TypeError, base64.binascii.Error,
            UnicodeDecodeError):
        pass
    return resp.status_code, dict(resp.headers), raw


VEHICLE_VALIDITY_KEYS = [
    ("regNo", "Registration No"), ("stateCd", "State Code"),
    ("stateName", "State"), ("officeName", "RTO Office"),
    ("offCd", "Office Code"), ("ishypothetical", "Hypothetical"),
    ("vltdUpto", "Vehicle Ltd Tax Upto"), ("cngkitUpto", "CNG Kit Upto"),
    ("regnUpto", "Registration Upto"), ("fitUpto", "Fitness Upto"),
    ("taxUpto", "Tax Upto"), ("insUpto", "Insurance Upto"),
    ("puccUpto", "PUCC Upto"), ("permitUpto", "Permit Upto"),
    ("aitpUpto", "AITP Upto"), ("nptUpto", "NPT Upto"),
]


def lookup(mobile_no: str, token=None):
    mobile_no = re.sub(r"\D", "", str(mobile_no or ""))
    if not re.fullmatch(r"\d{10}", mobile_no):
        raise ValueError("10-digit mobile required")
    token = token or get_oauth_token()
    url = WRAPPER_BASE + "/vahan/vahancapi/common/getvehiclevalidity"
    last = None
    for attempt in range(2):
        try:
            status, _, result = encrypted_post(url, {"mobileNo": mobile_no},
                                               token, timeout=10.0)
        except requests.RequestException as exc:
            status, result = None, {"error": f"attempt {attempt + 1}: {exc}"}
        if status and status < 500 and result not in (None, ""):
            last = result
            break
        last = result
        time.sleep(1.0)
    if last is None:
        raise ValueError("upstream did not respond")
    api_message = last.get("apiMessage") or {} if isinstance(last, dict) else {}
    raw = last.get("data") if isinstance(last, dict) else None
    
    vehicles = []
    if isinstance(raw, list):
        vehicles = [v for v in raw if isinstance(v, dict)]
    elif isinstance(raw, dict):
        vehicles = [raw]
        
    code = str(api_message.get("statusCode")
               or (last.get("statusCode") if isinstance(last, dict) else "") or "")
    if not vehicles:
        if code and code != "200":
            return {"mobileNo": mobile_no, "found": False, "vehicles": [],
                    "error": f"NAPIX down ({code}): "
                    f"{api_message.get('developerMessage') or api_message.get('message') or (last.get('statusDesc') if isinstance(last, dict) else '') or 'upstream error'}"}
        return {"mobileNo": mobile_no, "found": False, "vehicles": [],
                "message": "No vehicle is registered against this mobile number."}
    
    out = []
    seen_reg_nos = set()
    
    for v in vehicles:
        reg_no = v.get("regNo")
        if reg_no and reg_no in seen_reg_nos:
            continue
            
        e = {label: v.get(key) for key, label in VEHICLE_VALIDITY_KEYS}
        out.append(e)
        if reg_no:
            seen_reg_nos.add(reg_no)
            
    return {"mobileNo": mobile_no, "found": True, "count": len(out), "vehicles": out}


# ===================== API SERVER =====================

app = Flask(__name__)


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "numtoveh API with Proxy (Clean Data)",
        "endpoints": {
            "GET /health": "server status",
            "GET /api/mobveh?mobile=9060200196": "vehicle lookup"
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "token_set": bool(TOKEN), "proxy_enabled": True})


@app.route("/api/mobveh", methods=["GET", "POST"])
def mobveh():
    body = request.get_json(silent=True) or {}
    mob = (request.args.get("mobile") or body.get("mobile") or "").strip()
    if not mob:
        return jsonify({"status": "Error", "error": "mobile required"}), 400
    try:
        return jsonify({"status": "Success", "data": lookup(mob)})
    except ValueError as e:
        return jsonify({"status": "Error", "error": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "Error",
                        "error": f"{type(e).__name__}: {e}"}), 502


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, threaded=True)
