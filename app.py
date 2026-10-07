import os
import time
import uuid
import hmac
import hashlib
import threading
from collections import deque
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

API_TOKEN = os.environ["API_TOKEN"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]

MAX_SIGNAL_AGE_MS = int(os.environ.get("MAX_SIGNAL_AGE_MS", "180000"))
MAX_QUEUE = 100

queue = deque()
seen = {}
acks = {}
lock = threading.Lock()


def now_ms():
    return int(time.time() * 1000)


def authorised():
    auth = request.headers.get("Authorization", "")
    return hmac.compare_digest(auth, f"Bearer {API_TOKEN}")


@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "service": "V15 Gold Bridge",
        "pending": len(queue)
    })


@app.get("/health")
def health():
    return "OK", 200


@app.post("/webhook/tradingview")
def tradingview_webhook():
    key = request.args.get("key", "")

    if not hmac.compare_digest(key, WEBHOOK_SECRET):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "invalid_json"}), 400

    try:
        side = str(data["side"]).upper()
        symbol = str(data.get("symbol", "XAUUSD"))
        signal_price = float(data["signal_price"])
        sl = float(data["sl"])
        tp = float(data["tp"])
        risk_pct = float(data["risk_pct"])
        max_spread_oz = float(data["max_spread_oz"])
        signal_time_ms = int(
            data.get("signal_time_ms", now_ms())
        )

        engine = str(data.get("engine", "-"))
        source = str(data.get("source", "-"))

    except Exception:
        return jsonify({"ok": False, "error": "missing_or_invalid_fields"}), 400

    if side not in ("BUY", "SELL"):
        return jsonify({"ok": False, "error": "invalid_side"}), 400

    if "XAUUSD" not in symbol.upper():
        return jsonify({"ok": False, "error": "invalid_symbol"}), 400

    if risk_pct <= 0 or risk_pct > 1.0:
        return jsonify({"ok": False, "error": "risk_above_1_percent"}), 400

    if max_spread_oz <= 0 or max_spread_oz > 0.25:
        return jsonify({"ok": False, "error": "spread_cap_too_high"}), 400

    fingerprint_text = (
        f"{symbol}|{side}|{signal_price}|{sl}|{tp}|"
        f"{risk_pct}|{signal_time_ms}|{engine}|{source}"
    )

    fingerprint = hashlib.sha256(
        fingerprint_text.encode()
    ).hexdigest()

    with lock:
        if fingerprint in seen:
            return jsonify({
                "ok": True,
                "duplicate": True
            }), 200

        if len(queue) >= MAX_QUEUE:
            return jsonify({
                "ok": False,
                "error": "queue_full"
            }), 503

        signal_id = uuid.uuid4().hex[:16]

        signal = {
            "id": signal_id,
            "side": side,
            "symbol": symbol,
            "signal_price": signal_price,
            "sl": sl,
            "tp": tp,
            "risk_pct": risk_pct,
            "max_spread_oz": max_spread_oz,
            "signal_time_ms": signal_time_ms,
            "engine": engine,
            "source": source
        }

        queue.append(signal)
        seen[fingerprint] = now_ms()

    return jsonify({
        "ok": True,
        "queued": True,
        "id": signal_id
    }), 202


@app.get("/api/next")
def next_signal():
    if not authorised():
        return "UNAUTHORIZED", 401

    current = now_ms()

    signal = None

    with lock:
        while queue:
            candidate = queue.popleft()

            age = current - candidate["signal_time_ms"]

            if age <= MAX_SIGNAL_AGE_MS:
                signal = candidate
                break

    if signal is None:
        return Response("NONE", mimetype="text/plain")

    payload = "|".join([
        signal["id"],
        signal["side"],
        signal["symbol"],
        f'{signal["signal_price"]:.6f}',
        f'{signal["sl"]:.6f}',
        f'{signal["tp"]:.6f}',
        f'{signal["risk_pct"]:.4f}',
        f'{signal["max_spread_oz"]:.4f}',
        str(signal["signal_time_ms"]),
        signal["engine"],
        signal["source"]
    ])

    return Response(payload, mimetype="text/plain")


@app.post("/api/ack")
def acknowledge():
    if not authorised():
        return "UNAUTHORIZED", 401

    signal_id = request.args.get("id", "")
    status = request.args.get("status", "")
    detail = request.args.get("detail", "")

    if not signal_id:
        return "MISSING_ID", 400

    with lock:
        acks[signal_id] = {
            "status": status,
            "detail": detail,
            "time_ms": now_ms()
        }

    return "OK", 200
