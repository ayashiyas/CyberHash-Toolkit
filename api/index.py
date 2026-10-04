"""
api/index.py
Flask app exposing CyberHash Toolkit as a web UI + JSON API.
Deployed on Vercel via vercel.json (routes everything here).
Stateless: history lives in the browser (localStorage), not the server,
since serverless filesystems are ephemeral/read-only.
"""

import os
import sys
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify, render_template

from core import hasher, identifier, analyzer, encoder

app = Flask(__name__)

VERSION = "1.1.0"

# Safety caps for the *public* deployment - tighter than the CLI defaults
# so a single request can't run long on a serverless function.
WEB_MAX_BRUTEFORCE_LENGTH = 4
WEB_MAX_BRUTEFORCE_ATTEMPTS = 300_000
WEB_MAX_WORDLIST_WORDS = 20_000
WEB_MAX_FILE_BYTES = 15 * 1024 * 1024  # 15MB, keeps serverless requests fast

# ---------------------------------------------------------------- rate limit
# Naive in-memory limiter for the two compute-heavy endpoints. Good enough
# to stop casual abuse on a single serverless instance; it resets whenever
# the instance recycles (a known limitation of stateless functions, noted
# here on purpose rather than pretending it's bulletproof).
_RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_CALLS = 10


def rate_limited(key):
    now = time.time()
    calls = [t for t in _RATE_LIMIT.get(key, []) if now - t < RATE_LIMIT_WINDOW]
    calls.append(now)
    _RATE_LIMIT[key] = calls
    return len(calls) > RATE_LIMIT_MAX_CALLS


@app.route("/")
def index():
    return render_template(
        "index.html",
        algorithms=hasher.list_algorithms(),
        algo_info=json.dumps(hasher.ALGO_INFO),
        version=VERSION,
    )


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "version": VERSION, "algorithms": hasher.list_algorithms()})


@app.route("/api/hash-text", methods=["POST"])
def api_hash_text():
    data = request.get_json(force=True)
    text = data.get("text", "")
    algorithm = data.get("algorithm", "")
    try:
        if algorithm == "all":
            return jsonify({"results": hasher.hash_text_all(text)})
        return jsonify({"digest": hasher.hash_text(text, algorithm)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/hash-file", methods=["POST"])
def api_hash_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    algorithm = request.form.get("algorithm", "")
    data = f.read(WEB_MAX_FILE_BYTES + 1)
    if len(data) > WEB_MAX_FILE_BYTES:
        return jsonify({"error": f"File too large for the web demo (max {WEB_MAX_FILE_BYTES // (1024*1024)}MB). Use the CLI for bigger files."}), 400
    try:
        if algorithm == "all":
            results = {}
            for algo in hasher.list_algorithms():
                h = hasher.ALGORITHMS[algo]()
                h.update(data)
                results[algo] = h.hexdigest()
            return jsonify({"results": results, "filename": f.filename, "size": len(data)})
        h = hasher.ALGORITHMS[algorithm]()
        h.update(data)
        return jsonify({"digest": h.hexdigest(), "filename": f.filename, "size": len(data)})
    except KeyError:
        return jsonify({"error": f"Unsupported algorithm: {algorithm}"}), 400


@app.route("/api/identify", methods=["POST"])
def api_identify():
    data = request.get_json(force=True)
    value = data.get("value", "")
    return jsonify({"results": identifier.identify(value)})


@app.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json(force=True)
    match = analyzer.compare_hashes(data.get("a", ""), data.get("b", ""))
    return jsonify({"match": match})


@app.route("/api/decode", methods=["POST"])
def api_decode():
    data = request.get_json(force=True)
    target = data.get("hash", "")
    algorithm = data.get("algorithm", "")
    try:
        result = analyzer.decode_hash(target, algorithm, limit=WEB_MAX_WORDLIST_WORDS)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/wordlist", methods=["POST"])
def api_wordlist():
    if rate_limited(request.remote_addr):
        return jsonify({"error": "Rate limit hit. Wait a minute and try again."}), 429
    data = request.get_json(force=True)
    target = data.get("hash", "")
    algorithm = data.get("algorithm", "")
    words_raw = data.get("words", "")
    words = [w.strip() for w in words_raw.splitlines() if w.strip()][:WEB_MAX_WORDLIST_WORDS]
    try:
        result = analyzer.attack_words(target, algorithm, words, limit=WEB_MAX_WORDLIST_WORDS)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/bruteforce", methods=["POST"])
def api_bruteforce():
    if rate_limited(request.remote_addr):
        return jsonify({"error": "Rate limit hit. Wait a minute and try again."}), 429
    data = request.get_json(force=True)
    target = data.get("hash", "")
    algorithm = data.get("algorithm", "")
    charset = data.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")
    max_length = min(int(data.get("max_length", 3)), WEB_MAX_BRUTEFORCE_LENGTH)

    old_cap = analyzer.MAX_BRUTEFORCE_ATTEMPTS
    analyzer.MAX_BRUTEFORCE_ATTEMPTS = WEB_MAX_BRUTEFORCE_ATTEMPTS
    try:
        keyspace = analyzer.keyspace_size(len(charset), max_length)
        result = analyzer.bounded_bruteforce(target, algorithm, charset, max_length)
        result["keyspace"] = keyspace
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    finally:
        analyzer.MAX_BRUTEFORCE_ATTEMPTS = old_cap


@app.route("/api/encode", methods=["POST"])
def api_encode():
    data = request.get_json(force=True)
    try:
        result = encoder.run(data.get("tool", ""), data.get("mode", ""), data.get("text", ""))
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Local dev: `python api/index.py` runs this on http://localhost:5000
if __name__ == "__main__":
    app.run(debug=True)
