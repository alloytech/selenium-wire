"""A minimal httpbin-compatible server used by the integration tests.

The archived ``httpbin`` package no longer runs on modern Python (its
``flasgger`` dependency imports the removed ``imp`` module), so the tests
serve this small Flask app instead. Only the endpoints exercised by the
test suite are implemented.
"""

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# 1x1 transparent PNG.
_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

_HTML = """<!DOCTYPE html>
<html>
  <head><title>Moby-Dick</title></head>
  <body>
    <h1>Herman Melville - Moby-Dick</h1>
    <p>Call me Ishmael.</p>
  </body>
</html>
"""

_ANY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def _request_headers():
    return {name: value for name, value in request.headers.items()}


def _echo():
    return {
        "args": request.args.to_dict(),
        "data": request.get_data().decode("utf-8", "replace"),
        "files": {},
        "form": request.form.to_dict(),
        "headers": _request_headers(),
        "json": request.get_json(silent=True),
        "method": request.method,
        "origin": request.remote_addr or "",
        "url": request.url,
    }


@app.after_request
def _add_cache_control(response):
    response.headers.setdefault("Cache-Control", "no-cache")
    return response


@app.get("/html")
def html():
    return _HTML


@app.get("/get")
def get():
    return jsonify(
        args=request.args.to_dict(),
        headers=_request_headers(),
        origin=request.remote_addr or "",
        url=request.url,
    )


@app.get("/headers")
def headers():
    return jsonify(headers=_request_headers())


@app.get("/image/png")
def image_png():
    return Response(_PNG, mimetype="image/png")


@app.get("/bytes/<int:count>")
def send_bytes(count):
    return Response(bytes(count), mimetype="application/octet-stream")


@app.post("/post")
def post():
    return jsonify(_echo())


@app.route("/anything", defaults={"path": ""}, methods=_ANY_METHODS)
@app.route("/anything/<path:path>", methods=_ANY_METHODS)
def anything(path):
    return jsonify(_echo())
