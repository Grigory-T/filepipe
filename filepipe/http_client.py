from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    def __init__(self, status_code: int, body: bytes):
        super().__init__(f"HTTP {status_code}: {body.decode('utf-8', errors='replace')}")
        self.status_code = status_code
        self.body = body


class RelayHttpClient:
    def __init__(self, base_url: str, cafile: str | None = None, insecure_skip_verify: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.context = None
        if self.base_url.startswith("https://"):
            if insecure_skip_verify:
                self.context = ssl._create_unverified_context()
            else:
                self.context = ssl.create_default_context(cafile=cafile)

    def _request(self, method: str, path: str, data: bytes | None = None, headers: dict[str, str] | None = None) -> bytes:
        request_headers = dict(headers or {})
        request_headers.setdefault("Connection", "close")
        if data is not None:
            request_headers.setdefault("Content-Length", str(len(data)))
            request_headers.setdefault("Expect", "")
        request = urllib.request.Request(
            url=self.base_url + path,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, context=self.context) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            raise HttpError(exc.code, body) from exc

    def get_json(self, path: str) -> Any:
        return json.loads(self._request("GET", path).decode("utf-8"))

    def post_json(self, path: str, payload: Any) -> Any:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        response = self._request("POST", path, body, {"Content-Type": "application/json"})
        return json.loads(response.decode("utf-8"))

    def put_bytes(self, path: str, payload: bytes) -> Any:
        response = self._request("PUT", path, payload, {"Content-Type": "application/octet-stream"})
        return json.loads(response.decode("utf-8"))

    def get_bytes(self, path: str) -> bytes:
        return self._request("GET", path)
