def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers.get("Content-Security-Policy")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_csp_has_no_wildcard_cors(client):
    # CORS wildcard was removed; no Access-Control-Allow-Origin: *
    r = client.get("/login")
    assert r.headers.get("Access-Control-Allow-Origin") != "*"


def test_csp_has_no_external_hosts(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "unpkg.com" not in csp
    assert "cartocdn" not in csp
    assert "jsdelivr" not in csp          # libraries are vendored now
    assert "https://" not in csp          # zero external hosts
    assert "script-src 'self' 'unsafe-inline'" in csp


def test_bad_host_rejected(anon_client):
    r = anon_client.get("/login", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_rate_limit_batch_start(client):
    # Limit is 5/min; the 6th within the window should be refused.
    codes = [client.post("/api/batch/start", json={"targets": "", "mode": "adaptive"}).status_code
             for _ in range(7)]
    assert 429 in codes
