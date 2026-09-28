def test_status_shape(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.json()
    assert set(d.keys()) == {"tor", "vpn", "proxy", "agents"}
    for k in ("tor", "vpn", "proxy"):
        assert isinstance(d[k], bool)


def test_report_path_traversal_blocked(client):
    r = client.get("/api/reports/..%2f..%2f..%2fetc%2fpasswd")
    assert r.status_code == 404


def test_settings_env_key_allowlist(client):
    r = client.post("/api/settings/env", json={"key": "NOT_ALLOWED", "value": "x"})
    assert r.status_code == 400


def test_settings_onion_rejects_bad_value(client):
    r = client.post("/api/settings/onion", json={"targets": {"ok": "not a valid onion value !!!\n"}})
    assert r.status_code in (400, 404)  # 404 if agent-10 script absent in the test tree


def test_map_ips_country_aggregates(client):
    r = client.get("/api/map/ips")
    assert r.status_code == 200
    d = r.json()
    assert "countries" in d and isinstance(d["countries"], list)
    assert "resolver" in d and "total_ips" in d


def test_account_endpoint_shape(client):
    r = client.get("/api/settings/account")
    assert r.status_code == 200
    assert "username" in r.json()


def test_activity_recent_shape(client):
    r = client.get("/api/activity/recent?limit=5")
    assert r.status_code == 200
    d = r.json()
    assert "findings" in d and isinstance(d["findings"], list)


def test_metrics_shape(client):
    r = client.get("/api/metrics")
    assert r.status_code == 200
    d = r.json()
    assert "tiles" in d
    for key in ("reports", "kb_docs", "threat_actors", "critical"):
        assert key in d["tiles"]
        tile = d["tiles"][key]
        assert "value" in tile and "series" in tile and isinstance(tile["series"], list)
