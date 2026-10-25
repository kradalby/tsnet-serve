import json
import re
import shlex

T = 120
URL = "https://proxy.tailnet.test:8443"


def put(machine, path, text):
    machine.succeed(f"printf %s {shlex.quote(text)} > {path}")


def environment(
    key=None,
    backend="8080",
    allowed_paths="^/allowed",
    denied_paths="^/allowed/private",
):
    text = (
        "TSNS_HOSTNAME=proxy\nTSNS_LISTEN_PORT=8443\n"
        f"TSNS_ALLOWED_PATHS={allowed_paths}\nTSNS_DENIED_PATHS={denied_paths}\n"
        f"TSNS_BACKEND={backend}\n"
    )
    if key:
        text += f"TS_AUTHKEY={key}\n"
    put(app, "/run/proxy.env", text)
    app.succeed("chmod 600 /run/proxy.env")


def request(path="/allowed", extra=""):
    return (
        f"curl -sS --max-time 5 --cacert /run/ca.crt "
        f"--resolve proxy.tailnet.test:8443:{ip} {extra} {shlex.quote(URL + path)}"
    )


def status(machine, path, expected):
    output = machine.succeed(request(path, "-o /tmp/body -w '%{http_code}'"))
    assert output == str(expected), (path, output, expected)


def healthy(machine):
    machine.wait_until_succeeds(request(extra="-f") + " > /tmp/response", timeout=T)
    return json.loads(machine.succeed("cat /tmp/response"))


def policy(allow_denied=True):
    rules = [{"action": "accept", "src": ["alice@"], "dst": ["tag:web:8443"]}]
    if allow_denied:
        rules.append({"action": "accept", "src": ["bob@"], "dst": ["tag:web:8443"]})
    put(
        headscale,
        "/tmp/policy.json",
        json.dumps(
            {
                "tagOwners": {"tag:web": ["server@"]},
                "acls": rules,
            }
        ),
    )
    headscale.succeed("headscale policy set -f /tmp/policy.json")


def server_node():
    nodes = json.loads(headscale.succeed("headscale nodes list -o json"))
    return next(n for n in nodes if n["givenName"] == "proxy")


start_all()
with subtest("trusted certificate fixture and enrollment"):
    app.wait_for_unit("backend")
    headscale.succeed("hs-authkey server > /dev/null")
    policy()
    key = headscale.succeed("hs-authkey server --tags tag:web").strip()
    headscale.succeed(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=test-CA "
        "-addext basicConstraints=critical,CA:TRUE -keyout /tmp/ca.key -out /tmp/ca.crt"
    )
    headscale.succeed(
        "openssl req -newkey rsa:2048 -nodes -subj /CN=proxy.tailnet.test "
        "-keyout /tmp/app.key -out /tmp/app.csr"
    )
    put(
        headscale,
        "/tmp/extensions",
        "subjectAltName=DNS:proxy.tailnet.test\nextendedKeyUsage=serverAuth\n",
    )
    headscale.succeed(
        "openssl x509 -req -in /tmp/app.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key "
        "-CAcreateserial -out /tmp/app.crt -days 30 -extfile /tmp/extensions"
    )
    for machine in (app, direct, relay, denied):
        machine.wait_for_unit("multi-user.target")
        put(machine, "/run/ca.crt", headscale.succeed("cat /tmp/ca.crt"))
    for suffix in ("crt", "key"):
        put(app, f"/run/app.{suffix}", headscale.succeed(f"cat /tmp/app.{suffix}"))
    environment()
    app.succeed("systemctl start tsnet-serve")
    auth_log = app.wait_until_succeeds(
        "journalctl -u tsnet-serve -o cat | grep 'http://headscale/.*hskey-authreq-'",
        timeout=T,
    )
    assert not any(
        n["givenName"] == "proxy"
        for n in json.loads(headscale.succeed("headscale nodes list -o json"))
    )
    auth_match = re.search(r"hskey-authreq-[a-f0-9]+", auth_log)
    assert auth_match, auth_log
    auth_id = auth_match.group()
    headscale.succeed(f"headscale auth register --user server --auth-id {auth_id}")
    app.wait_until_succeeds(
        "journalctl -u tsnet-serve -o cat | grep 'proxying traffic to'", timeout=T
    )
    interactive = server_node()
    assert interactive["user"]["name"] == "server", interactive
    app.succeed("systemctl stop tsnet-serve")
    headscale.succeed(
        f"headscale nodes delete --identifier {interactive['id']} --force"
    )
    # The rejected-key case must not inherit the interactively approved identity.
    app.succeed("rm /var/lib/private/tsnet-serve/tailscaled.state")
    environment("invalid-auth-key")
    app.succeed("systemctl start tsnet-serve")
    app.wait_until_succeeds(
        "journalctl -u tsnet-serve -o cat | grep -i 'invalid.*key\\|key.*invalid'",
        timeout=T,
    )
    assert not any(
        n["givenName"] == "proxy"
        for n in json.loads(headscale.succeed("headscale nodes list -o json"))
    )
    app.succeed("systemctl stop tsnet-serve")
    environment(key)
    app.succeed("systemctl start tsnet-serve")
    peer_keys = {
        user: headscale.succeed(f"hs-authkey {user}").strip()
        for user in ("alice", "bob")
    }
    for machine, user in ((direct, "alice"), (relay, "alice"), (denied, "bob")):
        machine.succeed(f"hs-join {peer_keys[user]}")
    ip = direct.wait_until_succeeds("tailscale ip -4 proxy", timeout=T).strip()
    healthy(direct)
    direct.wait_until_succeeds(
        f"curl -fsS --max-time 5 --cacert /run/ca.crt {URL}/allowed", timeout=T
    )
    node = server_node()
    assert "tag:web" in node["tags"], node
    pid = app.succeed("systemctl show tsnet-serve -p MainPID --value").strip()
    app.succeed(f"test $(stat -c %u /proc/{pid}) -ne 0")
    app.succeed("test $(stat -c %a /var/lib/private/tsnet-serve) = 700")

with subtest("direct and forced-DERP HTTPS, forwarding and path permissions"):
    direct.wait_until_succeeds(
        "tailscale ping -c 1 --timeout 3s proxy | grep 'via .*:.*'", timeout=T
    )
    direct.succeed(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "proxy") | .CurAddr != ""\''
    )
    relay.wait_until_succeeds(
        "tailscale ping --until-direct=false -c 1 --timeout 3s proxy | grep 'via DERP(headscale)'",
        timeout=T,
    )
    for machine in (direct, relay):
        response = healthy(machine)
        assert response["path"] == "/allowed", response
        response = json.loads(
            machine.succeed(
                request(
                    "/allowed/echo?q=one%20two",
                    "-X POST --data 'payload' -H 'X-Forwarded-For: forged'",
                )
            )
        )
        assert response["method"] == "POST" and response["body"] == "payload", response
        assert response["path"] == "/allowed/echo?q=one%20two", response
        headers = {k.lower(): v for k, v in response["headers"].items()}
        assert headers["x-forwarded-proto"] == "https", headers
        assert headers["x-forwarded-host"] == "proxy.tailnet.test:8443", headers
        assert (
            headers["x-forwarded-for"] == machine.succeed("tailscale ip -4").strip()
        ), headers
        status(machine, "/allowed/private", 403)
        status(machine, "/allowed/%70rivate", 403)
        status(machine, "/other", 404)
        healthy(machine)
    # Trust is required; the application fixture does not disable TLS verification.
    code, output = direct.execute(
        f"curl -fsS --max-time 5 --resolve proxy.tailnet.test:8443:{ip} {URL}/allowed"
    )
    assert code == 60, (code, output)
    healthy(direct)

with subtest("path policies block traversal before a normalizing backend"):
    traversal_paths = (
        "/allowed/public/../private/secret.txt",
        "/allowed/public/%2e%2e/private/secret.txt",
        "/allowed/public/.%2E/private/secret.txt",
        "/allowed/public/..%2fprivate/secret.txt",
        "/allowed/../outside.txt",
        "/allowed/%2e%2e/outside.txt",
        "/allowed/./private/secret.txt",
        "/allowed/%2e/private/secret.txt",
        "/allowed//private/secret.txt",
    )
    assert (
        app.succeed(
            "curl -fsS --path-as-is http://127.0.0.1:8080/allowed/public/../private/secret.txt"
        )
        == "private resource\n"
    )
    probes = []
    for machine, name in ((direct, "direct"), (relay, "relay")):
        assert (
            machine.succeed(
                request("/allowed/public/%68ello.txt?ref=%2e%2e", "-f --path-as-is")
            )
            == "allowed resource\n"
        )
        for index, path in enumerate(traversal_paths):
            marker = f"traversal-{name}-{index}"
            code = machine.succeed(
                request(
                    f"{path}?probe={marker}",
                    "--path-as-is -o /tmp/traversal-body -w '%{http_code}'",
                )
            )
            probes.append(
                (path, marker, code, machine.succeed("cat /tmp/traversal-body"))
            )
        marker = f"traversal-control-{name}"
        assert (
            machine.succeed(request(f"/allowed/public/hello.txt?probe={marker}", "-f"))
            == "allowed resource\n"
        )
        app.wait_until_succeeds(
            f"journalctl -u backend -o cat | grep -F {marker}", timeout=T
        )
    backend_log = app.succeed("journalctl -u backend -o cat")
    print(
        "path-policy resource probes: "
        + json.dumps(
            [
                {
                    "path": path,
                    "probe": marker,
                    "status": code,
                    "body": body,
                    "backend_access": marker in backend_log,
                }
                for path, marker, code, body in probes
            ]
        )
    )
    assert all(
        code == "400" and marker not in backend_log for _, marker, code, _ in probes
    ), probes

with subtest("independent path policies and explicit no-policy passthrough"):
    for allowed_paths, denied_paths in (
        ("^/allowed", ""),
        ("", "^/allowed/private"),
        ("", ""),
    ):
        app.succeed("systemctl stop tsnet-serve")
        environment(allowed_paths=allowed_paths, denied_paths=denied_paths)
        app.succeed("systemctl start tsnet-serve")
        for machine in (direct, relay):
            healthy(machine)
            response = json.loads(machine.succeed(request("/allowed/", "-f")))
            assert response["path"] == "/allowed/", response
            assert (
                machine.succeed(
                    request("/allowed/public/%68ello.txt?ref=%2e%2e", "-f --path-as-is")
                )
                == "allowed resource\n"
            )
            status(machine, "/allowed/private/secret.txt", 403 if denied_paths else 200)
            status(machine, "/outside.txt", 404 if allowed_paths else 200)
            status(machine, "/", 404 if allowed_paths else 200)
            for path, body in (
                ("/allowed/public/../private/secret.txt", "private resource\n"),
                ("/allowed/public/%2e%2e/private/secret.txt", "private resource\n"),
                ("/allowed/../outside.txt", "outside resource\n"),
                ("/allowed/%2e%2e/outside.txt", "outside resource\n"),
            ):
                code = machine.succeed(
                    request(path, "--path-as-is -o /tmp/policy-body -w '%{http_code}'")
                )
                expected = "400" if allowed_paths or denied_paths else "200"
                assert code == expected, (allowed_paths, denied_paths, path, code)
                if expected == "200":
                    assert machine.succeed("cat /tmp/policy-body") == body
            if not allowed_paths and not denied_paths:
                for path in (
                    "/allowed/public/../echo?q=one%20two",
                    "/allowed/public/%2E%2E/echo?q=one%20two",
                    "/allowed//echo?q=one%20two",
                ):
                    response = json.loads(
                        machine.succeed(request(path, "-f --path-as-is"))
                    )
                    assert response["path"] == path, response
    app.succeed("systemctl stop tsnet-serve")
    environment()
    app.succeed("systemctl start tsnet-serve")
    healthy(direct)
    healthy(relay)

with subtest("live user ACL revocation with positive control and recovery"):
    healthy(denied)
    policy(False)
    denied.wait_until_fails(request(extra="-f"), timeout=T)
    healthy(direct)
    healthy(relay)
    denied.fail(request(extra="-f"))
    policy()
    healthy(denied)

with subtest("established direct traffic survives control and DERP outage"):
    direct.wait_until_succeeds(
        "tailscale ping -c 1 --timeout 3s proxy | grep 'via .*:.*'", timeout=T
    )
    headscale.succeed("systemctl stop headscale")
    headscale.fail("systemctl is-active --quiet headscale")
    healthy(direct)
    headscale.succeed("systemctl start headscale")
    headscale.wait_for_unit("headscale")
    healthy(relay)

with subtest("restart without auth key preserves identity and HTTPS"):
    before = server_node()
    app.succeed("systemctl stop tsnet-serve")
    environment()
    app.succeed("systemctl start tsnet-serve")
    healthy(direct)
    healthy(relay)
    after = server_node()
    for field in ("id", "nodeKey", "ipAddresses", "tags"):
        assert before[field] == after[field], (field, before, after)

with subtest("Funnel capability refusal and ordinary HTTPS recovery"):
    app.succeed("systemctl stop tsnet-serve")
    environment()
    app.succeed("echo TSNS_FUNNEL=true >> /run/proxy.env; systemctl start tsnet-serve")
    app.wait_until_succeeds(
        "journalctl -u tsnet-serve -o cat | grep 'failed to start listener: Funnel not available'",
        timeout=T,
    )
    app.wait_until_succeeds("systemctl is-failed --quiet tsnet-serve", timeout=T)
    environment()
    app.succeed("systemctl reset-failed tsnet-serve; systemctl start tsnet-serve")
    healthy(direct)
    healthy(relay)

with subtest("backend failure is 502; path policy still enforced; recovery"):
    app.succeed("systemctl stop backend")
    status(direct, "/allowed", 502)
    status(relay, "/allowed", 502)
    status(direct, "/allowed/private", 403)
    app.succeed("systemctl start backend")
    healthy(direct)
    healthy(relay)

with subtest("backend URL prefix and configuration precedence"):
    for backend in ("127.0.0.1:8080", "http://127.0.0.1:8080/prefix?fixed=yes"):
        app.succeed("systemctl stop tsnet-serve")
        environment(backend=backend)
        app.succeed("systemctl start tsnet-serve")
        response = healthy(direct)
        expected = "/prefix/allowed?fixed=yes" if "/prefix" in backend else "/allowed"
        assert response["path"] == expected, response
        for machine in (direct, relay):
            response = json.loads(
                machine.succeed(request("/allowed/%65cho/?q=one%20two", "-f"))
            )
            expected = (
                "/prefix/allowed/%65cho/?fixed=yes&q=one%20two"
                if "/prefix" in backend
                else "/allowed/%65cho/?q=one%20two"
            )
            assert response["path"] == expected, response

with subtest("HTTPS backends verify trust and hostname unless explicitly insecure"):
    headscale.succeed(
        "openssl req -newkey rsa:2048 -nodes -subj /CN=localhost "
        "-keyout /tmp/backend.key -out /tmp/backend.csr"
    )
    put(
        headscale,
        "/tmp/extensions",
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
    )
    headscale.succeed(
        "openssl x509 -req -in /tmp/backend.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key "
        "-CAcreateserial -out /tmp/backend.crt -days 30 -extfile /tmp/extensions"
    )
    for suffix in ("crt", "key"):
        put(
            app,
            f"/run/backend.{suffix}",
            headscale.succeed(f"cat /tmp/backend.{suffix}"),
        )
    app.succeed("systemctl start backend-tls")
    for backend, expected in (
        ("https://localhost:8444", 200),
        ("https://127.0.0.1:8444", 502),
        ("https+insecure://127.0.0.1:8444", 200),
    ):
        app.succeed("systemctl stop tsnet-serve")
        environment(backend=backend)
        app.succeed("systemctl start tsnet-serve")
        direct.wait_until_succeeds(
            request("/allowed/private", "-o /dev/null -w '%{http_code}'")
            + " | grep '^403$'",
            timeout=T,
        )
        status(direct, "/allowed", expected)
        status(relay, "/allowed", expected)
    healthy(direct)
    headscale.succeed(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost "
        "-addext subjectAltName=DNS:localhost -keyout /tmp/untrusted.key -out /tmp/untrusted.crt"
    )
    for suffix in ("crt", "key"):
        put(
            app,
            f"/run/backend.{suffix}",
            headscale.succeed(f"cat /tmp/untrusted.{suffix}"),
        )
    app.succeed("systemctl restart backend-tls")
    app.wait_until_succeeds(
        "curl -fsS --max-time 5 --cacert /run/backend.crt https://localhost:8444/allowed",
        timeout=T,
    )
    for backend, expected in (
        ("https://localhost:8444", 502),
        ("https+insecure://localhost:8444", 200),
    ):
        app.succeed("systemctl stop tsnet-serve")
        environment(backend=backend)
        app.succeed("systemctl start tsnet-serve")
        direct.wait_until_succeeds(
            request("/allowed/private", "-o /dev/null -w '%{http_code}'")
            + " | grep '^403$'",
            timeout=T,
        )
        status(direct, "/allowed", expected)
        status(relay, "/allowed", expected)
        if expected == 502:
            app.succeed(
                "journalctl -u tsnet-serve -o cat | grep 'http: proxy error:.*unknown authority'"
            )
    healthy(direct)

with subtest("invalid configuration fails before joining"):
    cases = [
        ("-listen-port 0", "invalid port"),
        ("-funnel -listen-port 8080", "funnel mode is only available"),
        ("-backend ftp://localhost", "must be a URL starting"),
        ("-allowed-paths '['", "regexp"),
        ("-state-dir /proc/tsnet-serve", "failed to create state directory"),
    ]
    for args, message in cases:
        code, output = app.execute(f"timeout 10 tsnet-serve {args} 2>&1")
        assert code != 0 and code != 124 and message in output, (args, code, output)
    for assignment, message in (
        ("TSNS_LISTEN_PORT=oops", "invalid TSNS_LISTEN_PORT"),
        ("TSNS_FUNNEL=oops", "invalid TSNS_FUNNEL"),
    ):
        code, output = app.execute(f"env {assignment} tsnet-serve 2>&1")
        assert code != 0 and message in output, (assignment, output)
    healthy(direct)
