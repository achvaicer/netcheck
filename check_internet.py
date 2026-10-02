#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_internet.py - Verifica a conexão com a internet (somente biblioteca padrão).

Testes realizados:
  1. DNS   - resolução de nomes
  2. TCP   - conexão direta a IPs públicos (independe de DNS)
  3. HTTP  - requisição a endpoint que responde 204 (detecta captive portal/proxy)

Saídas (em --dir):
  status.json  - último resultado (sobrescrito a cada execução)
  history.log  - histórico, uma linha JSON por execução (com rotação)
  index.html   - página de status pronta para ser servida por qualquer web server

Opcional: --report-url envia o resultado (HTTP POST + token Bearer) para um
servidor que hospeda a página pública (status_server.py ou o Worker em netcheck-worker/). O payload enviado
NÃO inclui hostname nem IP local, apenas o --label escolhido. Se o envio falhar
(ex.: internet fora do ar), o resultado fica em fila (pending.jsonl) e é reenviado
na próxima execução bem-sucedida, preservando o horário original do teste.

Códigos de saída: 0 = ONLINE | 1 = DEGRADED/CAPTIVE_PORTAL | 2 = OFFLINE | 3 = já em execução

Exemplo de cron (a cada 5 minutos):
  */5 * * * * /usr/bin/python3 /wfs/netcheck/check_internet.py --dir /wfs/netcheck/out
"""

import argparse
import fcntl
import html
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ----------------------------- Configuração padrão -----------------------------
DNS_HOSTS = ["google.com", "cloudflare.com", "microsoft.com"]
TCP_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)]
HTTP_URL = "http://connectivitycheck.gstatic.com/generate_204"
TIMEOUT = 3.0                      # segundos por teste
HISTORY_MAX_BYTES = 256 * 1024     # rotação do histórico
HISTORY_KEEP_LINES = 500
HTML_HISTORY_ROWS = 30
MAX_PENDING = 200                  # máximo de resultados em fila durante uma queda
# -------------------------------------------------------------------------------


def with_timeout(fn, timeout, *args):
    """Executa fn com limite de tempo (getaddrinfo não possui timeout próprio)."""
    box = {}

    def run():
        try:
            box["result"] = fn(*args)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("timeout")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def timed(fn, *args):
    """Retorna (ok, latência_ms, erro)."""
    start = time.monotonic()
    try:
        fn(*args)
        return True, round((time.monotonic() - start) * 1000), None
    except Exception as exc:  # noqa: BLE001
        return False, None, f"{type(exc).__name__}: {exc}"


def check_dns(host, timeout):
    return timed(lambda: with_timeout(
        socket.getaddrinfo, timeout, host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM))


def check_tcp(host, port, timeout):
    def connect():
        socket.create_connection((host, port), timeout=timeout).close()
    return timed(connect)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # não segue redirects: redirect = provável captive portal


def check_http(url, timeout):
    """Retorna (código_http|None, latência_ms|None, erro|None)."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "netcheck/1.0"})
    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except Exception as exc:  # noqa: BLE001
        return None, None, f"{type(exc).__name__}: {exc}"
    return code, round((time.monotonic() - start) * 1000), None


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # não envia pacotes
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa: BLE001
        return None


def run_checks(timeout):
    dns = []
    for host in DNS_HOSTS:
        ok, ms, err = check_dns(host, timeout)
        dns.append({"target": host, "ok": ok, "ms": ms, "error": err})

    tcp = []
    for host, port in TCP_TARGETS:
        ok, ms, err = check_tcp(host, port, timeout)
        tcp.append({"target": f"{host}:{port}", "ok": ok, "ms": ms, "error": err})

    code, ms, err = check_http(HTTP_URL, timeout)
    http = {"target": HTTP_URL, "code": code, "ms": ms, "error": err, "ok": code == 204}

    dns_ok = any(d["ok"] for d in dns)
    tcp_ok = any(t["ok"] for t in tcp)

    if http["ok"] and dns_ok:
        status = "ONLINE"
    elif code is not None and not http["ok"]:
        status = "CAPTIVE_PORTAL"   # respondeu, mas não com 204 (login/proxy)
    elif http["ok"] or tcp_ok or dns_ok:
        status = "DEGRADED"
    else:
        status = "OFFLINE"

    latencies = [x["ms"] for x in tcp if x["ok"]]
    return {
        "status": status,
        "dns_ok": dns_ok,
        "tcp_ok": tcp_ok,
        "http_ok": http["ok"],
        "best_tcp_latency_ms": min(latencies) if latencies else None,
        "dns": dns,
        "tcp": tcp,
        "http": http,
    }


def atomic_write(path, content):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def append_history(path, entry):
    try:
        if os.path.exists(path) and os.path.getsize(path) > HISTORY_MAX_BYTES:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-HISTORY_KEEP_LINES:]
            atomic_write(path, "".join(lines))
    except OSError:
        pass
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_history(path, n):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        return [json.loads(l) for l in lines if l.strip()][::-1]
    except (OSError, ValueError):
        return []


COLORS = {"ONLINE": "#1a9a4b", "DEGRADED": "#e0a800",
          "CAPTIVE_PORTAL": "#e0a800", "OFFLINE": "#d9342b"}


def render_html(result, history):
    esc = html.escape
    color = COLORS.get(result["status"], "#666")
    rows = "".join(
        f"<tr><td>{esc(h['timestamp_local'])}</td>"
        f"<td style='color:{COLORS.get(h['status'], '#666')};font-weight:600'>{esc(h['status'])}</td>"
        f"<td>{h.get('best_tcp_latency_ms') or '-'}</td></tr>"
        for h in history
    )
    detail_rows = ""
    for group, label in (("dns", "DNS"), ("tcp", "TCP")):
        for item in result[group]:
            mark = "OK" if item["ok"] else "FALHA"
            detail_rows += (f"<tr><td>{label}</td><td>{esc(item['target'])}</td>"
                            f"<td>{mark}</td><td>{item['ms'] or '-'}</td></tr>")
    h = result["http"]
    detail_rows += (f"<tr><td>HTTP</td><td>{esc(h['target'])}</td>"
                    f"<td>{'OK' if h['ok'] else 'FALHA'} ({h['code'] or 'sem resposta'})</td>"
                    f"<td>{h['ms'] or '-'}</td></tr>")

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="60">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Status de conexão - {esc(result['hostname'])}</title>
<style>
 body{{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#222}}
 .badge{{display:inline-block;padding:.4rem 1rem;border-radius:.5rem;color:#fff;
        background:{color};font-size:1.6rem;font-weight:700}}
 table{{border-collapse:collapse;margin:1rem 0}} td,th{{border:1px solid #ddd;padding:.3rem .7rem;text-align:left}}
 th{{background:#f3f3f3}} .muted{{color:#777}}
</style></head><body>
<h1>Status da conexão</h1>
<p><span class="badge">{esc(result['status'])}</span></p>
<p>Host: <b>{esc(result['hostname'])}</b> &middot; IP local: <b>{esc(str(result['local_ip']))}</b><br>
Última execução: <b>{esc(result['timestamp_local'])}</b>
<span class="muted">({esc(result['timestamp_utc'])})</span><br>
Duração do teste: {result['duration_ms']} ms</p>
<h2>Detalhes</h2>
<table><tr><th>Teste</th><th>Alvo</th><th>Resultado</th><th>ms</th></tr>{detail_rows}</table>
<h2>Histórico recente</h2>
<table><tr><th>Data/hora</th><th>Status</th><th>Latência TCP (ms)</th></tr>{rows}</table>
</body></html>"""


def build_payload(result, label, interval_min):
    """Payload enviado ao servidor público: sem IP local e sem hostname."""
    return {
        "label": label,
        "status": result["status"],
        "epoch": result["epoch"],
        "timestamp_utc": result["timestamp_utc"],
        "best_tcp_latency_ms": result["best_tcp_latency_ms"],
        "dns_ok": result["dns_ok"],
        "tcp_ok": result["tcp_ok"],
        "http_ok": result["http_ok"],
        "interval_min": interval_min,
    }


def report(url, payload, timeout, token=None):
    """Retorna (ok, erro, descartar). descartar=True para rejeições definitivas (4xx)."""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "netcheck/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 400, None, False
    except urllib.error.HTTPError as exc:
        permanent = 400 <= exc.code < 500 and exc.code not in (401, 403, 408, 429)
        try:
            body = exc.read(200).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            body = ""
        return False, f"HTTP {exc.code}" + (f": {body}" if body else ""), permanent
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}", False


def load_pending(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


def save_pending(path, items):
    if items:
        atomic_write(path, "".join(json.dumps(i, ensure_ascii=False) + "\n"
                                   for i in items[-MAX_PENDING:]))
    elif os.path.exists(path):
        os.remove(path)


def flush_reports(url, token, pending_path, payload, timeout):
    """Envia pendências (mais antigas primeiro) e o resultado atual.
    Para na primeira falha temporária para não acumular timeouts."""
    queue = load_pending(pending_path) + [payload]
    done, err = 0, None
    for item in queue:
        ok, err, drop = report(url, item, timeout, token)
        if ok or drop:          # enviado, ou rejeitado em definitivo (não reenviar)
            done += 1
            continue
        break
    save_pending(pending_path, queue[done:])
    return {"url": url, "ok": done == len(queue), "sent": done,
            "pending": len(queue) - done, "error": err if done < len(queue) else None}


def main():
    parser = argparse.ArgumentParser(description="Verifica conectividade com a internet.")
    parser.add_argument("--dir", default=os.environ.get("NETCHECK_DIR", "/tmp/netcheck"),
                        help="diretório de saída (padrão: /tmp/netcheck ou $NETCHECK_DIR)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="timeout por teste (s)")
    parser.add_argument("--report-url", default=os.environ.get("NETCHECK_REPORT_URL"),
                        help="URL do servidor de status (ex.: https://status.exemplo.com/report)")
    parser.add_argument("--token", default=os.environ.get("NETCHECK_TOKEN"),
                        help="token de autenticação do servidor (ou $NETCHECK_TOKEN)")
    parser.add_argument("--label", default=os.environ.get("NETCHECK_LABEL"),
                        help="nome público deste equipamento (padrão: hostname)")
    parser.add_argument("--interval", type=int, default=5,
                        help="intervalo do cron em minutos (usado para detectar falta de contato)")
    parser.add_argument("--quiet", action="store_true", help="não imprime nada no stdout")
    args = parser.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    # Evita execuções sobrepostas caso o cron dispare antes da anterior terminar
    lock_file = open(os.path.join(args.dir, ".lock"), "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 3

    started = time.monotonic()
    result = run_checks(args.timeout)

    now_local = datetime.now().astimezone()
    result.update({
        "hostname": socket.gethostname(),
        "local_ip": local_ip(),
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_local": now_local.strftime("%d/%m/%Y %H:%M:%S %Z"),
        "epoch": int(time.time()),
        "duration_ms": round((time.monotonic() - started) * 1000),
    })

    history_path = os.path.join(args.dir, "history.log")
    append_history(history_path, {
        "timestamp_local": result["timestamp_local"],
        "epoch": result["epoch"],
        "status": result["status"],
        "best_tcp_latency_ms": result["best_tcp_latency_ms"],
    })

    if args.report_url:
        label = args.label or result["hostname"]
        payload = build_payload(result, label, args.interval)
        result["report"] = flush_reports(
            args.report_url, args.token,
            os.path.join(args.dir, "pending.jsonl"), payload, args.timeout)

    atomic_write(os.path.join(args.dir, "status.json"),
                 json.dumps(result, indent=2, ensure_ascii=False))
    atomic_write(os.path.join(args.dir, "index.html"),
                 render_html(result, read_history(history_path, HTML_HISTORY_ROWS)))

    if not args.quiet:
        print(f"[{result['timestamp_local']}] {result['status']} "
              f"(dns={result['dns_ok']} tcp={result['tcp_ok']} http={result['http_ok']})")
        rep_info = result.get("report")
        if rep_info:
            if rep_info["ok"]:
                print(f"  envio ao servidor: OK ({rep_info['sent']} enviado(s))")
            else:
                print(f"  envio ao servidor: FALHOU - {rep_info['error']} "
                      f"({rep_info['pending']} na fila)")

    return {"ONLINE": 0, "DEGRADED": 1, "CAPTIVE_PORTAL": 1, "OFFLINE": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
