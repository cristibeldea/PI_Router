#!/usr/bin/env python3
import os
import re
import time
import json
import subprocess
from functools import wraps

from flask import (
    Flask, request, redirect, url_for,
    render_template_string, abort, session, jsonify
)

# ───────────────────────────────────────────
# Config
# ───────────────────────────────────────────
LISTEN = os.environ.get("LISTEN_ADDR", "0.0.0.0")
PORT   = int(os.environ.get("PORT", "8080"))

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeME!")

APP = Flask(__name__)
APP.secret_key = os.environ.get("SECRET_KEY", "ufw-ui-secret-key")

# Regex pentru linii de forma: "[ 12] REGULA ..."
RULE_RE = re.compile(r"^\s*\[\s*(\d+)\]\s+(.*)$")

# ───────────────────────────────────────────
# Utilitare shell
# ───────────────────────────────────────────
def run(cmd, shell=False):
    """Return (rc, stdout, stderr) for a command."""
    if shell:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    else:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

# ───────────────────────────────────────────
# Auth
# ───────────────────────────────────────────
def login_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not session.get("logged"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return _wrap

@APP.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["logged"] = True
            return redirect(url_for("index"))
        return render_template_string(LOGIN_TMPL, error="Credentiale greșite")
    return render_template_string(LOGIN_TMPL)

@APP.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

LOGIN_TMPL = """
<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Autentificare</title>
<style>
body{background:#0f172a;color:#e5e7eb;font-family:system-ui,Segoe UI,Roboto,Arial}
.card{max-width:360px;margin:12vh auto;background:#111827;padding:22px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{font-size:22px;margin:0 0 12px}
input{width:100%;padding:10px 12px;margin:8px 0;border:1px solid #374151;border-radius:8px;background:#0b1220;color:#e5e7eb}
.btn{display:block;width:100%;padding:10px 12px;background:#2563eb;border:none;border-radius:8px;color:white;cursor:pointer;margin-top:10px}
.err{color:#f87171;margin:6px 0}
small{color:#9ca3af}
</style>
<div class=card>
  <h1>Login UFW Admin UI</h1>
  {% if error %}<div class=err>{{ error }}</div>{% endif %}
  <form method=post>
    <input name=username placeholder="utilizator" autofocus>
    <input name=password type=password placeholder="parolă">
    <button class=btn type=submit>Intră</button>
  </form>
  <small>Utilizator & parolă sunt citite din variabilele de mediu <b>ADMIN_USER</b>/<b>ADMIN_PASS</b>.</small>
</div>
"""

# ───────────────────────────────────────────
# UFW helpers
# ───────────────────────────────────────────
def ufw_status():
    rc, out, _ = run(["sudo", "ufw", "status", "verbose"])
    return out if rc == 0 else "Eroare la 'ufw status verbose'"

def ufw_rules_numbered():
    rc, out, _ = run(["sudo", "ufw", "status", "numbered"])
    rules = []
    if rc == 0:
        for line in out.splitlines():
            m = RULE_RE.match(line)
            if m:
                rules.append({"n": int(m.group(1)), "text": m.group(2)})
    # sortare crescătoare după număr (asigurăm [1] la început)
    rules.sort(key=lambda r: r["n"])
    return rules

def ufw_enable():  run(["sudo", "ufw", "enable"], shell=False)
def ufw_disable(): run(["sudo", "ufw", "disable"], shell=False)

def delete_rule_by_number(n: str):
    # confirm automat la delete
    cmd = f"yes | sudo ufw delete {int(n)}"
    rc, out, err = run(cmd, shell=True)
    return rc == 0

def add_rule(action, direction, proto, port, iface=None, src=None):
    """
    Construiește: sudo ufw [route] {allow|deny} {in|out} [on IFACE] [proto tcp/udp] to any port PORT [from SRC]
    Return (rc, msg)
    """
    base = ["sudo", "ufw"]
    if direction == "routed":
        base.append("route")
        direction = "in"  # 'route' folosește 'in/out' pe perechi, aici doar in->out rulează prin 'route allow ...'
    if action not in ("allow", "deny"):        return (1, "Acțiune invalidă")
    if direction not in ("in", "out"):         return (1, "Direcție invalidă")
    if proto not in ("tcp", "udp", "any"):     return (1, "Protocol invalid")
    if not port and proto != "any":            return (1, "Port lipsă")

    cmd = base + [action, direction]
    if iface: cmd += ["on", iface]
    if proto != "any": cmd += ["proto", proto]
    if port: cmd += ["to", "any", "port", port]
    if src:  cmd += ["from", src]

    rc, out, err = run(cmd)
    return (rc, out or err)

# deny/allow routed pentru un IP (blocare internet pentru device)
def block_device(ip):
    return run(["sudo", "ufw", "route", "insert", "1", "deny", "from", ip])

def unblock_device(ip):
    # găsim regula(ile) DENY FWD de la ip și le ștergem după număr
    rc, out, _ = run(["sudo", "ufw", "status", "numbered"])
    if rc != 0:
        return (rc, "nu pot citi regulile")
    # colectăm numerele potrivite
    to_delete = []
    for line in out.splitlines():
        m = RULE_RE.match(line)
        if not m:
            continue
        num = m.group(1)
        txt = m.group(2)
        if ("DENY FWD" in txt) and (ip in txt):
            to_delete.append(int(num))
    # ștergem în ordine descrescătoare (ca să nu se deplaseze numerotarea celor rămase)
    ok = True
    for n in sorted(to_delete, reverse=True):
        cmd = f"yes | sudo ufw delete {n}"
        rc, _, _ = run(cmd, shell=True)
        ok = ok and (rc == 0)
    return (0 if ok else 1, f"șters: {to_delete}" if ok else "eroare la ștergere")

# ───────────────────────────────────────────
# Dispozitive active + viteză Internet
# ───────────────────────────────────────────
def parse_dnsmasq_leases():
    """Returnează {ip: (hostname_or_None, mac)} din leases."""
    leases = {}
    try:
        with open("/var/lib/misc/dnsmasq.leases", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 5:
                    _ts, mac, ip, host, _id = parts[:5]
                    leases[ip] = (None if host == "*" else host, mac.lower())
    except Exception:
        pass
    return leases

def active_devices():
    """
    Dispozitive LIVE: ARP pe br0 + leases dnsmasq.
    Considerăm active toate stările în afară de INCOMPLETE/FAILED (inclusiv STALE).
    """
    leases = parse_dnsmasq_leases()
    rc, out, _ = run(["ip", "neigh", "show", "dev", "br0"])
    devs = []
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+lladdr\s+([0-9a-f:]{17})\s+(\S+)", line, re.I)
            if not m:
                continue
            ip, mac, state = m.group(1), m.group(2).lower(), m.group(3).upper()
            if state in {"INCOMPLETE", "FAILED"}:
                continue
            host = leases.get(ip, (None, mac))[0] or mac
            devs.append({"label": host, "ip": ip, "mac": mac})
    devs.sort(key=lambda d: (str(d["label"]).lower(), d["ip"]))
    return devs

def internet_speed_text():
    """
    Citește viteză cu speedtest-cli (dacă e instalat în venv / sistem).
    Returnează 'indisponibil' dacă nu e disponibil sau a eșuat.
    """
    for exe in ("/home/pi/ufw-web/.venv/bin/speedtest-cli", "speedtest-cli"):
        try:
            rc, out, _ = run([exe, "--secure", "--simple", "--timeout", "10"])
            if rc == 0 and out:
                d = re.search(r"Download:\s+([\d.]+)", out)
                u = re.search(r"Upload:\s+([\d.]+)", out)
                if d and u:
                    return f"{d.group(1)} ↓  {u.group(1)} ↑"
        except FileNotFoundError:
            continue
        except Exception:
            break
    return "indisponibil"

# ───────────────────────────────────────────
# Template UI (dark)
# ───────────────────────────────────────────
TEMPLATE = """
<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>UFW Admin UI</title>
<style>
:root{
  --bg:#0f172a; --panel:#111827; --muted:#9ca3af; --text:#e5e7eb;
  --good:#16a34a; --bad:#ef4444; --blue:#2563eb; --chip:#1f2937;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Roboto,Arial}
.wrap{max-width:1100px;margin:24px auto;padding:0 16px}
h1{font-size:22px;margin:0 0 14px}
.topbar{display:flex;align-items:center;gap:10px;justify-content:space-between}
a.logout{background:#374151;padding:8px 12px;border-radius:10px;color:#cbd5e1;text-decoration:none}
.panel{background:var(--panel);border-radius:14px;padding:14px;margin:12px 0}
.btn{display:inline-block;padding:8px 12px;border-radius:10px;border:0;cursor:pointer;color:#fff}
.btn-green{background:var(--good)} .btn-red{background:var(--bad)} .btn-blue{background:var(--blue)}
.btn-gray{background:#374151}
.table{width:100%;border-collapse:separate;border-spacing:0 10px}
th,td{padding:10px 12px}
.row{background:#0b1220;border:1px solid #1f2937;border-radius:10px}
.badge{background:var(--chip);padding:4px 8px;border-radius:999px;color:#cbd5e1;font-size:12px}
.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
@media (max-width:900px){.grid{grid-template-columns:1fr}}
hr{border:0;border-top:1px solid #1f2937;margin:14px 0}
.input{background:#0b1220;border:1px solid #1f2937;border-radius:10px;color:#e5e7eb;padding:8px 10px}
.small{color:var(--muted);font-size:13px}
</style>

<div class="wrap">
  <div class="topbar">
    <h1>UFW Admin UI</h1>
    <div>
      <a class="logout" href="{{ url_for('logout') }}">Logout</a>
    </div>
  </div>

  <div class="panel" style="display:flex;gap:8px;flex-wrap:wrap">
    <form method="post" action="{{ url_for('toggle') }}" style="display:inline">
      <input type="hidden" name="action" value="enable">
      <button class="btn btn-green" type="submit">Enable</button>
    </form>
    <form method="post" action="{{ url_for('toggle') }}" style="display:inline">
      <input type="hidden" name="action" value="disable">
      <button class="btn btn-red" type="submit">Disable</button>
    </form>
    <form method="post" action="{{ url_for('reboot') }}" style="display:inline" onsubmit="return confirm('Reboot acum?');">
      <button class="btn btn-gray" type="submit">Reboot router</button>
    </form>
    <span class="small" style="margin-left:8px;">Status UFW & detalii mai jos.</span>
  </div>

  <div class="grid">
    <!-- Reguli UFW -->
    <div class="panel">
      <h2 style="margin:6px 0 10px">Reguli UFW</h2>

      <table class="table">
        <thead><tr><th>#</th><th>Regulă</th><th></th></tr></thead>
        <tbody>
          {% for r in ufw_rules %}
          <tr class="row">
            <td width="60"><span class="badge">[{{ r.n }}]</span></td>
            <td><code style="color:#d1d5db">{{ r.text }}</code></td>
            <td width="90">
              <form method="post" action="{{ url_for('delete') }}" onsubmit="return confirm('Ștergi regula #{{ r.n }}?');">
                <input type="hidden" name="numar" value="{{ r.n }}">
                <button class="btn btn-red" type="submit">Șterge</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>

      <hr>
      <h3 style="margin:8px 0">Adaugă regulă</h3>
      <form method="post" action="{{ url_for('add') }}" style="display:flex;gap:8px;flex-wrap:wrap">
        <select class="input" name="rule_action">
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
        <select class="input" name="direction">
          <option value="in">in</option>
          <option value="out">out</option>
          <option value="routed">routed</option>
        </select>
        <select class="input" name="proto">
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="any">any</option>
        </select>
        <input class="input" name="port" placeholder="port (ex: 22 sau 80,443)">
        <input class="input" name="iface" placeholder="interfață (ex: br0)">
        <input class="input" name="src" placeholder="from (ex: 192.168.50.141)">
        <button class="btn btn-blue" type="submit">Adaugă</button>
      </form>
    </div>

    <!-- Dispozitive + Internet -->
    <div class="panel">
      <h2 style="margin:6px 0 10px">Dispozitive ACTIVE</h2>
      <div id="devices" class="small" style="min-height:40px;color:#cbd5e1">— încărcare… —</div>
      <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
        <button class="btn btn-blue" onclick="loadDevices(); loadSpeed();">Actualizează + viteză</button>
        <div id="speed" class="small">Internet: —</div>
      </div>

      <hr>
      <h3 style="margin:8px 0">Blocare / Deblocare IP (trafic „routed”)</h3>
      <form method="post" action="{{ url_for('block') }}" style="display:flex;gap:8px;flex-wrap:wrap">
        <input class="input" name="ip" placeholder="IP (ex: 192.168.50.141)">
        <button class="btn btn-red" type="submit">Blochează</button>
      </form>
      <form method="post" action="{{ url_for('unblock') }}" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
        <input class="input" name="ip" placeholder="IP (ex: 192.168.50.141)">
        <button class="btn btn-blue" type="submit">Deblochează</button>
      </form>
    </div>
  </div>
</div>

<script>
async function loadDevices(){
  try{
    const r = await fetch("{{ url_for('devices_json') }}", {cache:"no-store"});
    const data = await r.json();
    const el = document.querySelector("#devices");
    if (!Array.isArray(data) || !data.length){
      el.innerHTML = "<span class='small' style='color:#9ca3af'>— nimic activ acum —</span>";
      return;
    }
    el.innerHTML = data.map(d =>
      `<div style="padding:6px 0;border-bottom:1px solid #1f2937">
         <span class="badge">${d.label || d.mac}</span>
         <code style="margin-left:8px;color:#93c5fd">${d.ip}</code>
         <code style="margin-left:8px;color:#a7f3d0">${d.mac}</code>
       </div>`
    ).join("");
  }catch(e){
    document.querySelector("#devices").textContent = "eroare încărcare";
  }
}
async function loadSpeed(){
  try{
    const r = await fetch("{{ url_for('speed_json') }}", {cache:"no-store"});
    const data = await r.json();
    document.querySelector("#speed").textContent = "Internet: " + (data.internet || "indisponibil");
  }catch(e){
    document.querySelector("#speed").textContent = "Internet: indisponibil";
  }
}
// Încarcă automat la intrarea în pagină
loadDevices(); loadSpeed();
</script>
"""

# ───────────────────────────────────────────
# Rute
# ───────────────────────────────────────────
@APP.get("/")
@login_required
def index():
    return render_template_string(
        TEMPLATE,
        ufw_rules=ufw_rules_numbered(),
    )

@APP.post("/toggle")
@login_required
def toggle():
    action = request.form.get("action", "")
    if action == "enable":
        ufw_enable()
    elif action == "disable":
        ufw_disable()
    return redirect(url_for("index"))

@APP.post("/add")
@login_required
def add():
    rc, msg = add_rule(
        request.form.get("rule_action","allow"),
        request.form.get("direction","in"),
        request.form.get("proto","tcp"),
        request.form.get("port",""),
        request.form.get("iface") or None,
        request.form.get("src") or None,
    )
    if rc != 0:
        return (f"Eroare: {msg}", 400)
    return redirect(url_for("index"))

@APP.post("/delete")
@login_required
def delete():
    n = request.form.get("numar", "")
    if not n or not n.isdigit():
        abort(400, "Număr invalid")
    ok = delete_rule_by_number(n)
    if not ok:
        abort(400, "Ștergere eșuată")
    return redirect(url_for("index"))

@APP.post("/block")
@login_required
def block():
    ip = request.form.get("ip", "").strip()
    if not ip:
        abort(400, "Lipsește IP")
    rc, msg = block_device(ip)
    if rc != 0:
        return (f"Eroare: {msg}", 400)
    return redirect(url_for("index"))

@APP.post("/unblock")
@login_required
def unblock():
    ip = request.form.get("ip", "").strip()
    if not ip:
        abort(400, "Lipsește IP")
    rc, msg = unblock_device(ip)
    if rc != 0:
        return (f"Eroare: {msg}", 400)
    return redirect(url_for("index"))

@APP.post("/reboot")
@login_required
def reboot():
    run(["sudo","/sbin/reboot"])
    return "Rebooting…", 200

# JSON APIs pentru UI
@APP.get("/devices")
@login_required
def devices_json():
    return jsonify(active_devices())

@APP.get("/speed")
@login_required
def speed_json():
    return jsonify({"internet": internet_speed_text()})

# ───────────────────────────────────────────
# Entrypoint
# ───────────────────────────────────────────
if __name__ == "__main__":
    print(f"[*] UFW Admin UI la http://{LISTEN}:{PORT}")
    APP.run(host=LISTEN, port=PORT)
