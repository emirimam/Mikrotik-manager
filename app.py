from flask import Flask, render_template, request, jsonify, Response
import paramiko
import threading
import queue
import json
import time
import socket
import io
import re
import ftplib
import traceback
from datetime import datetime

app = Flask(__name__)

TEMPLATES = {
    # ── Firewall / Routing ────────────────────────────────────────────────────
    "fw_block_ip": {
        "name": "Block IP Address",
        "category": "Firewall / Routing",
        "params": [{"name": "ip_address", "label": "IP Address to Block", "placeholder": "1.2.3.4"}],
        "commands": '/ip firewall address-list add list=blacklist address={ip_address} comment="Blocked via manager"'
    },
    "fw_unblock_ip": {
        "name": "Remove IP from Blacklist",
        "category": "Firewall / Routing",
        "params": [{"name": "ip_address", "label": "IP Address", "placeholder": "1.2.3.4"}],
        "commands": "/ip firewall address-list remove [find where address={ip_address}]"
    },
    "dns_set": {
        "name": "Set DNS Servers",
        "category": "Firewall / Routing",
        "params": [
            {"name": "primary",   "label": "Primary DNS",   "placeholder": "8.8.8.8"},
            {"name": "secondary", "label": "Secondary DNS", "placeholder": "8.8.4.4"}
        ],
        "commands": "/ip dns set servers={primary},{secondary} allow-remote-requests=yes"
    },
    "ntp_set": {
        "name": "Set NTP Server",
        "category": "Firewall / Routing",
        "params": [{"name": "ntp_server", "label": "NTP Server", "placeholder": "pool.ntp.org"}],
        "commands": "/system ntp client set enabled=yes servers={ntp_server}"
    },

    # ── Update / Upgrade ──────────────────────────────────────────────────────
    "sys_check_update": {
        "name": "Check for Updates",
        "category": "Update / Upgrade",
        "params": [],
        "commands": "/system package update check-for-updates"
    },
    "sys_upgrade": {
        "name": "Install Update (reboot!)",
        "category": "Update / Upgrade",
        "params": [],
        "commands": "/system package update check-for-updates\n/system package update install"
    },
    "sys_reboot": {
        "name": "Reboot Device",
        "category": "Update / Upgrade",
        "params": [],
        "commands": "/system reboot"
    },
    "sys_info": {
        "name": "System Info",
        "category": "Update / Upgrade",
        "params": [],
        "commands": "/system resource print\n/system identity print\n/system routerboard print"
    },

    # ── WiFi ──────────────────────────────────────────────────────────────────
    "wifi_ssid_24": {
        "name": "Change WiFi SSID – 2.4 GHz",
        "category": "WiFi",
        "params": [
            {"name": "ssid",     "label": "New SSID",    "placeholder": "MyWiFi"},
            {"name": "password", "label": "WiFi Password", "placeholder": "StrongPass123"}
        ],
        "commands": (
            "/interface wireless set [find where band=2ghz-b/g/n or band=2ghz-g/n or band=2ghz-onlyn or band=2ghz-b/g] ssid={ssid}\n"
            "/interface wireless security-profiles set [find where name=default] "
            "wpa-pre-shared-key={password} wpa2-pre-shared-key={password} "
            "mode=dynamic-keys authentication-types=wpa2-psk"
        )
    },
    "wifi_ssid_5": {
        "name": "Change WiFi SSID – 5 GHz",
        "category": "WiFi",
        "params": [
            {"name": "ssid",     "label": "New SSID",    "placeholder": "MyWiFi-5G"},
            {"name": "password", "label": "WiFi Password", "placeholder": "StrongPass123"}
        ],
        "commands": (
            "/interface wireless set [find where band=5ghz-a/n/ac or band=5ghz-onlyn or band=5ghz-a/n] ssid={ssid}\n"
            "/interface wireless security-profiles set [find where name=default] "
            "wpa-pre-shared-key={password} wpa2-pre-shared-key={password} "
            "mode=dynamic-keys authentication-types=wpa2-psk"
        )
    },
    "wifi_ssid_both": {
        "name": "Change SSID – Both Bands (2.4 + 5)",
        "category": "WiFi",
        "params": [
            {"name": "ssid24",   "label": "SSID 2.4 GHz",  "placeholder": "MyWiFi"},
            {"name": "ssid5",    "label": "SSID 5 GHz",    "placeholder": "MyWiFi-5G"},
            {"name": "password", "label": "WiFi Password (both bands)", "placeholder": "StrongPass123"}
        ],
        "commands": (
            "/interface wireless set [find where band=2ghz-b/g/n or band=2ghz-g/n or band=2ghz-onlyn or band=2ghz-b/g] ssid={ssid24}\n"
            "/interface wireless set [find where band=5ghz-a/n/ac or band=5ghz-onlyn or band=5ghz-a/n] ssid={ssid5}\n"
            "/interface wireless security-profiles set [find] wpa-pre-shared-key={password} wpa2-pre-shared-key={password} mode=dynamic-keys authentication-types=wpa2-psk"
        )
    },
    "wifi_disable": {
        "name": "Disable WiFi Interface",
        "category": "WiFi",
        "params": [],
        "commands": "/interface wireless disable [find]"
    },
    "wifi_enable": {
        "name": "Enable WiFi Interface",
        "category": "WiFi",
        "params": [],
        "commands": "/interface wireless enable [find]"
    },
    "wifi_password_only": {
        "name": "Change WiFi Password Only",
        "category": "WiFi",
        "params": [
            {"name": "password", "label": "New WiFi Password", "placeholder": "StrongPass123"}
        ],
        "commands": (
            "/interface wireless security-profiles set [find] "
            "wpa-pre-shared-key={password} wpa2-pre-shared-key={password} "
            "mode=dynamic-keys authentication-types=wpa2-psk"
        )
    },
    "wifi_info": {
        "name": "Show WiFi Configuration",
        "category": "WiFi",
        "params": [],
        "commands": "/interface wireless print\n/interface wireless security-profiles print"
    },

    # ── IP / WAN ──────────────────────────────────────────────────────────────
    "wan_set_static": {
        "name": "Set Static WAN IP Address",
        "category": "IP / WAN",
        "params": [
            {"name": "iface",    "label": "WAN Interface",   "placeholder": "ether1"},
            {"name": "ip",       "label": "New IP Address",  "placeholder": "203.0.113.10"},
            {"name": "prefix",   "label": "Prefix (CIDR)",   "placeholder": "24"},
            {"name": "gw",       "label": "Gateway",         "placeholder": "203.0.113.1"}
        ],
        "commands": (
            "/ip address remove [find where interface={iface}]\n"
            "/ip address add address={ip}/{prefix} interface={iface}\n"
            "/ip route remove [find where dst-address=0.0.0.0/0]\n"
            "/ip route add dst-address=0.0.0.0/0 gateway={gw}"
        )
    },
    "wan_set_dhcp": {
        "name": "Set WAN to DHCP Client",
        "category": "IP / WAN",
        "params": [
            {"name": "iface", "label": "WAN Interface", "placeholder": "ether1"}
        ],
        "commands": (
            "/ip address remove [find where interface={iface}]\n"
            "/ip dhcp-client add interface={iface} disabled=no add-default-route=yes use-peer-dns=yes"
        )
    },
    "wan_show": {
        "name": "Show IP Addresses & Routes",
        "category": "IP / WAN",
        "params": [],
        "commands": "/ip address print\n/ip route print where dst-address=0.0.0.0/0"
    },

    # ── Queue / Brzina ────────────────────────────────────────────────────────
    "queue_add": {
        "name": "Add Simple Queue (limit speed)",
        "category": "Queue / Brzina",
        "params": [
            {"name": "name",   "label": "Queue Name",      "placeholder": "User-01"},
            {"name": "target", "label": "IP Address / Subnet", "placeholder": "192.168.1.100"},
            {"name": "dl",     "label": "Download Limit",     "placeholder": "10M"},
            {"name": "ul",     "label": "Upload Limit",       "placeholder": "5M"}
        ],
        "commands": "/queue simple add name={name} target={target} max-limit={ul}/{dl}"
    },
    "queue_remove": {
        "name": "Remove Simple Queue by Name",
        "category": "Queue / Brzina",
        "params": [
            {"name": "name", "label": "Queue Name", "placeholder": "User-01"}
        ],
        "commands": "/queue simple remove [find where name={name}]"
    },
    "queue_change": {
        "name": "Change Existing Queue Speed",
        "category": "Queue / Brzina",
        "params": [
            {"name": "name", "label": "Queue Name", "placeholder": "User-01"},
            {"name": "dl",   "label": "New Download", "placeholder": "20M"},
            {"name": "ul",   "label": "New Upload",   "placeholder": "10M"}
        ],
        "commands": "/queue simple set [find where name={name}] max-limit={ul}/{dl}"
    },
    "queue_list": {
        "name": "Show All Queues",
        "category": "Queue / Brzina",
        "params": [],
        "commands": "/queue simple print"
    },

    # ── Svašta ────────────────────────────────────────────────────────────────
    "custom": {
        "name": "Custom Command",
        "category": "Svašta",
        "params": [
            {"name": "custom_commands", "label": "RouterOS Commands (one per line)",
             "placeholder": "/ip address print\n/system identity print", "multiline": True}
        ],
        "commands": "{custom_commands}"
    }
}


def ssh_connect(host, port, username, password, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=int(port), username=username, password=password,
                   timeout=timeout, look_for_keys=False, allow_agent=False)
    return client


def ssh_run(client, cmd, timeout=15):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace').strip()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    return out, err


def ssh_execute(host, port, username, password, commands, timeout=15):
    results = []
    try:
        client = ssh_connect(host, port, username, password, timeout)
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            out, err = ssh_run(client, cmd, timeout)
            results.append({"command": cmd, "output": out, "error": err, "success": not bool(err)})
        client.close()
        return {"connected": True, "results": results}
    except paramiko.AuthenticationException:
        return {"connected": False, "error": "Greška autentikacije – pogrešno korisničko ime ili lozinka"}
    except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError):
        return {"connected": False, "error": "Timeout – uređaj nije dostupan ili je SSH zatvoren"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def upload_sftp(file_bytes, host, port, user, pwd, folder, filename, timeout=30):
    """Upload file via SFTP. Returns (success, detail_msg)."""
    try:
        cl = paramiko.SSHClient()
        cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cl.connect(hostname=host, port=int(port), username=user, password=pwd,
                   timeout=timeout, look_for_keys=False, allow_agent=False)
        sftp = cl.open_sftp()

        # Rekurzivno kreiraj folder
        folder = folder.rstrip('/')
        parts = [p for p in folder.split('/') if p]
        current = "/"
        for part in parts:
            current = f"{current}{part}/"
            try:
                sftp.stat(current)
            except FileNotFoundError:
                sftp.mkdir(current)

        dest = f"{folder}/{filename}"
        file_bytes.seek(0)
        sftp.putfo(file_bytes, dest)
        size = sftp.stat(dest).st_size
        sftp.close()
        cl.close()
        return True, f"Snimljeno: {dest} ({size:,} bytes) na {host}:{port}"
    except paramiko.AuthenticationException:
        return False, f"SFTP autentikacija neuspješna za {user}@{host}:{port}"
    except Exception as e:
        return False, f"SFTP greška: {type(e).__name__}: {e}"


def upload_ftp(file_bytes, host, port, user, pwd, folder, filename, timeout=30):
    """Upload file via plain FTP. Returns (success, detail_msg)."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, int(port), timeout=timeout)
        ftp.login(user, pwd)

        # Navigiraj/kreiraj folder
        folder = folder.rstrip('/')
        parts = [p for p in folder.split('/') if p]
        for part in parts:
            try:
                ftp.cwd(part)
            except ftplib.error_perm:
                ftp.mkd(part)
                ftp.cwd(part)

        file_bytes.seek(0)
        ftp.storbinary(f"STOR {filename}", file_bytes)
        ftp.quit()
        return True, f"Snimljeno: {folder}/{filename} na {host}:{port}"
    except ftplib.error_perm as e:
        return False, f"FTP greška dozvola: {e}"
    except Exception as e:
        return False, f"FTP greška: {type(e).__name__}: {e}"


def export_and_upload(host, port, username, password,
                      srv_host, srv_port, srv_user, srv_pass, srv_folder,
                      protocol, delete_after, timeout=30):
    steps = []
    client = None

    def ok(step, label, detail=""):
        steps.append({"step": step, "label": label, "detail": detail, "success": True})

    def err(step, label, detail=""):
        steps.append({"step": step, "label": label, "detail": detail, "success": False})

    def fail(step, label, detail=""):
        err(step, label, detail)
        return {"connected": True, "host": host, "steps": steps, "success": False}

    try:
        # ── 1: SSH konekcija ─────────────────────────────────────────────
        try:
            client = ssh_connect(host, port, username, password, timeout)
            ok("connect", "SSH konekcija na MikroTik", f"Spojeno na {host}:{port}")
        except paramiko.AuthenticationException:
            err("connect", "SSH konekcija na MikroTik", "Greška autentikacije – pogrešno ime/lozinka")
            return {"connected": False, "host": host, "steps": steps, "success": False}
        except Exception as e:
            err("connect", "SSH konekcija na MikroTik", f"Ne mogu se spojiti: {e}")
            return {"connected": False, "host": host, "steps": steps, "success": False}

        # ── 2: Identity ime rutera ───────────────────────────────────────
        try:
            out, _ = ssh_run(client, "/system identity print", timeout)
            identity = "router"
            for line in out.splitlines():
                if "name:" in line.lower():
                    identity = line.split(":", 1)[-1].strip()
                    break
            identity = re.sub(r'[^\w\-]', '_', identity)
            ok("identity", "Čitanje identity imena rutera", f"Ime: {identity}")
        except Exception as e:
            return fail("identity", "Čitanje identity imena rutera", f"Greška: {e}")

        # ── 3: Export konfiguracije ──────────────────────────────────────
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        export_name = f"{identity}-{ts}"
        remote_rsc = f"{export_name}.rsc"
        try:
            # Export u fajl na ruteru
            out, ssh_err = ssh_run(client, f"/export file={export_name}", timeout)
            time.sleep(2)  # Sačekaj da ruter završi pisanje

            # Provjeri da li fajl postoji
            file_list, _ = ssh_run(client, "/file print", timeout)
            if export_name not in file_list:
                return fail("export_create", "Export konfiguracije na ruteru",
                            f"Fajl {remote_rsc} nije pronađen. SSH out: {out!r} | err: {ssh_err!r} | /file: {file_list[:300]}")
            ok("export_create", "Export konfiguracije na ruteru",
               f"Fajl: {remote_rsc} | {out.strip() or '(bez poruke)'}")
        except Exception as e:
            return fail("export_create", "Export konfiguracije na ruteru", f"Iznimka: {e}")

        # ── 4: Preuzimanje export fajla via SFTP ────────────────────────
        export_bytes = io.BytesIO()
        try:
            sftp_mt = client.open_sftp()
            ok("sftp_open", "Otvaranje SFTP sesije na MikroTiku", "SFTP sesija otvorena")

            # Listaj dostupne fajlove
            try:
                sftp_files = sftp_mt.listdir(".")
                relevant = [f for f in sftp_files if export_name in f or f.endswith('.rsc')]
                ok("sftp_list", "Listanje SFTP direktorija", f"RSC fajlovi: {relevant}")
            except Exception as le:
                ok("sftp_list", "Listanje SFTP direktorija", f"Listanje neuspješno: {le}")
                sftp_files = []

            # Pokušaj sve moguće putanje
            candidates = [remote_rsc, f"flash/{remote_rsc}", f"/{remote_rsc}"]
            candidates += [f for f in sftp_files if export_name in f]
            tried, downloaded, actual_path = [], False, remote_rsc

            for path in candidates:
                if path in tried:
                    continue
                tried.append(path)
                try:
                    export_bytes.seek(0)
                    export_bytes.truncate(0)
                    sftp_mt.getfo(path, export_bytes)
                    if export_bytes.tell() > 0:
                        downloaded = True
                        actual_path = path
                        break
                except Exception:
                    pass

            sftp_mt.close()

            if not downloaded:
                return fail("download", "Preuzimanje export fajla sa rutera",
                            f"Fajl nije pronađen. Pokušano: {tried}. SFTP sadržaj: {sftp_files[:20]}")

            size = export_bytes.tell()
            export_bytes.seek(0)
            ok("download", "Preuzimanje export fajla sa rutera",
               f"Preuzeto {size:,} bytes s putanje: {actual_path}")
        except Exception as e:
            return fail("download", "Preuzimanje export fajla sa rutera",
                        f"SFTP greška: {type(e).__name__}: {e}")

        # ── 5: Brisanje export fajla s rutera (opciono) ─────────────────
        if delete_after:
            try:
                ssh_run(client, f"/file remove [find name={remote_rsc}]", timeout)
                time.sleep(1)
                check, _ = ssh_run(client, f"/file print where name={remote_rsc}", timeout)
                if remote_rsc in check:
                    err("delete_local", "Brisanje export fajla s rutera",
                        f"Fajl još postoji nakon brisanja")
                else:
                    ok("delete_local", "Brisanje export fajla s rutera",
                       f"Fajl {remote_rsc} uspješno obrisan s rutera")
            except Exception as e:
                err("delete_local", "Brisanje export fajla s rutera", f"Greška: {e}")
        else:
            ok("delete_local", "Brisanje export fajla s rutera",
               "Preskočeno – checkbox nije označen, fajl ostaje na ruteru")

        client.close()
        client = None

        # ── 6: Upload na server ──────────────────────────────────────────
        proto_label = "SFTP" if protocol == "sftp" else "FTP"
        try:
            if protocol == "sftp":
                success, detail = upload_sftp(export_bytes, srv_host, srv_port,
                                              srv_user, srv_pass, srv_folder, remote_rsc, timeout)
            else:
                success, detail = upload_ftp(export_bytes, srv_host, srv_port,
                                             srv_user, srv_pass, srv_folder, remote_rsc, timeout)

            if success:
                ok("upload", f"Upload na server ({proto_label})", detail)
                dest_path = f"{srv_folder.rstrip('/')}/{remote_rsc}"
            else:
                return fail("upload", f"Upload na server ({proto_label})", detail)
        except Exception as e:
            return fail("upload", f"Upload na server ({proto_label})",
                        f"Neočekivana greška: {traceback.format_exc()}")

        return {
            "connected": True, "host": host, "steps": steps,
            "success": True, "filename": remote_rsc, "dest": dest_path
        }

    except Exception as e:
        err("unexpected", "Neočekivana greška", traceback.format_exc())
        if client:
            try: client.close()
            except: pass
        return {"connected": False, "host": host, "steps": steps, "success": False}


def build_commands(template_id, params):
    template = TEMPLATES.get(template_id)
    if not template:
        return []
    command_str = template["commands"]
    if template_id == "custom":
        raw = params.get("custom_commands", "")
        return [line for line in raw.splitlines() if line.strip()]
    for key, value in params.items():
        command_str = command_str.replace("{" + key + "}", value)
    return [line for line in command_str.splitlines() if line.strip()]


@app.route("/")
def index():
    return render_template("index.html", templates=TEMPLATES)


@app.route("/api/templates")
def get_templates():
    return jsonify(TEMPLATES)


@app.route("/api/execute", methods=["POST"])
def execute():
    data = request.json
    hosts = [h.strip() for h in data.get("hosts", "").splitlines() if h.strip()]
    port = data.get("port", "22")
    username = data.get("username", "admin")
    password = data.get("password", "")
    template_id = data.get("template_id")
    params = data.get("params", {})
    max_threads = int(data.get("max_threads", 10))

    if not hosts:
        return jsonify({"error": "Nema unesenih IP adresa"}), 400
    commands = build_commands(template_id, params)
    if not commands:
        return jsonify({"error": "Nema komandi za izvršavanje"}), 400

    result_queue = queue.Queue()

    def worker(host):
        result = ssh_execute(host, port, username, password, commands)
        result["host"] = host
        result_queue.put(result)

    def generate():
        semaphore = threading.Semaphore(max_threads)
        threads = []

        def limited_worker(h):
            with semaphore:
                worker(h)

        for h in hosts:
            t = threading.Thread(target=limited_worker, args=(h,))
            threads.append(t)
            t.start()

        completed = 0
        total = len(hosts)
        while completed < total:
            try:
                result = result_queue.get(timeout=60)
                completed += 1
                yield f"data: {json.dumps(result)}\n\n"
            except queue.Empty:
                break
        for t in threads:
            t.join(timeout=1)
        yield f"data: {json.dumps({'done': True, 'total': total})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/export", methods=["POST"])
def export_config():
    data = request.json
    hosts = [h.strip() for h in data.get("hosts", "").splitlines() if h.strip()]
    port = data.get("port", "22")
    username = data.get("username", "admin")
    password = data.get("password", "")
    srv_host = data.get("srv_host", "")
    srv_port = data.get("srv_port", 22)
    srv_user = data.get("srv_user", "")
    srv_pass = data.get("srv_pass", "")
    srv_folder = data.get("srv_folder", "/exports")
    protocol = data.get("protocol", "sftp")  # "sftp" or "ftp"
    delete_after = data.get("delete_after", True)
    max_threads = int(data.get("max_threads", 5))

    if not hosts:
        return jsonify({"error": "Nema unesenih IP adresa"}), 400
    if not srv_host or not srv_user:
        return jsonify({"error": "Podaci servera nisu uneseni"}), 400

    result_queue = queue.Queue()

    def worker(host):
        result = export_and_upload(
            host, port, username, password,
            srv_host, srv_port, srv_user, srv_pass, srv_folder,
            protocol, delete_after
        )
        result_queue.put(result)

    def generate():
        semaphore = threading.Semaphore(max_threads)
        threads = []

        def limited_worker(h):
            with semaphore:
                worker(h)

        for h in hosts:
            t = threading.Thread(target=limited_worker, args=(h,))
            threads.append(t)
            t.start()

        completed = 0
        total = len(hosts)
        while completed < total:
            try:
                result = result_queue.get(timeout=120)
                completed += 1
                yield f"data: {json.dumps(result)}\n\n"
            except queue.Empty:
                break
        for t in threads:
            t.join(timeout=1)
        yield f"data: {json.dumps({'done': True, 'total': total})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/test-server", methods=["POST"])
def test_server():
    data = request.json
    host = data.get("srv_host", "")
    port = int(data.get("srv_port", 22))
    user = data.get("srv_user", "")
    pwd = data.get("srv_pass", "")
    folder = data.get("srv_folder", "/exports")
    protocol = data.get("protocol", "sftp")
    results = []

    # TCP check
    try:
        sock = socket.create_connection((host, port), timeout=8)
        sock.close()
        results.append({"ok": True, "msg": f"TCP port {port} otvoren na {host}"})
    except Exception as e:
        results.append({"ok": False, "msg": f"TCP port {port} nedostupan na {host}: {e}"})
        return jsonify({"success": False, "steps": results})

    if protocol == "sftp":
        try:
            cl = paramiko.SSHClient()
            cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cl.connect(hostname=host, port=port, username=user, password=pwd,
                       timeout=10, look_for_keys=False, allow_agent=False)
            results.append({"ok": True, "msg": f"SFTP autentikacija uspješna ({user}@{host})"})
            sftp = cl.open_sftp()
            f2 = folder.rstrip("/")
            try:
                sftp.stat(f2)
                results.append({"ok": True, "msg": f"Folder postoji: {f2}"})
            except FileNotFoundError:
                results.append({"ok": True, "msg": f"Folder {f2} ne postoji – biće kreiran automatski"})
            sftp.close()
            cl.close()
            return jsonify({"success": True, "steps": results})
        except paramiko.AuthenticationException:
            results.append({"ok": False, "msg": "SFTP autentikacija neuspješna – pogrešan user/pass"})
            return jsonify({"success": False, "steps": results})
        except Exception as e:
            results.append({"ok": False, "msg": f"SFTP greška: {e}"})
            return jsonify({"success": False, "steps": results})
    else:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=10)
            ftp.login(user, pwd)
            results.append({"ok": True, "msg": f"FTP login uspješan ({user}@{host})"})
            try:
                ftp.cwd(folder)
                results.append({"ok": True, "msg": f"Folder postoji: {folder}"})
            except ftplib.error_perm:
                results.append({"ok": True, "msg": f"Folder {folder} ne postoji – biće kreiran automatski"})
            ftp.quit()
            return jsonify({"success": True, "steps": results})
        except ftplib.error_perm as e:
            results.append({"ok": False, "msg": f"FTP greška dozvola: {e}"})
            return jsonify({"success": False, "steps": results})
        except Exception as e:
            results.append({"ok": False, "msg": f"FTP greška: {e}"})
            return jsonify({"success": False, "steps": results})


import os, uuid, base64, json as _json
SCRIPT_STORE = {}   # in-memory: id -> {name, content, vars}

# ── Script placeholders parser ──────────────────────────────────────────────
def parse_script_vars(script_text):
    """Find all {@varname} placeholders and return sorted unique list."""
    import re
    return sorted(set(re.findall(r'\{@([\w]+)\}', script_text)))


@app.route("/api/scripts/upload", methods=["POST"])
def script_upload():
    """Upload a .rsc/.txt script file, parse its variables, store in memory."""
    data = request.json
    name = data.get("name", "script.rsc")
    content_b64 = data.get("content_b64", "")
    try:
        script_text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

    script_id = str(uuid.uuid4())[:8]
    variables = parse_script_vars(script_text)
    SCRIPT_STORE[script_id] = {"id": script_id, "name": name, "content": script_text, "vars": variables}
    return jsonify({"success": True, "id": script_id, "name": name, "vars": variables, "preview": script_text[:500]})


@app.route("/api/scripts/list", methods=["GET"])
def script_list():
    return jsonify(list(SCRIPT_STORE.values()))


@app.route("/api/scripts/delete/<sid>", methods=["DELETE"])
def script_delete(sid):
    SCRIPT_STORE.pop(sid, None)
    return jsonify({"success": True})


@app.route("/api/scripts/deploy", methods=["POST"])
def script_deploy():
    """Deploy a script to one or more MikroTik devices via SSH, replacing {@var} placeholders."""
    data = request.json
    script_id = data.get("script_id")
    hosts = [h.strip() for h in data.get("hosts", "").splitlines() if h.strip()]
    port = data.get("port", "22")
    username = data.get("username", "admin")
    password = data.get("password", "")
    var_values = data.get("vars", {})   # {varname: value}
    max_threads = int(data.get("max_threads", 5))
    via_romon = data.get("via_romon", False)
    romon_host = data.get("romon_host", "")
    romon_port = int(data.get("romon_port", 22))
    romon_user = data.get("romon_user", "admin")
    romon_pass = data.get("romon_pass", "")

    if script_id not in SCRIPT_STORE:
        return jsonify({"error": "Script not found"}), 404
    if not hosts:
        return jsonify({"error": "No hosts provided"}), 400

    script_tmpl = SCRIPT_STORE[script_id]["content"]

    result_queue = queue.Queue()

    def deploy_one(host):
        # Build script for this host
        script = script_tmpl
        for k, v in var_values.items():
            # Support per-host values: if value is "host" use the IP itself
            val = v if v != "__host__" else host
            script = script.replace(f"{{@{k}}}", val)

        steps = []
        def ok(step, label, detail=""):
            steps.append({"step": step, "label": label, "detail": detail, "success": True})
        def err(step, label, detail=""):
            steps.append({"step": step, "label": label, "detail": detail, "success": False})

        client = None
        try:
            if via_romon:
                # Connect to RoMON proxy first
                try:
                    proxy = ssh_connect(romon_host, romon_port, romon_user, romon_pass, timeout=15)
                    ok("romon_connect", f"RoMON proxy connected", f"{romon_host}:{romon_port}")
                except Exception as e:
                    err("romon_connect", "RoMON proxy connection failed", str(e))
                    result_queue.put({"host": host, "steps": steps, "success": False, "connected": False})
                    return

                # Open SSH through RoMON tunnel using exec_command
                # MikroTik supports: /tool romon route mac=XX:XX:XX:XX:XX:XX
                # But SSH jump via paramiko proxy is more reliable
                import socket as _sock
                try:
                    transport = proxy.get_transport()
                    dest_addr = (host, int(port))
                    local_addr = (romon_host, 0)
                    channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host, port=int(port), username=username, password=password,
                                   sock=channel, look_for_keys=False, allow_agent=False, timeout=15)
                    ok("ssh_via_romon", "SSH via RoMON tunnel", f"Connected to {host}:{port} through {romon_host}")
                except Exception as e:
                    err("ssh_via_romon", "SSH via RoMON tunnel failed", str(e))
                    proxy.close()
                    result_queue.put({"host": host, "steps": steps, "success": False, "connected": False})
                    return
                finally:
                    proxy.close()
            else:
                try:
                    client = ssh_connect(host, port, username, password, timeout=15)
                    ok("connect", "SSH connection", f"Connected to {host}:{port}")
                except paramiko.AuthenticationException:
                    err("connect", "SSH connection", "Authentication failed")
                    result_queue.put({"host": host, "steps": steps, "success": False, "connected": False})
                    return
                except Exception as e:
                    err("connect", "SSH connection", str(e))
                    result_queue.put({"host": host, "steps": steps, "success": False, "connected": False})
                    return

            # Upload script as a file via SFTP, then execute it
            try:
                sftp = client.open_sftp()
                script_filename = f"deploy_{uuid.uuid4().hex[:6]}.rsc"
                script_bytes = io.BytesIO(script.encode("utf-8"))
                sftp.putfo(script_bytes, script_filename)
                sftp.close()
                ok("upload_script", "Script uploaded to router", f"File: {script_filename}")
            except Exception as e:
                err("upload_script", "Script upload failed", str(e))
                client.close()
                result_queue.put({"host": host, "steps": steps, "success": False, "connected": True})
                return

            # Execute the script
            try:
                out, ssh_err = ssh_run(client, f"/import file-name={script_filename}", timeout=60)
                time.sleep(1)
                # Clean up script file
                try:
                    ssh_run(client, f"/file remove [find name={script_filename}]", timeout=10)
                except:
                    pass
                if ssh_err and "error" in ssh_err.lower():
                    err("execute", "Script execution", f"Error: {ssh_err} | Output: {out}")
                    client.close()
                    result_queue.put({"host": host, "steps": steps, "success": False, "connected": True})
                    return
                ok("execute", "Script executed successfully", out[:300] if out else "(no output)")
            except Exception as e:
                err("execute", "Script execution failed", str(e))
                client.close()
                result_queue.put({"host": host, "steps": steps, "success": False, "connected": True})
                return

            client.close()
            result_queue.put({"host": host, "steps": steps, "success": True, "connected": True})

        except Exception as e:
            import traceback
            steps.append({"step": "unexpected", "label": "Unexpected error",
                          "detail": traceback.format_exc(), "success": False})
            if client:
                try: client.close()
                except: pass
            result_queue.put({"host": host, "steps": steps, "success": False, "connected": False})

    def generate():
        semaphore = threading.Semaphore(max_threads)
        threads = []
        def limited(h):
            with semaphore: deploy_one(h)
        for h in hosts:
            t = threading.Thread(target=limited, args=(h,))
            threads.append(t)
            t.start()
        completed, total = 0, len(hosts)
        while completed < total:
            try:
                r = result_queue.get(timeout=120)
                completed += 1
                yield f"data: {_json.dumps(r)}\n\n"
            except queue.Empty:
                break
        for t in threads:
            t.join(timeout=1)
        yield f"data: {_json.dumps({'done': True, 'total': total})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/romon/scan", methods=["POST"])
def romon_scan():
    """Connect to a RoMON-enabled router and list reachable neighbours."""
    data = request.json
    host = data.get("host", "")
    port = int(data.get("port", 22))
    user = data.get("user", "admin")
    pwd  = data.get("password", "")
    try:
        client = ssh_connect(host, port, user, pwd, timeout=15)
        out, err = ssh_run(client, "/tool romon neighbor print", timeout=20)
        client.close()
        # Parse output into list of {id, mac, identity, address}
        neighbours = []
        current = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0 ") or (line and line[0].isdigit()):
                if current: neighbours.append(current)
                current = {"raw": line}
            for field in ["address", "identity", "id"]:
                if field + ":" in line.lower():
                    val = line.split(":", 1)[-1].strip()
                    current[field] = val
        if current: neighbours.append(current)
        return jsonify({"success": True, "output": out, "neighbours": neighbours})
    except paramiko.AuthenticationException:
        return jsonify({"success": False, "error": "Authentication failed"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
