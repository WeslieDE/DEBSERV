#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dev-HTTP/HTTPS-Server mit Auto-CA und SNI-VirtualHosts.

Features
- HTTP auf :80, HTTPS auf :443
- Root-CA unter ./Certs/rootCA.key / rootCA.pem
- Pro Host Zertifikate unter ./Certs/<host>.key / ./Certs/<host>.pem
- Hosts in ./config.json => {"hosts": ["site.local", "api.local"]}
- Webroot je Host: ./www/<host>/
- SNI-Routing: korrektes Zert je Host, DocumentRoot je Host
- Automatische Erzeugung fehlender Files/Ordner

Benutzung
1) `pip install cryptography`
2) config.json anlegen oder automatisch erzeugen lassen.
3) Script mit Admin-Rechten starten: `python dev_webserver.py`
4) (Optional) Windows: rootCA.pem in "Vertrauenswürdige Stammzertifizierungsstellen" importieren.
"""

import http.server
import socketserver
import socket
import ssl
import json
import sys
import threading
import datetime
import subprocess
import shutil
from pathlib import Path

# --- Pfade/Config ---
# Pfad zum Verzeichnis, das die Binärdatei/Script enthält.
# Damit die config.json sowie die www/ und Certs/-Ordner neben einer
# mit PyInstaller erzeugten EXE gefunden werden, verwenden wir bei
# "gefrosteren" Builds (sys.frozen) das Verzeichnis der ausführbaren Datei.
def _determine_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

BASE_DIR   = _determine_base_dir()
CERTS_DIR  = BASE_DIR / "Certs"
WWW_DIR    = BASE_DIR / "www"
CONFIG_PTH = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "hosts": ["example.local", "test.local"],
    # Optional: zusätzliche SANs pro Host (z.B. "localhost") -> {"example.local": ["localhost","127.0.0.1"]}
    "extra_sans": {}
}

# --- Crypto / Zertifikate ---
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, SubjectAlternativeName, BasicConstraints, KeyUsage, ExtendedKeyUsage

def ensure_dirs(hosts):
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    WWW_DIR.mkdir(parents=True, exist_ok=True)
    for h in hosts:
        (WWW_DIR / h).mkdir(parents=True, exist_ok=True)
        idx = WWW_DIR / h / "index.html"
        if not idx.exists():
            idx.write_text(f"""<!doctype html><html><head><meta charset="utf-8"><title>{h}</title></head>
<body><h1>{h}</h1><p>It works! DocumentRoot: ./www/{h}/</p></body></html>""", encoding="utf-8")

def load_or_create_ca():
    ca_key_pth = CERTS_DIR / "rootCA.key"
    ca_pem_pth = CERTS_DIR / "rootCA.pem"

    if ca_key_pth.exists() and ca_pem_pth.exists():
        ca_key = serialization.load_pem_private_key(ca_key_pth.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_pem_pth.read_bytes())
        return ca_key, ca_cert

    # Neues CA-Keypair
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Dev Local CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Dev Local Root CA"),
    ])
    now = datetime.datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 Jahre
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(KeyUsage(
            digital_signature=True, key_encipherment=False,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # speichern
    ca_key_pth.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )
    ca_pem_pth.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[CA] Root CA erzeugt: {ca_key_pth} / {ca_pem_pth}")
    return ca_key, ca_cert

def ensure_host_cert(hostname: str, ca_key, ca_cert, extra_sans=None):
    key_pth = CERTS_DIR / f"{hostname}.key"
    crt_pth = CERTS_DIR / f"{hostname}.pem"

    # Falls existiert, einfach laden / weiterverwenden
    if key_pth.exists() and crt_pth.exists():
        return str(key_pth), str(crt_pth)

    # Server-Key
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()

    # SANs: hostname + optional extras (localhost, 127.0.0.1, weitere DNS)
    sans = [DNSName(hostname)]
    for san in (extra_sans or []):
        if san.strip():
            sans.append(DNSName(san.strip()))

    csr_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Dev Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr_subject)
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))  # ~27 Monate
        .add_extension(SubjectAlternativeName(sans), critical=False)
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    key_pth.write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )
    crt_pth.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[CERT] Zertifikat erzeugt für {hostname}: {key_pth} / {crt_pth}")
    return str(key_pth), str(crt_pth)

def _fingerprint_sha1_hex(cert):
    return cert.fingerprint(hashes.SHA1()).hex().upper()

def _format_thumbprint_with_colons(thumbprint: str) -> str:
    return ":".join(thumbprint[i:i+2] for i in range(0, len(thumbprint), 2))

def _is_root_ca_installed_windows(thumbprint: str) -> bool:
    ps_script = (
        "$thumb='{thumb}'; "
        "if (Get-ChildItem -Path Cert:\\LocalMachine\\Root | "
        "Where-Object { $_.Thumbprint -eq $thumb }) { exit 0 } else { exit 1 }"
    ).format(thumb=thumbprint)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0

def _is_root_ca_installed_linux(thumbprint: str) -> bool:
    candidate_dirs = [Path("/usr/local/share/ca-certificates"), Path("/etc/ssl/certs")]
    for directory in candidate_dirs:
        if not directory.exists():
            continue
        for cert_file in directory.iterdir():
            if not cert_file.is_file():
                continue
            try:
                data = cert_file.read_bytes()
            except OSError:
                continue
            cert = None
            try:
                cert = x509.load_pem_x509_certificate(data)
            except ValueError:
                try:
                    cert = x509.load_der_x509_certificate(data)
                except ValueError:
                    continue
            if cert and cert.fingerprint(hashes.SHA1()).hex().upper() == thumbprint:
                return True
    return False

def _is_root_ca_installed_macos(thumbprint: str) -> bool:
    formatted = _format_thumbprint_with_colons(thumbprint)
    try:
        result = subprocess.run(
            ["security", "find-certificate", "-Z", "-a", "/Library/Keychains/System.keychain"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    if result.returncode != 0:
        return False
    return formatted in result.stdout

def is_root_ca_installed(ca_cert) -> bool:
    thumbprint = _fingerprint_sha1_hex(ca_cert)
    if sys.platform.startswith("win"):
        return _is_root_ca_installed_windows(thumbprint)
    if sys.platform == "darwin":
        return _is_root_ca_installed_macos(thumbprint)
    return _is_root_ca_installed_linux(thumbprint)

def _install_root_ca_windows(ca_path: Path) -> bool:
    ps_script = (
        "Import-Certificate -FilePath \"{path}\" "
        "-CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null"
    ).format(path=str(ca_path))
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())
        return False
    return True

def _install_root_ca_linux(ca_cert) -> bool:
    target_dir = Path("/usr/local/share/ca-certificates")
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "dev_local_root_ca.crt"
        target_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        update_cmd = shutil.which("update-ca-certificates")
        if not update_cmd:
            print("[CA] 'update-ca-certificates' wurde nicht gefunden. Bitte manuell installieren.")
            return False
        result = subprocess.run([update_cmd], capture_output=True, text=True, check=False)
    except OSError as exc:
        print(f"[CA] Fehler beim Schreiben der Root-CA: {exc}")
        return False
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())
        return False
    return True

def _install_root_ca_macos(ca_path: Path) -> bool:
    try:
        result = subprocess.run(
            [
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                str(ca_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())
        return False
    return True

def install_root_ca(ca_path: Path, ca_cert) -> bool:
    if sys.platform.startswith("win"):
        return _install_root_ca_windows(ca_path)
    if sys.platform == "darwin":
        return _install_root_ca_macos(ca_path)
    return _install_root_ca_linux(ca_cert)

# --- HTTP Handler, der je nach Host das DocumentRoot umbiegt ---
class VHostHandler(http.server.SimpleHTTPRequestHandler):
    # Kein Logging-Spam
    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s\n" % (self.address_string(), fmt % args))

    def translate_path(self, path):
        # Host-Header ohne Port
        host = self.headers.get("Host", "")
        host = host.split(":")[0].strip().lower()
        if not host:
            # Fallback: erster Host
            host = self.server.default_host

        # Wenn unbekannt: 404-Verzeichnis (leer)
        docroot = (WWW_DIR / host) if (WWW_DIR / host).exists() else (WWW_DIR / self.server.default_host)

        # Basismethode für Pfad-Normalisierung nutzen:
        # Kopie von SimpleHTTPRequestHandler.translate_path, angepasst auf docroot
        import posixpath, urllib, os
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except Exception:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = [w for w in path.split('/') if w]
        p = str(docroot)
        for w in words:
            drive, w = os.path.splitdrive(w)
            head, w = os.path.split(w)
            if w in (os.curdir, os.pardir): continue
            p = os.path.join(p, w)
        return p

# --- Threading Server ---
class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, server_address, RequestHandlerClass, default_host):
        super().__init__(server_address, RequestHandlerClass)
        self.default_host = default_host

def build_ssl_contexts(hosts, ca_key, ca_cert, extra_sans_map):
    """
    Erzeugt:
    - default_ctx: SSLContext mit default Zert (erster Host)
    - per_host_ctx: dict(host -> SSLContext)
    - sni_callback: setzt context je nach SNI
    """
    per_host_ctx = {}
    for h in hosts:
        key_pth, crt_pth = ensure_host_cert(h, ca_key, ca_cert, extra_sans=extra_sans_map.get(h, []))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=crt_pth, keyfile=key_pth)
        per_host_ctx[h] = ctx

    default_host = hosts[0]
    default_ctx = per_host_ctx[default_host]

    def sni_cb(ssl_sock: ssl.SSLSocket, server_name, initial_ctx):
        # server_name kann None sein (z.B. alte Clients)
        host = (server_name or default_host).lower()
        ctx = per_host_ctx.get(host, default_ctx)
        # Kontext dynamisch umschalten (Python 3.7+)
        try:
            ssl_sock.context = ctx
        except Exception:
            # Fallback: ignorieren, default bleibt
            pass

    default_ctx.set_servername_callback(sni_cb)
    return default_ctx, per_host_ctx, default_host

def load_config():
    if not CONFIG_PTH.exists():
        CONFIG_PTH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        print(f"[CONFIG] Standard-config.json erzeugt. Bitte anpassen: {CONFIG_PTH}")
    cfg = json.loads(CONFIG_PTH.read_text(encoding="utf-8"))
    hosts = cfg.get("hosts") or []
    extra_sans = cfg.get("extra_sans") or {}
    if not hosts:
        raise SystemExit("config.json enthält keine Hosts. Trage z.B. ['example.local'] ein.")
    return hosts, extra_sans

def serve_http(default_host):
    httpd = ThreadingHTTPServer(("0.0.0.0", 80), VHostHandler, default_host=default_host)
    print("[HTTP] Läuft auf http://0.0.0.0:80")
    httpd.serve_forever()

def serve_https(default_ctx, default_host):
    httpd = ThreadingHTTPServer(("0.0.0.0", 443), VHostHandler, default_host=default_host)
    httpd.socket = default_ctx.wrap_socket(httpd.socket, server_side=True)
    print("[HTTPS] Läuft auf https://0.0.0.0:443")
    httpd.serve_forever()

def main():
    hosts, extra_sans_map = load_config()
    ensure_dirs(hosts)
    ca_key, ca_cert = load_or_create_ca()
    ca_path = CERTS_DIR / "rootCA.pem"

    ca_installed = False
    try:
        ca_installed = is_root_ca_installed(ca_cert)
    except Exception as exc:
        print(f"[CA] Konnte Installationsstatus nicht prüfen: {exc}")
    else:
        if ca_installed:
            print("[CA] Root-CA ist bereits im System installiert.")
        else:
            print("[CA] Root-CA ist im System noch nicht installiert.")
            if sys.stdin.isatty():
                answer = input("[CA] Automatisch installieren? [Y/N]: ").strip().lower()
                if answer in {"y", "yes", "j", "ja"}:
                    if install_root_ca(ca_path, ca_cert):
                        try:
                            ca_installed = is_root_ca_installed(ca_cert)
                        except Exception:
                            ca_installed = False
                        if ca_installed:
                            print("[CA] Root-CA wurde erfolgreich installiert.")
                        else:
                            print("[CA] Installation durchgeführt, konnte Root-CA jedoch nicht verifizieren.")
                    else:
                        print("[CA] Automatische Installation fehlgeschlagen. Bitte manuell installieren.")
                else:
                    print("[CA] Automatische Installation übersprungen.")
            else:
                print("[CA] Kein interaktives Terminal – automatische Installation wird übersprungen.")

    default_ctx, per_host_ctx, default_host = build_ssl_contexts(hosts, ca_key, ca_cert, extra_sans_map)

    # Hinweis zum Import der Root-CA auf Windows

    t1 = threading.Thread(target=serve_http, args=(default_host,), daemon=True)
    t2 = threading.Thread(target=serve_https, args=(default_ctx, default_host), daemon=True)
    t1.start()
    t2.start()

    print("[READY] Server gestartet. Hosts:", ", ".join(hosts))
    print("       Webroots unter ./www/<host>/")
    print("       Zertifikate unter ./Certs/")
    try:
        # Hauptthread am Leben halten
        while True:
            t1.join(1)
            t2.join(1)
    except KeyboardInterrupt:
        print("\nBeende...")

if __name__ == "__main__":
    # Port-Check: hilfreiche Meldung, falls Ports blockiert
    try:
        main()
    except OSError as e:
        print(f"[ERROR] {e}")
        print("Tipp: Stelle sicher, dass keine anderen Dienste Port 80/443 belegen und du ausreichende Rechte hast.")
        sys.exit(1)

