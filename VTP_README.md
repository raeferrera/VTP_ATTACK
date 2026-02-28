# 🔴 VTP Attack Tool — Raelina Ferrera | 2021-2371 | ITLA

## Objetivo

Herramienta de demostración de ataques al protocolo **VTP (VLAN Trunking Protocol)** usando Scapy como framework principal. Permite inyectar VLANs maliciosas y eliminar VLANs autorizadas en switches Cisco mediante la manipulación del número de revisión VTP.

---

## Topología

```
Kali Linux (192.168.153.133)
        │
        │ eth0
        │
   RCORE (10.21.99.1)
   E0/1 ─────────── E0/0
                  SW-CORE (10.21.99.2) ← VTP Server
                  E0/1 ──── SW-01 (10.21.99.3) ← VTP Client
                  E0/2 ──── SW-02 (10.21.99.4) ← VTP Client
```

| Dispositivo | IP            | Rol        |
|-------------|---------------|------------|
| RCORE       | 10.21.99.1    | Router     |
| SW-CORE     | 10.21.99.2    | VTP Server |
| SW-01       | 10.21.99.3    | VTP Client |
| SW-02       | 10.21.99.4    | VTP Client |

### VLANs autorizadas

| VLAN | Nombre     | Segmento         |
|------|------------|------------------|
| 10   | USERS      | 10.21.10.0/24    |
| 20   | SERVERS    | 10.21.20.0/24    |
| 99   | MANAGEMENT | 10.21.99.0/24    |

---

## Descripción del ataque

VTP distribuye la base de datos de VLANs automáticamente entre switches. Si un switch recibe un anuncio VTP con **número de revisión superior al actual**, acepta y reemplaza toda su base de datos VLAN.

**El ataque explota esto:**
1. Scapy construye frames VTP Summary + Subset Advertisement en Layer 2
2. Los frames se envían al multicast Cisco `01:00:0c:cc:cc:cc`
3. El número de revisión inyectado es superior al del switch
4. El switch acepta el anuncio y reemplaza su base de datos VLAN

---

## Parámetros

```bash
sudo python3 vtp_attack.py -i <interfaz> -m <modo> [opciones]
```

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `-i` | Interfaz de red | `eth0` |
| `-m` | Modo: `show`, `add`, `delete`, `full` | `add` |
| `--vlan-id` | ID de VLAN a inyectar | `999` |
| `--vlan-name` | Nombre de VLAN a inyectar | `PWNED` |
| `--domain` | Dominio VTP | `LAB-ITLA` |
| `--revision` | Número de revisión (debe ser > actual) | `100` |

### Modos de ejecución

```bash
# Ver estado actual
sudo python3 vtp_attack.py -i eth0 -m show

# Inyectar VLAN maliciosa
sudo python3 vtp_attack.py -i eth0 -m add --vlan-id 999 --vlan-name PWNED --domain LAB-ITLA --revision 100

# Eliminar todas las VLANs
sudo python3 vtp_attack.py -i eth0 -m delete --domain LAB-ITLA --revision 200

# Demo completa (4 fases)
sudo python3 vtp_attack.py -i eth0 -m full --vlan-id 999 --vlan-name PWNED --domain LAB-ITLA --revision 100
```

---

## Requisitos

```bash
# Python 3.8+
sudo apt install python3-scapy python3-paramiko

# Verificar
python3 -c "from scapy.all import *; import paramiko; print('OK')"
```

---

## Frameworks utilizados

| Framework | Rol | Función |
|-----------|-----|---------|
| **Scapy** | Principal | Construcción y envío de frames VTP L2 |
| **Paramiko** | Auxiliar | Verificación SSH del estado de VLANs |

---

## Medidas de mitigación

| Medida | Comando Cisco | Protege contra |
|--------|---------------|----------------|
| VTP Password | `vtp password VTP2024!` | Frames VTP no autenticados |
| VTP Client mode | `vtp mode client` | Modificación de base de datos VLAN |
| VTP Transparent | `vtp mode transparent` | Propagación de cambios VTP |
| VTP Version 3 | `vtp version 3` | Ataques de revisión (usa SHA-2) |

```
SW-CORE(config)# vtp password VTP2024!
SW-CORE(config)# vtp version 2
SW-01(config)# vtp mode client
SW-01(config)# vtp password VTP2024!
```

---

## Instituto Tecnológico de las Américas — ITLA
**Raelina Ferrera | 2021-2371**
