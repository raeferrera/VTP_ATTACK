# 🔴 VTP Attack Tool
## Raelina Ferrera | 2021-2371 | ITLA — Seguridad en Redes

---

## 📋 Objetivo del Script

Herramienta de demostración del ataque al protocolo **VTP (VLAN Trunking Protocol)** desarrollada con **Scapy como framework principal**. Permite:

- **Agregar VLANs maliciosas** inyectando frames VTP con número de revisión superior al actual
- **Eliminar todas las VLANs** autorizadas enviando un Subset Advertisement vacío
- **Verificar el estado** del dominio VTP mediante SSH con Paramiko (auxiliar)

El ataque explota que VTP acepta cualquier anuncio con revisión N+1 sin autenticación por defecto, reemplazando toda la base de datos VLAN del switch receptor.

---

## 🗺️ Topología

```
┌─────────────────────────────────────────────────────────────────┐
│                    192.168.153.0/24 (VMware NAT)                │
│   Kali Linux ─────────────────────────── Windows Server        │
│   192.168.153.133                        192.168.153.147        │
└───────────────────────┬─────────────────────────────────────────┘
                        │ E0/2 (DHCP/NAT)
                   ┌────┴────┐
                   │  RCORE  │ 10.21.99.1
                   │IOS-XE   │
                   └────┬────┘
                        │ E0/1 (trunk)
                   ┌────┴────┐
                   │SW-CORE  │ 10.21.99.2  ← VTP Server
                   │IOL-L2-0 │
                   └─┬──┬──┬─┘
              E0/1 ──┘  │  └── E0/2
         ┌──────────┐   │   ┌──────────┐
         │  SW-01   │   │   │  SW-02   │
         │10.21.99.3│   │   │10.21.99.4│
         │VTP Client│   │   │VTP Client│
         └──────────┘   │   └──────────┘
                   E0/3─┘
              ┌──────────┐
              │ Ubuntu-0 │ 10.21.10.100
              │ (atacante│
              │  DTP)    │
              └──────────┘
```

### Interfaces y direccionamiento

| Dispositivo | Interfaz    | IP / Modo          | VLAN / Descripción      |
|-------------|-------------|--------------------|-------------------------|
| RCORE       | E0/1        | trunk              | Hacia SW-CORE           |
| RCORE       | E0/1.10     | 10.21.10.1/24      | Gateway VLAN 10 USERS   |
| RCORE       | E0/1.20     | 10.21.20.1/24      | Gateway VLAN 20 SERVERS |
| RCORE       | E0/1.99     | 10.21.99.1/24      | Gateway VLAN 99 MGMT    |
| RCORE       | E0/2        | DHCP (NAT)         | Salida internet         |
| SW-CORE     | E0/0        | trunk              | Hacia RCORE             |
| SW-CORE     | E0/1        | trunk              | Hacia SW-01             |
| SW-CORE     | E0/2        | trunk              | Hacia SW-02             |
| SW-CORE     | E0/3        | access VLAN 10     | Hacia Ubuntu-0          |
| SW-CORE     | Vlan99      | 10.21.99.2/24      | SVI Management          |
| SW-01       | E0/0        | trunk              | Uplink SW-CORE          |
| SW-01       | E0/1        | access VLAN 10     | Host USERS              |
| SW-01       | E0/2        | access VLAN 20     | Host SERVERS            |
| SW-01       | E0/3        | access VLAN 99     | Host MGMT               |
| SW-01       | Vlan99      | 10.21.99.3/24      | SVI Management          |
| SW-02       | E0/0        | trunk              | Uplink SW-CORE          |
| SW-02       | E0/1        | access VLAN 10     | Host USERS              |
| SW-02       | E0/2        | access VLAN 20     | Host SERVERS            |
| SW-02       | E0/3        | access VLAN 99     | Host MGMT               |
| SW-02       | Vlan99      | 10.21.99.4/24      | SVI Management          |

### VLANs autorizadas

| VLAN ID | Nombre     | Segmento         | Uso              |
|---------|------------|------------------|------------------|
| 1       | default    | —                | Nativa           |
| 10      | USERS      | 10.21.10.0/24    | Usuarios         |
| 20      | SERVERS    | 10.21.20.0/24    | Servidores       |
| 99      | MANAGEMENT | 10.21.99.0/24    | Administración   |

### Dominio VTP

| Parámetro        | Valor      |
|------------------|------------|
| Dominio          | LAB-ITLA   |
| Versión          | 2          |
| Password         | VTP2024!   |
| SW-CORE modo     | Server     |
| SW-01/SW-02 modo | Client     |

---

## ⚙️ Parámetros del Script

```bash
sudo python3 vtp_attack.py -i <interfaz> -m <modo> [opciones]
```

| Parámetro       | Descripción                                    | Ejemplo       |
|-----------------|------------------------------------------------|---------------|
| `-i / --iface`  | Interfaz de red para enviar frames L2          | `eth0`        |
| `-m / --mode`   | Modo: `show`, `add`, `delete`, `full`          | `add`         |
| `--vlan-id`     | ID de VLAN maliciosa a inyectar                | `999`         |
| `--vlan-name`   | Nombre de VLAN maliciosa                       | `PWNED`       |
| `--domain`      | Dominio VTP del objetivo                       | `LAB-ITLA`    |
| `--revision`    | Número de revisión (debe ser > al actual)      | `100`         |

### Modos de ejecución

```bash
# Ver estado actual de VLANs (Paramiko verifica por SSH)
sudo python3 vtp_attack.py -i eth0 -m show

# Inyectar VLAN maliciosa 999 "PWNED"
sudo python3 vtp_attack.py -i eth0 -m add \
  --vlan-id 999 --vlan-name PWNED \
  --domain LAB-ITLA --revision 100

# Eliminar TODAS las VLANs (revisión alta = 200)
sudo python3 vtp_attack.py -i eth0 -m delete \
  --domain LAB-ITLA --revision 200

# Demo completa (4 fases: show → add → verify → delete)
sudo python3 vtp_attack.py -i eth0 -m full \
  --vlan-id 999 --vlan-name PWNED \
  --domain LAB-ITLA --revision 100
```

---

## 📦 Requisitos

### Software

```bash
# Sistema operativo recomendado
Kali Linux 2024+ / Ubuntu 22.04+

# Python 3.8 o superior
python3 --version

# Scapy (framework principal)
sudo apt install python3-scapy
# o
pip3 install scapy --break-system-packages

# Paramiko (framework auxiliar - verificación SSH)
sudo apt install python3-paramiko
# o
pip3 install paramiko --break-system-packages

# Verificar instalación
python3 -c "from scapy.all import *; import paramiko; print('Dependencias OK')"
```

### Privilegios

```bash
# Raw sockets Layer 2 requieren root
sudo python3 vtp_attack.py [...]
```

### Conectividad

- Acceso Layer 2 o Layer 3 al segmento donde están los switches
- Switches con VTP configurado sin password (o con el password conocido)
- Número de revisión VTP actual del dominio objetivo

### Credenciales SSH (para verificación Paramiko)

```python
# Configuradas en el script
SSH_USER    = "admin"
SSH_PASS    = "Admin2024!"
ENABLE_PASS = "Enable2024!"
```

---

## 🛡️ Medidas de Mitigación

### Configuración aplicada en la topología

```
! SW-CORE — VTP Server con autenticación
vtp domain LAB-ITLA
vtp version 2
vtp password VTP2024!
vtp mode server

! SW-01 / SW-02 — VTP Client (no puede modificar BD VLAN)
vtp domain LAB-ITLA
vtp password VTP2024!
vtp mode client
```

### Tabla de mitigaciones

| Ataque                 | Mitigación                  | Comando                       | Efectividad |
|------------------------|-----------------------------|-------------------------------|-------------|
| Inyección VLAN         | VTP Password (MD5)          | `vtp password VTP2024!`       | ✅ Alta     |
| Escalación revisión    | VTP Client mode             | `vtp mode client`             | ✅ Alta     |
| Borrado de VLANs       | VTP Version 3 (SHA-2)       | `vtp version 3`               | ✅ Muy alta |
| Propagación maliciosa  | VTP Transparent mode        | `vtp mode transparent`        | ✅ Total    |

### Verificación de mitigación

```
SW-CORE# show vtp status
SW-CORE# show vtp password
SW-01# show vtp status
```

**Con VTP Password activo**, el MD5 digest del frame inyectado no coincide y el switch rechaza el anuncio malicioso sin aplicar cambios.

---

## 🔧 Frameworks Utilizados

| Framework  | Rol        | Función específica                                           |
|------------|------------|--------------------------------------------------------------|
| **Scapy**  | Principal  | Construcción y envío de frames VTP L2 (Dot3/LLC/SNAP/Raw)   |
| **Paramiko** | Auxiliar | Verificación SSH: `show vlan brief`, `show vtp status`      |

---

## 📁 Formato de entregables

```
RaelinaFerrera_2021-2371_P1.zip
├── RaelinaFerrera_2021-2371_Informe_P1.pdf
├── README.md
└── vtp_attack.py
```

---

## 👤 Información del Autor

| Campo       | Valor                                          |
|-------------|------------------------------------------------|
| Nombre      | Raelina Ferrera                                |
| Matrícula   | 2021-2371                                      |
| Institución | Instituto Tecnológico de las Américas — ITLA   |
| Asignatura  | Seguridad en Redes                             |
| Fecha       | Febrero 2026                                   |
