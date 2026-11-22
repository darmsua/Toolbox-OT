#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Toolbox-OT · Verificación de configuración de una célula OT
============================================================

Compara el ESTADO REAL de los equipos de una célula con su LÍNEA BASE
(archivo JSON creado con la herramienta «Verificación OT» de Toolbox-OT)
y genera un archivo de RESULTADOS que se carga de nuevo en esa herramienta.

    python verificar_celda.py linea_base_celda.json
    python verificar_celda.py linea_base_celda.json -o resultado.json
    python verificar_celda.py linea_base_celda.json --plan      (solo muestra qué consultaría)

REGLAS DE SEGURIDAD (forman parte de la práctica)
  · SOLO LECTURA. Este script nunca escribe en un equipo: no usa DCP «Set»,
    ni escrituras S7, ni «setdata» del IoT Core de ifm, ni modo configuración
    en el switch.
  · Consulta solo las IP de la línea base (no barre rangos) y con pausas
    entre consultas. Ejecútalo con la instalación parada o en pruebas y con
    permiso del responsable de la planta.
  · Las contraseñas NO van en el JSON: se leen de variables de entorno
    o se piden por teclado.

Bibliotecas: solo la biblioteca estándar para puertos, SNMP, HTTP e IoT Core.
Opcionales (se instalan con pip; si faltan, esas comprobaciones salen como
«NO COMPROBABLE»):
    python-snap7   → PLC S7 (PUT/GET, estado, referencia y firmware)
    asyncua        → OPC UA (parámetros del variador leídos por el PLC)
    netmiko        → configuración del switch Cisco por SSH
    pnio_dcp       → descubrimiento PROFINET DCP (en Windows requiere Npcap)

Toolbox-OT — concebida e inspirada por David de Armas Suárez
(conecta3@hotmail.com). Propulsada por Claude.ai. Licencia CC BY 4.0.
"""

import argparse
import datetime as _dt
import difflib
import getpass
import json
import os
import platform
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0-beta"
ESQUEMA_BASE = "ot-baseline/1.0"
ESQUEMA_RES = "ot-verif/1.0"

OK, DESV, NC, INFO = "OK", "DESVIACION", "NO_COMPROBABLE", "INFO"
ALTA, MEDIA, BAJA = "ALTA", "MEDIA", "BAJA"

AJUSTES = {"timeout_s": 2.0, "pausa_s": 0.5}


# ─────────────────────────────────────────────────────────── utilidades ──
def pausa():
    time.sleep(float(AJUSTES.get("pausa_s", 0.5)))


def version_tupla(v):
    """'V4.6.1' -> (4, 6, 1). Devuelve None si no hay números."""
    if v is None:
        return None
    nums = re.findall(r"\d+", str(v))
    return tuple(int(n) for n in nums) if nums else None


def version_menor(a, b):
    """True si la versión a es anterior a la b."""
    ta, tb = version_tupla(a), version_tupla(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))


def credencial(prefijo, quien):
    """Lee usuario/contraseña de variables de entorno <PREFIJO>_USER / _PASS
    o los pide por teclado. Nunca se guardan en el JSON."""
    if not prefijo:
        return None, None
    u = os.environ.get(prefijo + "_USER")
    p = os.environ.get(prefijo + "_PASS")
    if u is None and sys.stdin.isatty():
        u = input(f"  Usuario para {quien} (vacío = sin usuario): ").strip() or None
    if u and p is None and sys.stdin.isatty():
        p = getpass.getpass(f"  Contraseña de {u}@{quien}: ")
    return u, p


class Informe:
    """Acumula las comprobaciones de un dispositivo."""

    def __init__(self, disp):
        self.d = {
            "id_redot": disp.get("id_redot", ""),
            "nombre": disp.get("nombre", ""),
            "ip": disp.get("ip", ""),
            "perfil": disp.get("perfil", "generico"),
            "observado": {},
            "comprobaciones": [],
        }

    def add(self, cid, descripcion, esperado, real, estado, severidad="", evidencia="", recomendacion=""):
        if estado in (OK, INFO, NC):
            severidad = severidad if estado == INFO else ""
        self.d["comprobaciones"].append({
            "id": cid, "descripcion": descripcion,
            "esperado": esperado, "real": real,
            "estado": estado, "severidad": severidad,
            "evidencia": evidencia, "recomendacion": recomendacion,
        })
        marca = {OK: "  OK ", DESV: " !!  ", NC: "  ?  ", INFO: "  i  "}[estado]
        sev = f"[{severidad}] " if estado == DESV and severidad else ""
        print(f"   {marca} {sev}{descripcion}: {real}")

    def obs(self, clave, valor):
        if valor not in (None, ""):
            self.d["observado"][clave] = valor


# ────────────────────────────────────────────────────────── 1. puertos TCP ──
def puerto_abierto(ip, puerto):
    try:
        with socket.create_connection((ip, int(puerto)), timeout=AJUSTES["timeout_s"]):
            return True
    except OSError:
        return False


SERVICIOS = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 102: "S7comm (ISO-TSAP)",
             443: "HTTPS", 502: "Modbus/TCP", 4840: "OPC UA", 5900: "VNC", 44818: "EtherNet/IP",
             1883: "MQTT", 8080: "HTTP alternativo"}


def comprobar_puertos(inf, ip, esp):
    abiertos_esp = [int(p) for p in esp.get("puertos_abiertos", [])]
    cerrados_esp = [int(p) for p in esp.get("puertos_cerrados", [])]
    vistos = []
    for p in abiertos_esp + cerrados_esp:
        ab = puerto_abierto(ip, p)
        pausa()
        nom = f"{p}/tcp ({SERVICIOS.get(p, 'servicio')})"
        if ab:
            vistos.append(p)
        if p in abiertos_esp:
            inf.add(f"puerto_{p}", f"Puerto necesario {nom}", "abierto",
                    "abierto" if ab else "cerrado / sin respuesta",
                    OK if ab else DESV, BAJA,
                    recomendacion="" if ab else "Comprobar que el equipo está encendido y que el servicio necesario está activo.")
        else:
            inf.add(f"puerto_{p}", f"Puerto no permitido {nom}", "cerrado",
                    "ABIERTO" if ab else "cerrado",
                    DESV if ab else OK, ALTA if p in (21, 23, 5900) else MEDIA,
                    recomendacion=f"Desactivar el servicio {SERVICIOS.get(p, p)} si no es necesario o filtrarlo en el cortafuegos de la célula." if ab else "")
    inf.obs("puertos_abiertos", vistos)
    return vistos


# ──────────────────────────────────────────── 2. SNMP v1/v2c (sin librerías) ──
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _int(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, b)


def _oid(oid):
    p = [int(x) for x in oid.strip(".").split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for n in p[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.insert(0, 0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(chunk)
    return _tlv(0x06, bytes(out))


def _parse(data, i=0):
    """Devuelve lista de (tag, valor, hijos) del TLV a partir de i."""
    res = []
    while i < len(data):
        tag = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(data[i:i + nb], "big")
            i += nb
        val = data[i:i + ln]
        i += ln
        hijos = _parse(val) if tag in (0x30, 0xA0, 0xA2) else None
        res.append((tag, val, hijos))
    return res


def _oid_txt(b):
    p = [b[0] // 40, b[0] % 40]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            p.append(n)
            n = 0
    return ".".join(map(str, p))


def snmp_get(ip, comunidad, oids, version=1):
    """SNMP GET de solo lectura. version: 0 = v1, 1 = v2c.
    Devuelve dict oid -> valor (str) o None si no responde."""
    reqid = random.randint(1, 0x7FFFFFFF)
    vbs = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(0xA0, _int(reqid) + _int(0) + _int(0) + _tlv(0x30, vbs))
    msg = _tlv(0x30, _int(version) + _tlv(0x04, comunidad.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(AJUSTES["timeout_s"])
    try:
        s.sendto(msg, (ip, 161))
        data, _ = s.recvfrom(65535)
    except OSError:
        return None
    finally:
        s.close()
    try:
        msg = _parse(data)[0][2]
        pdu = msg[2]
        if pdu[0] != 0xA2:
            return None
        err = int.from_bytes(pdu[2][1][1], "big")
        if err:
            return {}
        out = {}
        for vb in pdu[2][3][2]:
            oid = _oid_txt(vb[2][0][1])
            tag, val = vb[2][1][0], vb[2][1][1]
            if tag == 0x04:
                out[oid] = val.decode("utf-8", "replace")
            elif tag == 0x06:
                out[oid] = _oid_txt(val)
            elif tag in (0x02, 0x41, 0x42, 0x43):
                out[oid] = str(int.from_bytes(val, "big"))
            else:
                out[oid] = None
        return out
    except Exception:
        return None


OID_DESCR, OID_OBJID, OID_NAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"
RE_FW = re.compile(r"FW[:\s]*(?:Version\s*)?V?\s*(\d+(?:\.\d+){1,3})", re.I)
RE_REF = re.compile(r"\b(6[A-Z]{2}\d\s?\d{3}-\w{5}-\w{4})\b")


def comprobar_snmp(inf, ip, esp, comunidades):
    politica = esp.get("snmp", "v3")       # v3 | desactivado | v1v2c_permitido
    respuesta = None
    for com in comunidades:
        for ver, vtxt in ((1, "v2c"), (0, "v1")):
            r = snmp_get(ip, com, [OID_DESCR, OID_OBJID, OID_NAME], ver)
            pausa()
            if r:
                respuesta = (com, vtxt, r)
                break
        if respuesta:
            break
    if respuesta:
        com, vtxt, r = respuesta
        descr = r.get(OID_DESCR) or ""
        inf.obs("snmp_sysdescr", descr)
        inf.obs("snmp_sysname", r.get(OID_NAME))
        m = RE_FW.search(descr)
        if m:
            inf.obs("firmware", "V" + m.group(1))
        m = RE_REF.search(descr)
        if m:
            inf.obs("referencia", m.group(1))
        if politica == "v1v2c_permitido":
            inf.add("snmp", "SNMP v1/v2c", "permitido (aceptado en la línea base)",
                    f"responde a la comunidad «{com}» ({vtxt})", INFO, BAJA, evidencia=descr)
        else:
            inf.add("snmp", "SNMP v1/v2c con comunidad por defecto",
                    "sin respuesta (" + ("SNMPv3" if politica == "v3" else "SNMP desactivado") + ")",
                    f"RESPONDE a la comunidad «{com}» ({vtxt})", DESV,
                    ALTA if com.lower() == "private" else MEDIA, evidencia=descr,
                    recomendacion="Desactivar SNMP v1/v2c o cambiar la comunidad; usar SNMPv3 con autenticación y cifrado.")
    else:
        inf.add("snmp", "SNMP v1/v2c con comunidades por defecto",
                "sin respuesta" if politica != "v1v2c_permitido" else "respuesta",
                "sin respuesta a " + ", ".join(comunidades),
                OK if politica != "v1v2c_permitido" else NC)


# ───────────────────────────────────────────────── 3. PLC S7 (python-snap7) ──
def _area_mk(snap7):
    for mod in ("type", "types", "util"):
        m = getattr(snap7, mod, None)
        for nom in ("Area", "Areas"):
            enum = getattr(m, nom, None) if m else None
            if enum is not None and hasattr(enum, "MK"):
                return enum.MK
    return 0x83


def comprobar_s7(inf, ip, esp):
    try:
        import snap7  # noqa
    except ImportError:
        inf.add("s7", "Acceso S7 (python-snap7)", "-", "python-snap7 no instalado", NC,
                recomendacion="pip install python-snap7")
        return
    rack, slot = int(esp.get("rack", 0)), int(esp.get("slot", 1))
    c = snap7.client.Client()
    try:
        c.connect(ip, rack, slot)
    except Exception as e:
        inf.add("s7_conexion", "Conexión S7 (puerto 102)", "posible (necesaria para TIA Portal)",
                f"no se pudo conectar: {e}", NC)
        return
    pausa()
    # Estado de la CPU
    try:
        estado = str(c.get_cpu_state())
        real = "RUN" if "RUN" in estado.upper() else ("STOP" if "STOP" in estado.upper() else estado)
        inf.obs("estado_cpu", real)
        exp = esp.get("estado_cpu")
        if exp:
            inf.add("s7_estado", "Estado de la CPU", exp, real, OK if real == exp else DESV, MEDIA,
                    recomendacion="" if real == exp else "Averiguar por qué la CPU no está en el estado esperado (¿cambio no autorizado?).")
    except Exception as e:
        inf.add("s7_estado", "Estado de la CPU", esp.get("estado_cpu", "-"), f"no disponible ({e})", NC)
    pausa()
    # Referencia y firmware
    try:
        oc = c.get_order_code()
        ref = (getattr(oc, "OrderCode", b"") or b"")
        ref = ref.decode("ascii", "ignore").strip() if isinstance(ref, (bytes, bytearray)) else str(ref).strip()
        fw = f"V{oc.V1}.{oc.V2}.{oc.V3}"
        inf.obs("referencia", ref)
        inf.obs("firmware", fw)
    except Exception:
        pass
    pausa()
    # PUT/GET: lectura inocua de 1 byte de marcas (MB0). Si funciona, PUT/GET está habilitado.
    try:
        c.read_area(_area_mk(snap7), 0, 0, 1)
        putget = True
    except Exception as e:
        txt = str(e).lower()
        putget = False if any(k in txt for k in ("not available", "not authorized", "access", "denied", "0x8500", "function")) else None
        ev = str(e)
    else:
        ev = "lectura de MB0 aceptada sin autenticación"
    inf.obs("put_get", putget)
    exp = bool(esp.get("put_get", False))
    if putget is None:
        inf.add("s7_putget", "Acceso PUT/GET", "habilitado" if exp else "deshabilitado", f"indeterminado ({ev})", NC)
    else:
        inf.add("s7_putget", "Acceso PUT/GET (lectura/escritura sin autenticación)",
                "habilitado" if exp else "deshabilitado",
                "HABILITADO" if putget else "deshabilitado",
                OK if putget == exp else DESV, ALTA, evidencia=ev,
                recomendacion="" if putget == exp else "Desactivar «Permitir acceso vía comunicación PUT/GET» en las propiedades de la CPU (TIA Portal) y usar OPC UA con usuarios.")
    # Nivel de protección (SZL 0x0232). En S7-1200 a menudo no está disponible.
    try:
        pr = c.get_protection()
        inf.obs("proteccion_szl", {"sch_schal": pr.sch_schal, "sch_par": pr.sch_par, "sch_rel": pr.sch_rel})
        inf.add("s7_proteccion", "Nivel de protección (SZL 0x0232)", esp.get("nivel_proteccion", "-"),
                f"sch_par={pr.sch_par}, sch_rel={pr.sch_rel}", INFO, BAJA,
                recomendacion="Contrastar con el nivel de acceso configurado en TIA Portal.")
    except Exception:
        pass
    try:
        c.disconnect()
    except Exception:
        pass


# ──────────────────────────────────────────────────── 4. servidor web ──
class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def comprobar_web(inf, ip, esp):
    politica = esp.get("web")          # desactivado | https | permitido
    if not politica:
        return
    http = puerto_abierto(ip, 80)
    https = puerto_abierto(ip, 443)
    pausa()
    redirige = False
    if http:
        try:
            op = urllib.request.build_opener(_SinRedireccion)
            op.open(f"http://{ip}/", timeout=AJUSTES["timeout_s"])
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "") if e.headers else ""
            redirige = e.code in (301, 302, 303, 307, 308) and loc.lower().startswith("https")
        except Exception:
            pass
    real = ("HTTP→HTTPS" if (http and redirige) else
            "HTTP y HTTPS" if (http and https) else
            "solo HTTP" if http else "solo HTTPS" if https else "desactivado")
    inf.obs("web", real)
    if politica == "desactivado":
        ok = not http and not https
        inf.add("web", "Servidor web", "desactivado", real, OK if ok else DESV, MEDIA,
                recomendacion="" if ok else "Desactivar el servidor web si no se usa (reduce la superficie de ataque).")
    elif politica == "https":
        ok = https and (not http or redirige)
        inf.add("web", "Servidor web cifrado", "solo HTTPS (HTTP redirigido o cerrado)", real,
                OK if ok else DESV, MEDIA,
                recomendacion="" if ok else "Forzar HTTPS y desactivar HTTP sin cifrar: las credenciales viajan en claro.")
    else:
        inf.add("web", "Servidor web", "permitido", real, INFO, BAJA)


# ─────────────────────────────────────────── 5. maestro IO-Link ifm (IoT Core) ──
def ifm_req(ip, ruta, servicio="getdata", datos=None, auth=None):
    adr = f"{ruta}/{servicio}" if servicio else ruta
    cuerpo = {"code": "request", "cid": random.randint(1, 9999), "adr": adr}
    if datos is not None:
        cuerpo["data"] = datos
    if auth:
        import base64
        cuerpo["auth"] = {"user": base64.b64encode(auth[0].encode()).decode(),
                          "passwd": base64.b64encode((auth[1] or "").encode()).decode()}
    req = urllib.request.Request(f"http://{ip}/", data=json.dumps(cuerpo).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=AJUSTES["timeout_s"]) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"code": e.code}
    except Exception:
        return None
    finally:
        pausa()


def _ifm_valor(resp):
    if resp and resp.get("code") == 200:
        return (resp.get("data") or {}).get("value")
    return None


def _hex_ascii(v):
    try:
        return bytes.fromhex(v).decode("ascii", "ignore").strip("\x00 ").strip()
    except Exception:
        return v


def comprobar_ifm(inf, ip, esp, ajustes):
    # 1) ¿Responde sin credenciales?
    r = ifm_req(ip, "/deviceinfo/productcode")
    if r is None:
        inf.add("ifm_iot", "IoT Core (REST/JSON)", "accesible para la verificación", "sin respuesta en http://" + ip, NC,
                recomendacion="Comprobar que el puerto IoT del maestro está en la red desde la que se ejecuta el script.")
        return
    sin_auth = r.get("code") == 200
    exp_auth = bool(esp.get("iot_auth", True))
    inf.add("ifm_auth", "IoT Core exige autenticación", "sí" if exp_auth else "no",
            "NO (responde a cualquiera)" if sin_auth else "sí",
            OK if (not sin_auth) == exp_auth else DESV, ALTA,
            recomendacion="" if (not sin_auth) == exp_auth else "Activar usuario y contraseña en el IoT Core y limitar desde qué red se accede al puerto IoT.")
    auth = None
    if not sin_auth:
        u, p = credencial(esp.get("cred_env", "OT_IFM"), f"IoT Core {ip}")
        auth = (u, p) if u else None
        if not auth:
            inf.add("ifm_lectura", "Lectura de datos del maestro", "-", "sin credenciales, no se puede leer más", NC)
            return
    val = lambda ruta: _ifm_valor(ifm_req(ip, ruta, auth=auth))
    inf.obs("referencia", val("/deviceinfo/productcode") or (r.get("data") or {}).get("value"))
    fw = val("/deviceinfo/swrevision")
    inf.obs("firmware", fw)
    inf.obs("serie", val("/deviceinfo/serialnumber"))
    # 2) Dispositivos IO-Link por puerto
    ruta_val = ajustes.get("ifm_ruta_validacion", "/iolinkmaster/port[{p}]/validation_datastorage_mode")
    observados = {}
    for p, e in (esp.get("puertos_iolink") or {}).items():
        base = f"/iolinkmaster/port[{p}]/iolinkdevice"
        vid, did = val(base + "/vendorid"), val(base + "/deviceid")
        serie = val(base + "/serial")
        nombre = val(base + "/productname")
        fwd = _ifm_valor(ifm_req(ip, base + "/iolreadacyclic", None, {"index": 23, "subindex": 0}, auth))
        fwd = _hex_ascii(fwd) if fwd else None
        valid = val(ruta_val.replace("{p}", str(p)))
        observados[p] = {"vendorid": vid, "deviceid": did, "serial": serie, "producto": nombre,
                         "firmware": fwd, "validacion": valid}
        tag = f"Puerto IO-Link {p}"
        if vid is None and did is None:
            inf.add(f"iol_{p}", tag, f"vendor {e.get('vendorid')} / device {e.get('deviceid')}",
                    "sin dispositivo o sin respuesta", DESV, MEDIA,
                    recomendacion="Comprobar el cableado y si el sensor ha sido retirado.")
            continue
        mismo_tipo = str(vid) == str(e.get("vendorid", vid)) and str(did) == str(e.get("deviceid", did))
        inf.add(f"iol_{p}_tipo", f"{tag}: tipo de dispositivo",
                f"vendor {e.get('vendorid')} / device {e.get('deviceid')}",
                f"vendor {vid} / device {did} ({nombre or '?'})",
                OK if mismo_tipo else DESV, ALTA,
                recomendacion="" if mismo_tipo else "Se ha conectado un dispositivo distinto al previsto: verificar sustitución no autorizada.")
        if e.get("serial"):
            ok = str(serie) == str(e["serial"])
            inf.add(f"iol_{p}_serie", f"{tag}: número de serie", e["serial"], serie or "?",
                    OK if ok else DESV, MEDIA,
                    recomendacion="" if ok else "El sensor ha sido sustituido por otro del mismo tipo: registrar el cambio o investigarlo.")
        if e.get("fw_minimo") and fwd:
            menor = version_menor(fwd, e["fw_minimo"])
            inf.add(f"iol_{p}_fw", f"{tag}: firmware del dispositivo", f"≥ {e['fw_minimo']}", fwd,
                    NC if menor is None else (DESV if menor else OK), MEDIA)
        if e.get("validacion") not in (None, ""):
            ok = str(valid) == str(e["validacion"])
            inf.add(f"iol_{p}_valid", f"{tag}: modo de validación / Data Storage", e["validacion"],
                    valid if valid is not None else "no leído (ver /gettree)",
                    NC if valid is None else (OK if ok else DESV), MEDIA,
                    recomendacion="" if ok else "Configurar la validación del puerto (tipo compatible o idéntico) para que el maestro rechace dispositivos no previstos.")
    inf.obs("iolink", observados)


# ─────────────────────────────────────────── 6. OPC UA (valores leídos por el PLC) ──
def comprobar_opcua(inf, ip, esp):
    cfg = esp.get("opcua") or {}
    nodos = cfg.get("nodos") or []
    if not nodos:
        return
    try:
        from asyncua.sync import Client
    except ImportError:
        inf.add("opcua", "Lectura OPC UA", "-", "asyncua no instalado", NC, recomendacion="pip install asyncua")
        return
    url = cfg.get("url") or f"opc.tcp://{ip}:4840"
    cl = Client(url, timeout=AJUSTES["timeout_s"] * 2)
    u, p = credencial(cfg.get("cred_env", ""), url)
    if u:
        cl.set_user(u)
        cl.set_password(p or "")
    try:
        cl.connect()
    except Exception as e:
        inf.add("opcua", "Conexión OPC UA", url, f"sin conexión ({e})", NC)
        return
    inf.add("opcua_anon" if not u else "opcua_user", "Acceso OPC UA",
            "con usuario" if cfg.get("cred_env") else "-",
            "anónimo aceptado" if not u else f"usuario {u}",
            DESV if (not u and cfg.get("cred_env")) else INFO, MEDIA)
    try:
        for n in nodos:
            try:
                v = cl.get_node(n["nodeid"]).read_value()
            except Exception as e:
                inf.add("opcua_" + n.get("nombre", n["nodeid"]), n.get("nombre", n["nodeid"]),
                        n.get("esperado"), f"error: {e}", NC)
                continue
            pausa()
            exp = n.get("esperado")
            tol = n.get("tolerancia")
            if n.get("maximo") is not None and isinstance(v, (int, float)):
                ok = float(v) <= float(n["maximo"])
            elif exp is None:
                ok = None
            elif isinstance(v, (int, float)) and tol is not None:
                ok = abs(float(v) - float(exp)) <= float(tol)
            else:
                ok = str(v) == str(exp)
            inf.obs("opcua:" + n.get("nombre", n["nodeid"]), v)
            inf.add("opcua_" + n.get("nombre", n["nodeid"]), n.get("nombre", n["nodeid"]),
                    exp if n.get("maximo") is None else f"≤ {n['maximo']}", v,
                    INFO if ok is None else (OK if ok else DESV), n.get("severidad", MEDIA),
                    recomendacion="" if ok in (None, True) else n.get("recomendacion", "Parámetro distinto de la línea base: verificar si el cambio está autorizado."))
    finally:
        try:
            cl.disconnect()
        except Exception:
            pass


# ─────────────────────────────────────────────── 7. switch Cisco por SSH ──
def comprobar_cisco(inf, ip, esp, carpeta_copias):
    try:
        from netmiko import ConnectHandler
    except ImportError:
        inf.add("ssh", "Configuración por SSH", "-", "netmiko no instalado", NC, recomendacion="pip install netmiko")
        return
    u, p = credencial(esp.get("cred_env", "OT_SSH"), f"SSH {ip}")
    if not u:
        inf.add("ssh", "Configuración por SSH", "-", "sin credenciales", NC)
        return
    try:
        con = ConnectHandler(device_type=esp.get("netmiko_tipo", "cisco_ios"), host=ip, username=u,
                             password=p, timeout=AJUSTES["timeout_s"] * 5)
        cfg = con.send_command("show running-config")
        ver = con.send_command("show version")
        con.disconnect()
    except Exception as e:
        inf.add("ssh", "Configuración por SSH", "accesible", f"error: {e}", NC)
        return
    m = re.search(r"Version\s+([\w.()]+)", ver)
    if m:
        inf.obs("firmware", m.group(1))
    for regla in esp.get("debe_contener", []):
        patron = regla["patron"] if isinstance(regla, dict) else regla
        ok = re.search(patron, cfg, re.M) is not None
        inf.add("cfg+" + patron, f"Debe contener «{patron}»", "presente", "presente" if ok else "AUSENTE",
                OK if ok else DESV, (regla.get("severidad") if isinstance(regla, dict) else None) or MEDIA,
                recomendacion="" if ok else (regla.get("recomendacion", "") if isinstance(regla, dict) else ""))
    for regla in esp.get("no_debe_contener", []):
        patron = regla["patron"] if isinstance(regla, dict) else regla
        m = re.search(patron, cfg, re.M)
        inf.add("cfg-" + patron, f"No debe contener «{patron}»", "ausente", f"PRESENTE: {m.group(0).strip()}" if m else "ausente",
                DESV if m else OK, (regla.get("severidad") if isinstance(regla, dict) else None) or MEDIA,
                recomendacion=(regla.get("recomendacion", "") if isinstance(regla, dict) else "") if m else "")
    # Copia y comparación con la anterior
    os.makedirs(carpeta_copias, exist_ok=True)
    nombre = re.sub(r"[^\w.-]+", "_", inf.d["nombre"] or ip)
    previas = sorted(f for f in os.listdir(carpeta_copias) if f.startswith(nombre + "_"))
    marca = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    nueva = os.path.join(carpeta_copias, f"{nombre}_{marca}.txt")
    limpia = lambda t: [l for l in t.splitlines() if not re.match(r"^(! Last configuration change|! NVRAM config last|ntp clock-period|Current configuration)", l)]
    with open(nueva, "w", encoding="utf-8") as f:
        f.write(cfg)
    if previas:
        with open(os.path.join(carpeta_copias, previas[-1]), encoding="utf-8") as f:
            ant = f.read()
        dif = [l for l in difflib.unified_diff(limpia(ant), limpia(cfg), previas[-1], os.path.basename(nueva), lineterm="", n=0)
               if l[:1] in "+-" and not l.startswith(("+++", "---"))]
        inf.add("cfg_cambios", "Cambios desde la copia anterior", "ninguno no autorizado",
                f"{len(dif)} línea(s) cambiada(s)" if dif else "sin cambios",
                DESV if dif else OK, MEDIA, evidencia="\n".join(dif[:40]),
                recomendacion="Revisar cada cambio y comprobar que está registrado en la gestión de cambios." if dif else "")
    else:
        inf.add("cfg_cambios", "Copia de la configuración", "-", f"primera copia guardada en {nueva}", INFO, BAJA)


# ──────────────────────────────────────────── 8. firmware y avisos (criterio c) ──
def comprobar_firmware(inf, esp):
    fw = inf.d["observado"].get("firmware")
    minimo = esp.get("fw_minimo")
    if minimo:
        if not fw:
            inf.add("fw", "Versión de firmware", f"≥ {minimo}", "no se pudo leer", NC)
        else:
            menor = version_menor(fw, minimo)
            inf.add("fw", "Versión de firmware", f"≥ {minimo}", fw,
                    NC if menor is None else (DESV if menor else OK), MEDIA,
                    recomendacion="Planificar la actualización del firmware (en parada y con copia del proyecto)." if menor else "")
    for av in esp.get("avisos", []):
        corr = av.get("corregido_en")
        ident = av.get("id", "aviso")
        if not fw or not corr:
            inf.add("aviso_" + ident, f"Aviso {ident}", f"firmware ≥ {corr}", fw or "firmware desconocido", NC)
            continue
        vuln = version_menor(fw, corr)
        inf.add("aviso_" + ident, f"Aviso {ident}" + (f" ({av['titulo']})" if av.get("titulo") else ""),
                f"firmware ≥ {corr}", fw + (" → VULNERABLE" if vuln else ""),
                NC if vuln is None else (DESV if vuln else OK), av.get("severidad", ALTA),
                evidencia=av.get("cve", ""),
                recomendacion=av.get("mitigacion", "Aplicar la actualización o las mitigaciones del aviso del fabricante.") if vuln else "")


def comprobar_referencia(inf, esp):
    ref = esp.get("referencia")
    real = inf.d["observado"].get("referencia")
    if ref and real:
        n = lambda s: re.sub(r"\s+", "", str(s)).upper()
        inf.add("referencia", "Referencia del equipo", ref, real, OK if n(ref) == n(real) else DESV, MEDIA,
                recomendacion="" if n(ref) == n(real) else "El equipo no coincide con el inventario: actualizar el inventario o investigar la sustitución.")


# ─────────────────────────────────────────── 9. descubrimiento PROFINET DCP ──
def descubrir_dcp(base):
    cfg = (base.get("ajustes") or {}).get("dcp") or {}
    if not cfg.get("activar"):
        return None
    try:
        import pnio_dcp
    except ImportError:
        print("  DCP: pnio_dcp no instalado (pip install pnio_dcp). Se omite.")
        return {"error": "pnio_dcp no instalado"}
    ip_local = cfg.get("ip_interfaz") or ""
    if not ip_local:
        return {"error": "Falta ajustes.dcp.ip_interfaz (IP del PC en la VLAN de la célula)"}
    print(f"  DCP Identify (solo lectura) desde {ip_local}…")
    try:
        dcp = pnio_dcp.DCP(ip_local)
        equipos = dcp.identify_all()       # ¡nunca set_name_of_station / set_ip_address!
    except Exception as e:
        return {"error": str(e)}
    out = []
    for d in equipos:
        out.append({"nombre_pn": getattr(d, "name_of_station", ""), "ip": getattr(d, "IP", ""),
                    "mac": getattr(d, "MAC", ""), "familia": getattr(d, "family", "")})
    return {"equipos": out}


# ─────────────────────────────────────────────────────────────── principal ──
PERFILES = {
    "plc_s7":      ["puertos", "snmp", "s7", "web", "opcua"],
    "hmi":         ["puertos", "snmp", "web"],
    "vfd_g120":    ["puertos", "snmp", "web"],
    "iolink_ifm":  ["puertos", "snmp", "ifm"],
    "switch_cisco": ["puertos", "snmp", "ssh"],
    "scalance":    ["puertos", "snmp", "web"],
    "generico":    ["puertos", "snmp", "web"],
}


def verificar_dispositivo(disp, base, args):
    perfil = disp.get("perfil", "generico")
    esp = disp.get("esperado") or {}
    ip = disp.get("ip", "")
    activas = disp.get("comprobaciones") or PERFILES.get(perfil, PERFILES["generico"])
    inf = Informe(disp)
    print(f"\n▶ {disp.get('nombre', ip)}  [{perfil}]  {ip}")
    if not ip:
        inf.add("ip", "Dirección IP", "definida", "sin IP en la línea base", NC)
        return inf.d
    ajustes = base.get("ajustes") or {}
    comunidades = ajustes.get("snmp_comunidades") or ["public", "private"]
    if "puertos" in activas:
        comprobar_puertos(inf, ip, esp)
    if "snmp" in activas and esp.get("snmp") != "omitir":
        comprobar_snmp(inf, ip, esp, comunidades)
    if "s7" in activas:
        comprobar_s7(inf, ip, esp)
    if "web" in activas:
        comprobar_web(inf, ip, esp)
    if "ifm" in activas:
        comprobar_ifm(inf, ip, esp, ajustes)
    if "opcua" in activas:
        comprobar_opcua(inf, ip, esp)
    if "ssh" in activas:
        comprobar_cisco(inf, ip, esp, args.copias)
    comprobar_referencia(inf, esp)
    comprobar_firmware(inf, esp)
    return inf.d


def comparar_dcp(dcp, base, resultado):
    if not dcp:
        return
    if dcp.get("error"):
        resultado["dcp"] = dcp
        return
    conocidos = {d.get("ip"): d for d in base.get("dispositivos", [])}
    desconocidos = []
    for eq in dcp["equipos"]:
        d = conocidos.get(eq["ip"])
        if not d:
            desconocidos.append(eq)
            continue
        esp = (d.get("esperado") or {}).get("nombre_pn")
        r = next((x for x in resultado["dispositivos"] if x["ip"] == eq["ip"]), None)
        if r is not None:
            r["observado"]["nombre_pn"] = eq["nombre_pn"]
            if esp:
                ok = eq["nombre_pn"] == esp
                r["comprobaciones"].append({"id": "dcp_nombre", "descripcion": "Nombre de estación PROFINET",
                                            "esperado": esp, "real": eq["nombre_pn"], "estado": OK if ok else DESV,
                                            "severidad": "" if ok else MEDIA, "evidencia": f"MAC {eq['mac']}",
                                            "recomendacion": "" if ok else "Nombre PROFINET cambiado: posible DCP Set no autorizado; el PLC perderá la comunicación con el equipo."})
    resultado["dcp"] = {"equipos": dcp["equipos"], "desconocidos": desconocidos}
    for eq in desconocidos:
        print(f"   !!  [MEDIA] Equipo PROFINET no inventariado: {eq['nombre_pn']} {eq['ip']} {eq['mac']}")


def resumen(res):
    r = {"OK": 0, "DESVIACION": 0, "NO_COMPROBABLE": 0, "INFO": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}
    for d in res["dispositivos"]:
        for c in d["comprobaciones"]:
            r[c["estado"]] = r.get(c["estado"], 0) + 1
            if c["estado"] == DESV and c["severidad"]:
                r[c["severidad"]] += 1
    r["equipos_no_inventariados"] = len((res.get("dcp") or {}).get("desconocidos", []))
    return r


def mostrar_plan(base):
    print("PLAN (no se envía nada a la red):")
    for d in base.get("dispositivos", []):
        act = d.get("comprobaciones") or PERFILES.get(d.get("perfil", "generico"))
        esp = d.get("esperado") or {}
        pts = esp.get("puertos_abiertos", []) + esp.get("puertos_cerrados", [])
        print(f"  · {d.get('nombre')} {d.get('ip')} [{d.get('perfil')}] → {', '.join(act)}"
              + (f" · puertos {pts}" if pts else ""))
    if ((base.get("ajustes") or {}).get("dcp") or {}).get("activar"):
        print("  · DCP Identify en la VLAN de la célula")


def main():
    ap = argparse.ArgumentParser(description="Toolbox-OT · verificación de configuración de una célula OT (solo lectura)")
    ap.add_argument("linea_base", help="archivo JSON de línea base (ot-baseline/1.0)")
    ap.add_argument("-o", "--salida", help="archivo de resultados (por defecto resultado_<celda>_<fecha>.json)")
    ap.add_argument("--plan", action="store_true", help="solo muestra qué se consultaría, sin tocar la red")
    ap.add_argument("--copias", default="copias_config", help="carpeta para las copias de configuración por SSH")
    ap.add_argument("--si", action="store_true", help="no pedir confirmación antes de empezar")
    args = ap.parse_args()

    with open(args.linea_base, encoding="utf-8") as f:
        base = json.load(f)
    if base.get("schema") != ESQUEMA_BASE:
        print(f"Aviso: el esquema es «{base.get('schema')}», se esperaba «{ESQUEMA_BASE}».")
    AJUSTES.update({k: v for k, v in (base.get("ajustes") or {}).items() if k in ("timeout_s", "pausa_s")})
    celda = base.get("celda") or {}
    print(f"Toolbox-OT v1.7 · Verificación OT v{VERSION}")
    print(f"Célula: {celda.get('nombre', '?')}  ·  VLAN {celda.get('vlan', '?')}  ·  {len(base.get('dispositivos', []))} equipos")
    if args.plan:
        mostrar_plan(base)
        return
    if not args.si and sys.stdin.isatty():
        print("\nSe van a enviar consultas de SOLO LECTURA a los equipos de la célula.")
        if input("¿Tienes autorización y la instalación está en un estado seguro? (s/N) ").strip().lower() != "s":
            print("Cancelado.")
            return

    inicio = _dt.datetime.now()
    resultado = {
        "schema": ESQUEMA_RES,
        "herramienta": f"verificar_celda.py v{VERSION}",
        "celda": celda,
        "linea_base": os.path.basename(args.linea_base),
        "fecha": inicio.isoformat(timespec="seconds"),
        "equipo_origen": {"host": socket.gethostname(), "so": platform.platform()},
        "dispositivos": [],
    }
    dcp = descubrir_dcp(base)
    for d in base.get("dispositivos", []):
        resultado["dispositivos"].append(verificar_dispositivo(d, base, args))
    comparar_dcp(dcp, base, resultado)
    resultado["duracion_s"] = round((_dt.datetime.now() - inicio).total_seconds(), 1)
    resultado["resumen"] = resumen(resultado)

    salida = args.salida or "resultado_{}_{}.json".format(
        re.sub(r"[^\w-]+", "_", celda.get("nombre", "celda")).strip("_").lower(), inicio.strftime("%Y%m%d_%H%M"))
    with open(salida, "w", encoding="utf-8") as f:
        json.dump(resultado, f, ensure_ascii=False, indent=2)
    r = resultado["resumen"]
    print(f"\nResumen: {r['OK']} OK · {r['DESVIACION']} desviaciones (ALTA {r['ALTA']}, MEDIA {r['MEDIA']}, BAJA {r['BAJA']})"
          f" · {r['NO_COMPROBABLE']} no comprobables")
    print(f"Resultados guardados en {salida}. Cárgalos en Toolbox-OT › Verificación OT.")


if __name__ == "__main__":
    main()
