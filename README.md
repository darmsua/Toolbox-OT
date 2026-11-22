# Toolbox-OT v1.9

**Caja de herramientas educativa para ciberseguridad en Tecnologías de la Operación (OT/ICS).**

Cinco aplicaciones web independientes que trabajan juntas mediante archivos JSON:

| Herramienta | Para qué sirve | Marcos de referencia |
|---|---|---|
| **Editor Red OT** (`redot.html`) | Arquitectura de la planta según el **modelo Purdue** (N0–N4): dispositivos, conductos con protocolo, zonas con SL-T y **capa física** (zonas Z0–Z3/REM, puntos de acceso y controles). Exporta JSON e imagen | ISA-95 / Purdue, IEC 62443 |
| **Análisis de Riesgo OT/ICS** (`riesgo.html`) | Evaluación del riesgo en 7 pasos: zonas y conductos, valoración de activos y amenazas. Importa el esquema de Red OT y genera informe | IEC 62443-3-2, MAGERIT v3, MITRE ATT&CK for ICS |
| **Proveedores OT** (`proveedores.html`) | Cadena de suministro: criticidad, homologación, riesgos y documentos (pliego, NDA, SLA, acceso de terceros, FAT/SAT, baja) en Word y PDF | IEC 62443-2-4, ISO/IEC 27036, ISO 31000 |
| **Verificación OT** *(beta)* (`verificacion.html` + `verificar_celda.py`) | Línea base de una célula y comprobación con un script de **solo lectura**: firmware y avisos, PUT/GET, SNMP, servicios, IO-Link, switch | IEC 62443-3-3 |
| **Accesos OT** (`accesos.html`) | Identidades, cuentas y credenciales: inventario de cuentas por equipo, roles, terceros enlazados con su proveedor, certificados, excepciones, **bajas y cambios de puesto** y diagnóstico frente a la política | IEC 62443-3-3 FR1/FR2, ISO/IEC 27002, NIST SP 800-63B |

Todo es **HTML estático**: funciona sin conexión y sin instalar nada. El trabajo se guarda en el navegador (`localStorage`) del propio equipo; nada sale del ordenador.

---

## Uso

### Opción A — Online (GitHub Pages)

<https://darmsua.github.io/toolbox-ot/>

### Opción B — Offline (descarga)

1. Descarga el paquete listo de [`dist/Toolbox-OT-v1.9.zip`](dist/Toolbox-OT-v1.9.zip) (o el repositorio con **Code → Download ZIP**).
2. Descomprime y abre **`index.html`** con un navegador (Chrome, Edge o Firefox).

---

## Flujo de trabajo

1. **Editor Red OT**: coloca los dispositivos por niveles, conéctalos, dibuja las zonas con su SL-T y, si trabajas la seguridad física, asigna la zona física de cada equipo y añade los elementos de la pestaña *Físico*. Exporta el **JSON**.
2. **Análisis de Riesgo**: *Menú → Importar desde Red OT*. Valora los activos (MAGERIT), define escenarios de amenaza (ATT&CK for ICS) y revisa el riesgo por zona frente al SL-T.
3. **Proveedores OT**: *Proyecto → Importar activos desde JSON* con el mismo esquema. Clasifica y homologa a los proveedores, registra los riesgos de la cadena de suministro y genera la documentación.
4. **Verificación OT** *(beta)*: importa el esquema, crea la línea base de una célula y ejecuta en su VLAN:
   ```
   python verificar_celda.py linea_base_<celda>.json --plan   # no toca la red
   python verificar_celda.py linea_base_<celda>.json
   ```
   Carga el resultado y usa *Actualizar inventario Red OT* para llevar los hallazgos al análisis de riesgo.
5. **Accesos OT**: importa los activos desde Red OT y los proveedores desde Proveedores OT, y registra roles, personas y todas las cuentas de cada equipo (**nunca contraseñas**). El panel compara el inventario con la política; *Bajas y cambios* genera la lista de comprobación de una salida o un cambio de puesto.

Ejemplos incluidos: `ejemplo_red_ot.json`, `etap_el_lomo_v2_0.json` (caso ETAP El Lomo, común a Red OT, Proveedores OT y Accesos OT), `ejemplo_linea_base.json` y `ejemplo_resultado.json` (resultado simulado para practicar sin equipos). Proveedores OT y Accesos OT traen además sus propios proyectos de ejemplo en el menú.

---

## Contenido del repositorio

| Archivo | Descripción |
|---|---|
| `index.html` | Lanzador de la suite (ábrelo primero) |
| `redot.html` | Editor Red OT |
| `riesgo.html` | Análisis de Riesgo OT/ICS |
| `proveedores.html` | Proveedores OT |
| `verificacion.html` · `verificar_celda.py` | Verificación OT (beta) y su script |
| `accesos.html` | Accesos OT |
| `*.json` | Esquemas, línea base y resultado de ejemplo |
| `LÉEME.txt` | Instrucciones y novedades de cada versión |
| `dist/Toolbox-OT-v1.9.zip` | Paquete completo listo para distribuir (offline) |
| `LICENSE` · `LICENCIA.txt` | Términos de uso (CC BY 4.0) |

El script de Verificación OT necesita Python 3.9+. Bibliotecas opcionales: `pip install python-snap7 asyncua netmiko pnio_dcp`. Las contraseñas se pasan por variables de entorno, nunca en la línea base.

---

## Novedades

- **v1.9** — Capa física en Red OT. Campo *Fin del contrato* en Proveedores OT. Accesos OT importa la capa física y los proveedores y comprueba homologación, acceso remoto autorizado, alcance y fin de contrato de los terceros.
- **v1.8** — Nueva herramienta **Accesos OT** (RA4: credenciales y gestión de usuarios).
- **v1.7** — Nueva herramienta **Verificación OT** (beta).
- **v1.6** — Nueva herramienta **Proveedores OT**. Tema claro/oscuro común.

Detalle completo en [`LÉEME.txt`](LÉEME.txt).

---

## Créditos y licencia

Aplicación concebida e **inspirada por David de Armas Suárez** · conecta3@hotmail.com
**Propulsada por Claude.ai** (Anthropic) · *boosted by Claude.ai*.

Distribuida bajo **Creative Commons Reconocimiento 4.0 Internacional (CC BY 4.0)**: libre uso, copia, modificación y redistribución —incluso comercial— **citando la autoría**. Ver [`LICENSE`](LICENSE) · <https://creativecommons.org/licenses/by/4.0/deed.es>

> Material educativo. No sustituye un análisis de riesgos ni una auditoría profesionales conforme a la serie IEC 62443. Verificación OT y su script deben usarse solo en equipos de laboratorio o con autorización expresa del titular de la instalación.
