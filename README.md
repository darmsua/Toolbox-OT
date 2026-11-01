# Toolbox-OT v1.0

**Caja de herramientas educativa para ciberseguridad en Tecnologías de la Operación (OT/ICS).**

Dos aplicaciones web independientes que trabajan juntas mediante un archivo JSON:

- **Editor Red OT** — diseña la arquitectura de la planta según el **modelo Purdue** (niveles N0–N4): paleta de dispositivos, conductos con protocolo, zonas IEC 62443 con SL-T, zoom/minimapa, y exportación a JSON e imagen (PNG/JPG/PDF).
- **Análisis de Riesgo OT/ICS** — evalúa el riesgo en 7 pasos combinando **IEC 62443-3-2** (zonas y conductos), **MAGERIT v3** (valoración D·I·C·A·T + Safety + Medioambiente) y **MITRE ATT&CK for ICS** (amenazas). Importa el esquema de Red OT y genera informes.

Todo es **HTML estático**: funciona sin conexión y sin instalar nada. El trabajo se guarda en el navegador (`localStorage`) del propio equipo; nada sale del ordenador.

---

## Uso

### Opción A — Online (GitHub Pages)
Una vez publicado el repositorio con Pages activado (ver más abajo), abre:

```
https://TU_USUARIO.github.io/toolbox-ot/
```

### Opción B — Offline (descarga)
1. Descarga el repositorio (botón **Code → Download ZIP**) o el paquete listo de la carpeta [`dist/`](dist/).
2. Descomprime y abre **`index.html`** con un navegador (Chrome, Edge, Firefox). Doble clic.

---

## Flujo de trabajo

1. En el **Editor Red OT**: coloca los dispositivos por niveles, conéctalos y dibuja las zonas con su SL-T. Exporta el **JSON**.
2. En **Análisis de Riesgo**: *Menú → Importar desde Red OT* (puedes probar con [`ejemplo_red_ot.json`](ejemplo_red_ot.json)). Se crean activos, zonas y conductos.
3. Valora los activos (MAGERIT), define escenarios de amenaza (ATT&CK ICS) y revisa el riesgo por zona frente al SL-T.

---

## Contenido del repositorio

| Archivo | Descripción |
|---|---|
| `index.html` | Lanzador de la suite (ábrelo primero) |
| `redot.html` | Editor Red OT (esquemas Purdue) |
| `riesgo.html` | Análisis de Riesgo OT/ICS |
| `ejemplo_red_ot.json` | Esquema de ejemplo para importar en el análisis |
| `dist/Toolbox-OT-v1.0.zip` | Paquete completo listo para distribuir (offline) |
| `LICENSE` | Términos de uso (CC BY 4.0) |

---

## Publicar en GitHub Pages

1. Sube este repositorio a GitHub como **público**.
2. En el repositorio: **Settings → Pages**.
3. En *Build and deployment → Source* elige **Deploy from a branch**.
4. *Branch*: `main` · carpeta `/ (root)` → **Save**.
5. Espera ~1 minuto. La URL aparece en esa misma página: `https://TU_USUARIO.github.io/toolbox-ot/`.

Para distribuir a los alumnos puedes enlazar esa URL (p. ej. desde EVAGD) o subir el `.zip` de `dist/` como recurso descargable.

---

## Créditos y licencia

Aplicación concebida e **inspirada por David de Armas Suárez** · conecta3@hotmail.com
**Propulsada por Claude.ai** (Anthropic) · *boosted by Claude.ai*.

Distribuida bajo **Creative Commons Reconocimiento 4.0 Internacional (CC BY 4.0)**: libre uso, copia, modificación y redistribución —incluso comercial— **citando la autoría**. Ver [`LICENSE`](LICENSE) · <https://creativecommons.org/licenses/by/4.0/deed.es>

> Material educativo. No sustituye un análisis de riesgos profesional conforme a la norma IEC 62443.
