# Taller individual: Seguridad en Messenger

**Autor:** Carlos Abiecer Velez Cardona
**Curso:** Sistemas Distribuidos · **Entrega:** 10/11/2026

Implementación educativa y local de dos algoritmos de mensajería segura:
**A1** (cadena de claves simétrica con HKDF) y **A2** (Double Ratchet reducido con X25519).
Todo corre en un solo proceso, en memoria, sin red ni datos reales (Ley 1581 de 2012).

## Requisitos

- Python 3.11 o superior
- Bibliotecas: `cryptography` y `pytest` (ver `requirements.txt`)

## Instalar dependencias

```bash
python -m venv .venv
source .venv/bin/activate          # Windows (PowerShell): .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Ejecutar las pruebas (un solo comando)

```bash
python -m pytest -q
```

Resultado esperado: `9 passed`. Al terminar se (re)generan `resultados.csv` y `log_pruebas.json`
con el resultado real de cada prueba. Para ver la conversación de 6 mensajes: `python a2_ratchet.py`.

## Archivos

| Archivo | Contenido |
| --- | --- |
| `ficha.md` | Ficha del concepto (E2EE y forward secrecy) |
| `a1_cadena.py`, `test_a1.py` | A1 y sus pruebas (A1-01 a A1-04) |
| `a2_ratchet.py`, `test_a2.py` | A2 y sus pruebas (A2-01 a A2-05) |
| `conftest.py` | Genera `resultados.csv` y `log_pruebas.json` al ejecutar pytest |
| `resultados.csv`, `log_pruebas.json` | Resultados de las 9 pruebas |
| `informe.md` | Informe corto |

Las funciones de prueba se llaman igual que las filas de la tabla, cambiando el guion por guion bajo

