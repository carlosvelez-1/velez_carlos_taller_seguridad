import csv
import json
import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).parent

ENCABEZADO = ["id_prueba", "algoritmo", "propiedad", "descripcion", "esperado", "obtenido", "estado", "comentario"]

PLANTILLA = [
    ("A1-01", "A1", "determinismo", "Misma cadena e índice producen la misma clave", "misma clave"),
    ("A1-02", "A1", "unicidad", "10 claves de mensaje distintas", "10 claves distintas"),
    ("A1-03", "A1", "cifrado", "Cifrar y descifrar 10 mensajes", "10/10 correctos"),
    ("A1-04", "A1", "borrado", "Clave usada y luego borrada no se recupera", "no recuperable"),
    ("A2-01", "A2", "descifrado", "Descifrar los 6 mensajes", "6/6 correctos"),
    ("A2-02", "A2", "integridad", "Un byte alterado del ciphertext", "rechazado"),
    ("A2-03", "A2", "repetición", "Mensaje reenviado", "rechazado"),
    ("A2-04", "A2", "forward secrecy", "Estado robado tras mensaje 3 no descifra mensaje 1", "no descifrable"),
    ("A2-05", "A2", "post-compromise", "Estado robado antes del cambio de dirección no descifra tras él", "no descifrable"),
]
ESPERADO = {fila[0]: fila[4] for fila in PLANTILLA}

_obtenido: dict[str, str] = {}
_comentario: dict[str, str] = {}
_estado: dict[str, str] = {}


def _id_de(nombre_prueba: str):
    """'test_A2_04' -> 'A2-04' (None si el nombre no sigue el patrón)."""
    m = re.match(r"test_(A[12])_(\d\d)", nombre_prueba)
    return f"{m.group(1)}-{m.group(2)}" if m else None


@pytest.fixture
def registro(request):
    """Devuelve una función registro(obtenido, comentario) que guarda el resultado y lo compara."""
    id_prueba = _id_de(request.node.name)

    def _registrar(obtenido: str, comentario: str = "") -> None:
        _obtenido[id_prueba] = obtenido
        _comentario[id_prueba] = comentario
        assert obtenido == ESPERADO[id_prueba], f"{id_prueba}: esperado '{ESPERADO[id_prueba]}', obtenido '{obtenido}'"

    return _registrar


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    resultado = yield
    informe = resultado.get_result()
    id_prueba = _id_de(item.name)
    if id_prueba is None:
        return
    if informe.when == "call" or (informe.when == "setup" and informe.failed):
        _estado[id_prueba] = "OK" if informe.passed else "FALLA"
        if informe.failed and id_prueba not in _obtenido:
            error = call.excinfo.value if call.excinfo else "error"
            _obtenido[id_prueba] = f"error: {type(error).__name__}"
            _comentario[id_prueba] = str(error)[:200]


def pytest_sessionfinish(session, exitstatus):
    if not all(fila[0] in _estado for fila in PLANTILLA):
        return  
    filas, log = [], []
    for id_prueba, algoritmo, propiedad, descripcion, esperado in PLANTILLA:
        obtenido, estado = _obtenido.get(id_prueba, ""), _estado[id_prueba]
        filas.append([id_prueba, algoritmo, propiedad, descripcion, esperado, obtenido, estado,
                      _comentario.get(id_prueba, "")])
        log.append({"prueba": id_prueba, "esperado": esperado, "obtenido": obtenido, "estado": estado})
    with open(RAIZ / "resultados.csv", "w", newline="", encoding="utf-8") as f:
        escritor = csv.writer(f, lineterminator="\n")
        escritor.writerow(ENCABEZADO)
        escritor.writerows(filas)
    with open(RAIZ / "log_pruebas.json", "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
        f.write("\n")
