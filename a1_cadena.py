from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LONGITUD_CLAVE = 32  
LONGITUD_NONCE = 12  

_INFO_MENSAJE = b"A1|clave-de-mensaje|"
_INFO_CADENA = b"A1|avance-de-cadena"


def derivar_clave(cadena: bytes, indice: int) -> bytes:
    """Deriva la clave de mensaje número `indice` a partir de `cadena`.

    Usa HKDF-SHA256 (RFC 5869). Es determinista: la misma `cadena` y el mismo
    `indice` producen siempre la misma clave de 32 bytes; índices distintos
    producen claves distintas e independientes.

    Args:
        cadena: clave de cadena (bytes o bytearray, normalmente 32 bytes).
        indice: número del mensaje (entero >= 0).

    Returns:
        Clave de 32 bytes lista para usar con `cifrar`.

    Raises:
        ValueError: si `indice` es negativo o `cadena` está vacía.
    """
    if indice < 0:
        raise ValueError("el índice debe ser >= 0")
    if len(cadena) == 0:
        raise ValueError("la clave de cadena no puede estar vacía")
    info = _INFO_MENSAJE + indice.to_bytes(8, "big")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=LONGITUD_CLAVE, salt=None, info=info)
    return hkdf.derive(bytes(cadena))


def avanzar_cadena(cadena: bytes) -> bytes:
    """Calcula la SIGUIENTE clave de cadena (función de un solo sentido).

    Como HKDF no es invertible, desde la clave nueva no se puede volver a la
    anterior: esa es la base del secreto hacia adelante.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=LONGITUD_CLAVE, salt=None, info=_INFO_CADENA)
    return hkdf.derive(bytes(cadena))


def borrar(secreto: bytearray) -> None:
    """Sobrescribe con ceros un secreto guardado en un `bytearray`.

    Los `bytes` de Python son inmutables y no se pueden borrar; por eso las
    claves se manejan como `bytearray`.
    """
    for i in range(len(secreto)):
        secreto[i] = 0


def cifrar(clave: bytes, texto: str | bytes, datos_asociados: bytes = b"") -> bytes:
    """Cifra `texto` con AES-256-GCM (cifrado autenticado).

    Args:
        clave: clave de 32 bytes (por ejemplo, la salida de `derivar_clave`).
        texto: mensaje en claro (str se codifica en UTF-8).
        datos_asociados: datos que se autentican pero no se cifran (opcional).

    Returns:
        nonce (12 bytes) + texto cifrado + etiqueta de autenticación.
    """
    if isinstance(texto, str):
        texto = texto.encode("utf-8")
    nonce = os.urandom(LONGITUD_NONCE)
    return nonce + AESGCM(bytes(clave)).encrypt(nonce, texto, datos_asociados)


def descifrar(clave: bytes, paquete: bytes, datos_asociados: bytes = b"") -> bytes:
    """Descifra lo producido por `cifrar`.

    Raises:
        ValueError: si la clave es incorrecta o el paquete fue alterado.
    """
    if len(paquete) < LONGITUD_NONCE + 16:
        raise ValueError("paquete demasiado corto")
    nonce, cuerpo = paquete[:LONGITUD_NONCE], paquete[LONGITUD_NONCE:]
    try:
        return AESGCM(bytes(clave)).decrypt(nonce, cuerpo, datos_asociados)
    except InvalidTag as exc:
        raise ValueError("autenticación fallida: clave incorrecta o mensaje alterado") from exc


class CadenaClaves:
    """Cadena de claves que entrega cada clave de mensaje una sola vez.

    En cada llamada a `siguiente_clave`:
      1. deriva la clave del mensaje con `derivar_clave`;
      2. calcula la nueva clave de cadena con `avanzar_cadena`;
      3. BORRA la clave de cadena anterior.
    """

    def __init__(self, clave_inicial: bytes):
        self._cadena = bytearray(clave_inicial)
        self._indice = 0

    @property
    def indice(self) -> int:
        """Número de claves ya entregadas."""
        return self._indice

    def siguiente_clave(self) -> tuple[int, bytearray]:
        """Devuelve (indice, clave_de_mensaje). La clave es un bytearray para poder borrarla."""
        indice = self._indice
        clave = bytearray(derivar_clave(self._cadena, indice))
        nueva = bytearray(avanzar_cadena(self._cadena))
        borrar(self._cadena)  
        self._cadena = nueva
        self._indice += 1
        return indice, clave

    def estado(self) -> bytes:
        """Copia del estado actual de la cadena (lo que robaría un atacante hoy)."""
        return bytes(self._cadena)
