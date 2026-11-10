from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_SALTO = 10  
_FORMATO_CABECERA = ">32sII"  
LONGITUD_CABECERA = struct.calcsize(_FORMATO_CABECERA)  


class ErrorRatchet(Exception):
    """Error general del ratchet."""


class MensajeRechazado(ErrorRatchet):
    """El mensaje se rechaza: alterado, repetido, demasiado viejo o inválido."""


def clave_publica_bytes(privada: X25519PrivateKey) -> bytes:
    """Clave pública X25519 en formato crudo (32 bytes)."""
    return privada.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def clave_privada_bytes(privada: X25519PrivateKey) -> bytes:
    """Clave privada X25519 en formato crudo (solo para simular el robo de estado)."""
    return privada.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def dh(privada: X25519PrivateKey, publica_bytes: bytes) -> bytes:
    """Secreto compartido Diffie-Hellman X25519."""
    return privada.exchange(X25519PublicKey.from_public_bytes(publica_bytes))


def kdf_rk(clave_raiz: bytes, salida_dh: bytes) -> tuple[bytes, bytes]:
    """KDF de la clave raíz: HKDF-SHA256(sal=clave_raiz, entrada=salida DH).

    Devuelve (nueva_clave_raiz, nueva_clave_de_cadena).
    """
    salida = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=clave_raiz, info=b"A2|ratchet-raiz"
    ).derive(salida_dh)
    return salida[:32], salida[32:]


def kdf_ck(clave_cadena: bytes) -> tuple[bytes, bytes]:
    """KDF de cadena: HMAC-SHA256 con constantes 0x01 y 0x02 (como en la especificación).

    Devuelve (clave_de_mensaje, nueva_clave_de_cadena).
    """
    clave_mensaje = hmac.new(clave_cadena, b"\x01", hashlib.sha256).digest()
    nueva_cadena = hmac.new(clave_cadena, b"\x02", hashlib.sha256).digest()
    return clave_mensaje, nueva_cadena


def _clave_y_nonce(clave_mensaje: bytes) -> tuple[bytes, bytes]:
    material = HKDF(
        algorithm=hashes.SHA256(), length=44, salt=b"\x00" * 32, info=b"A2|cifrado-de-mensaje"
    ).derive(clave_mensaje)
    return material[:32], material[32:]


def cifrar_con_clave_mensaje(clave_mensaje: bytes, texto: bytes, ad: bytes) -> bytes:
    """AES-256-GCM con clave y nonce derivados de la clave de mensaje (que se usa una sola vez)."""
    clave, nonce = _clave_y_nonce(clave_mensaje)
    return AESGCM(clave).encrypt(nonce, texto, ad)


def descifrar_con_clave_mensaje(clave_mensaje: bytes, cifrado: bytes, ad: bytes) -> bytes:
    """Inverso de `cifrar_con_clave_mensaje`. Lanza `InvalidTag` si algo no cuadra."""
    clave, nonce = _clave_y_nonce(clave_mensaje)
    return AESGCM(clave).decrypt(nonce, cifrado, ad)

class Ratchet:
    """Un extremo de la conversación.

    Se crea con `Ratchet.iniciar_emisor` (quien habla primero) o
    `Ratchet.iniciar_receptor` (quien recibe primero).
    Métodos principales: `enviar`, `recibir` y `cambiar_direccion`.
    """

    def __init__(self, nombre: str, ad: bytes = b""):
        self.nombre = nombre
        self._ad = ad  
        self._dhs: X25519PrivateKey | None = None  
        self._dhr: bytes | None = None  
        self._rk: bytes = b""  
        self._cks: bytes | None = None  
        self._ckr: bytes | None = None  
        self._ns = 0  
        self._nr = 0  
        self._pn = 0  
        self._omitidas: dict[tuple[bytes, int], bytes] = {}  
        self._remotas_vistas: set[bytes] = set()  
        self._girar_pendiente = False  

    @classmethod
    def iniciar_emisor(cls, secreto: bytes, publica_receptor: bytes, nombre="A", ad=b"") -> "Ratchet":
        """Quien envía primero: conoce la clave pública DH inicial del receptor."""
        r = cls(nombre, ad)
        r._dhs = X25519PrivateKey.generate()
        r._dhr = publica_receptor
        r._rk, r._cks = kdf_rk(secreto, dh(r._dhs, r._dhr))
        return r

    @classmethod
    def iniciar_receptor(cls, secreto: bytes, par_inicial: X25519PrivateKey, nombre="B", ad=b"") -> "Ratchet":
        """Quien recibe primero: tiene el par DH inicial cuya pública conoce el emisor."""
        r = cls(nombre, ad)
        r._dhs = par_inicial
        r._rk = secreto
        return r

    def cambiar_direccion(self) -> None:
        """Genera un NUEVO par X25519 y renueva la clave raíz y la cadena de envío."""
        if self._dhr is None:
            raise ErrorRatchet("no hay clave remota: aún no se puede cambiar de dirección")
        self._pn = self._ns
        self._ns = 0
        self._dhs = X25519PrivateKey.generate()
        self._rk, self._cks = kdf_rk(self._rk, dh(self._dhs, self._dhr))
        self._girar_pendiente = False

    # ---- envío
    def enviar(self, texto: str | bytes) -> bytes:
        """Cifra `texto` y devuelve el mensaje de red: cabecera (40 B) + texto cifrado."""
        if isinstance(texto, str):
            texto = texto.encode("utf-8")
        if self._girar_pendiente:
            self.cambiar_direccion()
        if self._cks is None:
            raise ErrorRatchet("este participante debe recibir un mensaje antes de poder enviar")
        clave_mensaje, self._cks = kdf_ck(self._cks)
        cabecera = struct.pack(_FORMATO_CABECERA, clave_publica_bytes(self._dhs), self._pn, self._ns)
        self._ns += 1
        return cabecera + cifrar_con_clave_mensaje(clave_mensaje, texto, self._ad + cabecera)


    def recibir(self, mensaje: bytes) -> bytes:
        """Descifra un mensaje. Lanza `MensajeRechazado` si está alterado, repetido o es inválido.

        Si el mensaje se rechaza, el estado interno queda exactamente igual que antes,
        de modo que un atacante no puede dañar la sesión inyectando basura.
        """
        copia = self._copiar_estado()
        try:
            return self._recibir(mensaje)
        except MensajeRechazado:
            self._restaurar_estado(copia)
            raise
        except (InvalidTag, ValueError, struct.error) as exc:
            self._restaurar_estado(copia)
            raise MensajeRechazado(f"mensaje rechazado: {type(exc).__name__}") from exc

    def _recibir(self, mensaje: bytes) -> bytes:
        if len(mensaje) < LONGITUD_CABECERA + 16:
            raise MensajeRechazado("mensaje demasiado corto")
        cabecera, cifrado = mensaje[:LONGITUD_CABECERA], mensaje[LONGITUD_CABECERA:]
        dh_remota, pn, n = struct.unpack(_FORMATO_CABECERA, cabecera)
        ad = self._ad + cabecera

        clave_guardada = self._omitidas.pop((dh_remota, n), None)
        if clave_guardada is not None:
            return descifrar_con_clave_mensaje(clave_guardada, cifrado, ad)

        if dh_remota != self._dhr:
            if dh_remota in self._remotas_vistas:
                raise MensajeRechazado("repetición: pertenece a una cadena ya cerrada")
            self._saltar_hasta(pn)  
            self._paso_dh_recepcion(dh_remota)

        if n < self._nr:
            raise MensajeRechazado("repetición: este número de mensaje ya fue procesado")
        self._saltar_hasta(n)
        clave_mensaje, self._ckr = kdf_ck(self._ckr)
        self._nr += 1
        return descifrar_con_clave_mensaje(clave_mensaje, cifrado, ad)

    def _saltar_hasta(self, hasta: int) -> None:
        if self._ckr is None:
            return
        if hasta - self._nr > MAX_SALTO:
            raise MensajeRechazado("demasiados mensajes salteados")
        while self._nr < hasta:
            clave_mensaje, self._ckr = kdf_ck(self._ckr)
            self._omitidas[(self._dhr, self._nr)] = clave_mensaje
            self._nr += 1

    def _paso_dh_recepcion(self, dh_remota: bytes) -> None:
        if self._dhr is not None:
            self._remotas_vistas.add(self._dhr)
        self._dhr = dh_remota
        self._nr = 0
        self._rk, self._ckr = kdf_rk(self._rk, dh(self._dhs, self._dhr))
        self._girar_pendiente = True  

    def _copiar_estado(self) -> dict:
        copia = dict(self.__dict__)
        copia["_omitidas"] = dict(self._omitidas)
        copia["_remotas_vistas"] = set(self._remotas_vistas)
        return copia

    def _restaurar_estado(self, copia: dict) -> None:
        self.__dict__.update(copia)

    def exportar_estado(self) -> dict:
        """Copia COMPLETA del estado secreto, como la tendría un atacante que roba el dispositivo."""
        return {
            "nombre": self.nombre,
            "ad": self._ad,
            "dhs_privada": clave_privada_bytes(self._dhs),
            "dhr": self._dhr,
            "rk": self._rk,
            "cks": self._cks,
            "ckr": self._ckr,
            "ns": self._ns,
            "nr": self._nr,
            "pn": self._pn,
            "omitidas": dict(self._omitidas),
            "remotas_vistas": set(self._remotas_vistas),
            "girar_pendiente": self._girar_pendiente,
        }

    @classmethod
    def desde_estado(cls, estado: dict) -> "Ratchet":
        """Reconstruye un Ratchet a partir de un estado exportado (lo que haría el atacante)."""
        r = cls(estado["nombre"], estado["ad"])
        r._dhs = X25519PrivateKey.from_private_bytes(estado["dhs_privada"])
        r._dhr = estado["dhr"]
        r._rk, r._cks, r._ckr = estado["rk"], estado["cks"], estado["ckr"]
        r._ns, r._nr, r._pn = estado["ns"], estado["nr"], estado["pn"]
        r._omitidas = dict(estado["omitidas"])
        r._remotas_vistas = set(estado["remotas_vistas"])
        r._girar_pendiente = estado["girar_pendiente"]
        return r


def crear_sesion(ad: bytes = b"") -> tuple[Ratchet, Ratchet]:
    """Crea (alice, bob) con un secreto inicial aleatorio. Sustituye al acuerdo X3DH."""
    secreto = os.urandom(32)
    par_bob = X25519PrivateKey.generate()
    alice = Ratchet.iniciar_emisor(secreto, clave_publica_bytes(par_bob), nombre="Alice", ad=ad)
    bob = Ratchet.iniciar_receptor(secreto, par_bob, nombre="Bob", ad=ad)
    return alice, bob


def demo() -> None:
    """Conversación de 6 mensajes con cambios de dirección (se ejecuta en memoria)."""
    alice, bob = crear_sesion()
    pasos = [
        (alice, bob, "1. Alice -> Bob: hola"),
        (alice, bob, "2. Alice -> Bob: ¿cómo vas con el taller?"),
        (alice, bob, "3. Alice -> Bob: ya casi termino"),
        (bob, alice, "4. Bob -> Alice: yo también"),  
        (bob, alice, "5. Bob -> Alice: nos vemos mañana"),
        (alice, bob, "6. Alice -> Bob: listo, adiós"),  
    ]
    for emisor, receptor, texto in pasos:
        if emisor._girar_pendiente:
            emisor.cambiar_direccion()
            print(f"   ({emisor.nombre} genera un par X25519 nuevo)")
        claro = receptor.recibir(emisor.enviar(texto)).decode("utf-8")
        print(f"{claro}  [OK]")


if __name__ == "__main__":
    demo()
