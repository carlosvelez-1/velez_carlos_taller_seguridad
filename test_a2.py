import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from a2_ratchet import (LONGITUD_CABECERA, MensajeRechazado, Ratchet, crear_sesion, dh,
                        descifrar_con_clave_mensaje, kdf_ck, kdf_rk)

TEXTOS = ["m1 hola", "m2 ¿cómo vas?", "m3 ya casi termino", "m4 yo también", "m5 nos vemos", "m6 adiós"]


def escenario():
    """Ejecuta la conversación. Devuelve alice, bob, los 6 mensajes de red y copias de estado robadas."""
    alice, bob = crear_sesion()
    robos = {"bob_inicial": bob.exportar_estado()}
    msgs = []
    for i in range(3):
        msgs.append(alice.enviar(TEXTOS[i]))
        assert bob.recibir(msgs[i]).decode() == TEXTOS[i]
    robos["bob_tras_m3"] = bob.exportar_estado()  
    robos["alice_tras_m3"] = alice.exportar_estado()
    bob.cambiar_direccion()  
    for i in (3, 4):
        msgs.append(bob.enviar(TEXTOS[i]))
        assert alice.recibir(msgs[i]).decode() == TEXTOS[i]
    alice.cambiar_direccion()  
    msgs.append(alice.enviar(TEXTOS[5]))
    assert bob.recibir(msgs[5]).decode() == TEXTOS[5]
    return alice, bob, msgs, robos


def atacante_descifra(estado, mensajes_objetivo, mensajes_publicos):
    privada = X25519PrivateKey.from_private_bytes(estado["dhs_privada"])
    publicas = {m[:32] for m in mensajes_publicos}
    if estado["dhr"]:
        publicas.add(estado["dhr"])
    raices, frontera, cadenas = {estado["rk"]}, {estado["rk"]}, set()
    for _ in range(3):  # tres niveles de ratchet DH
        nuevas = set()
        for rk in frontera:
            for pub in publicas:
                rk2, ck = kdf_rk(rk, dh(privada, pub))
                nuevas.add(rk2)
                cadenas.add(ck)
        frontera = nuevas - raices
        raices |= nuevas
    cadenas |= {c for c in (estado["cks"], estado["ckr"]) if c}
    claves = set(estado["omitidas"].values())
    for ck in cadenas:
        for _ in range(15):
            mk, ck = kdf_ck(ck)
            claves.add(mk)
    descifrados = []
    for indice, mensaje in mensajes_objetivo.items():
        cabecera, cifrado = mensaje[:LONGITUD_CABECERA], mensaje[LONGITUD_CABECERA:]
        for mk in claves:
            try:
                descifrar_con_clave_mensaje(mk, cifrado, cabecera)  
                descifrados.append(indice)
                break
            except InvalidTag:
                continue
    return descifrados


def test_A2_01(registro):
    """Descifrar los 6 mensajes."""
    _, _, msgs, _ = escenario()  
    alice, bob = crear_sesion()
    correctos = 0
    pasos = [(alice, bob)] * 3 + [(bob, alice)] * 2 + [(alice, bob)]
    for texto, (emisor, receptor) in zip(TEXTOS, pasos):
        if emisor._girar_pendiente:
            emisor.cambiar_direccion()
        if receptor.recibir(emisor.enviar(texto)).decode() == texto:
            correctos += 1
    registro(f"{correctos}/6 correctos", "3 mensajes Alice->Bob, 2 Bob->Alice, 1 Alice->Bob, con 2 cambios de dirección")


def test_A2_02(registro):
    """Un byte alterado del ciphertext."""
    alice, bob = crear_sesion()
    original = alice.enviar("mensaje a proteger")
    alterado = bytearray(original)
    alterado[LONGITUD_CABECERA + 3] ^= 0x01  
    try:
        bob.recibir(bytes(alterado))
        resultado = "aceptado"
    except MensajeRechazado:
        resultado = "rechazado"
    sigue_sano = bob.recibir(original) == b"mensaje a proteger"  
    registro(resultado if sigue_sano else "estado dañado",
             "AES-GCM detecta la alteración; el rechazo no modifica el estado y el mensaje original aún se descifra")


def test_A2_03(registro):
    """Mensaje reenviado."""
    alice, bob, msgs, _ = escenario()
    rechazos = 0
    alice2, bob2 = crear_sesion()
    m1, m2 = alice2.enviar("uno"), alice2.enviar("dos")
    bob2.recibir(m1), bob2.recibir(m2)
    for repetido in (m2, m1):  
        with pytest.raises(MensajeRechazado):
            bob2.recibir(repetido)
        rechazos += 1
    with pytest.raises(MensajeRechazado):  
        bob.recibir(msgs[0])
    rechazos += 1
    with pytest.raises(MensajeRechazado):  
        alice.recibir(msgs[3])
    rechazos += 1
    sigue_sano = bob2.recibir(alice2.enviar("tres")) == b"tres"  
    registro("rechazado" if rechazos == 4 and sigue_sano else "aceptado",
             "4 reenvíos rechazados (misma cadena y cadenas viejas); la sesión continúa sin daño")


def test_A2_04(registro):
    """Estado robado tras el mensaje 3 no descifra el mensaje 1."""
    _, _, msgs, robos = escenario()
    robo = robos["bob_tras_m3"]
    control = atacante_descifra(robos["bob_inicial"], {0: msgs[0]}, msgs) == [0]
    por_calculo = atacante_descifra(robo, {0: msgs[0]}, msgs)
    clon = Ratchet.desde_estado(robo)
    try:
        clon.recibir(msgs[0])
        por_protocolo = True
    except MensajeRechazado:
        por_protocolo = False
    ok = control and not por_calculo and not por_protocolo
    registro("no descifrable" if ok else "descifrable",
             "Control: con el estado previo al mensaje 1 sí se descifra; tras recibir m3 la clave de m1 ya se borró "
             "y la cadena no puede retroceder")


def test_A2_05(registro):
    """Estado robado antes del cambio de dirección no descifra tras él."""
    _, _, msgs, robos = escenario()
    robo_bob = robos["bob_tras_m3"]  
    despues = {3: msgs[3], 4: msgs[4], 5: msgs[5]}  
    descifrados = atacante_descifra(robo_bob, despues, msgs)
    ctrl = atacante_descifra(robos["alice_tras_m3"], despues, msgs)
    control_ok = set(ctrl) == {3, 4}
    registro("no descifrable" if not descifrados and control_ok else "descifrable",
             "Con el estado de Bob previo a su cambio de dirección no se descifran m4, m5 ni m6; "
             "control: el estado de Alice sí revela m4 y m5 pero no m6 (se cura en su propio cambio de dirección)")
