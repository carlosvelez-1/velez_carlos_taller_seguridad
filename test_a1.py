import os

from a1_cadena import (CadenaClaves, avanzar_cadena, borrar, cifrar, derivar_clave, descifrar)


def test_A1_01(registro):
    """Misma cadena e índice producen la misma clave."""
    cadena = os.urandom(32)
    k1, k2 = derivar_clave(cadena, 7), derivar_clave(cadena, 7)
    k_otro_indice = derivar_clave(cadena, 8)
    k_otra_cadena = derivar_clave(os.urandom(32), 7)
    ok = k1 == k2 and len(k1) == 32 and k1 != k_otro_indice and k1 != k_otra_cadena
    registro("misma clave" if ok else "claves diferentes",
             "Dos derivaciones idénticas coinciden; otro índice u otra cadena dan una clave distinta")


def test_A1_02(registro):
    """10 claves de mensaje distintas."""
    cadena = os.urandom(32)
    claves = {derivar_clave(cadena, i) for i in range(10)}
    secuencia = CadenaClaves(cadena)
    claves_cadena = {bytes(secuencia.siguiente_clave()[1]) for _ in range(10)}
    registro(f"{len(claves)} claves distintas" if len(claves_cadena) == 10 else "hay claves repetidas",
             "10 índices con derivar_clave y 10 entregas consecutivas de CadenaClaves, todas distintas")


def test_A1_03(registro):
    """Cifrar y descifrar 10 mensajes."""
    secreto = os.urandom(32)
    emisor, receptor = CadenaClaves(secreto), CadenaClaves(secreto)
    correctos = 0
    for i in range(10):
        texto = f"mensaje número {i} con tilde y eñe: ñandú"
        _, k_emisor = emisor.siguiente_clave()
        paquete = cifrar(k_emisor, texto)
        _, k_receptor = receptor.siguiente_clave()
        if descifrar(k_receptor, paquete).decode("utf-8") == texto:
            correctos += 1
        borrar(k_emisor)
        borrar(k_receptor)
    registro(f"{correctos}/10 correctos", "Emisor y receptor avanzan sus cadenas en paralelo desde el mismo secreto")


def test_A1_04(registro):
    """Clave usada y luego borrada no se recupera."""
    secreto = os.urandom(32)
    cadena = CadenaClaves(secreto)
    _, clave = cadena.siguiente_clave()
    copia_para_comparar = bytes(clave)  
    paquete = cifrar(clave, "mensaje secreto")
    borrar(clave)

    borrada = clave == bytearray(32)
    robado = cadena.estado()  
    recuperada = False
    candidata = robado
    for paso in range(500):  
        if any(derivar_clave(candidata, i) == copia_para_comparar for i in range(50)):
            recuperada = True
        candidata = avanzar_cadena(candidata)
    try: 
        descifrar(derivar_clave(robado, 0), paquete)
        recuperada = True
    except ValueError:
        pass

    control = derivar_clave(secreto, 0) == copia_para_comparar  
    ok = borrada and not recuperada and control
    registro("no recuperable" if ok else "recuperable",
             "Clave sobrescrita con ceros; con la cadena robada (500 avances x 50 índices) no se reconstruye; "
             "control: con la cadena original sí se obtenía")
