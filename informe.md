# Informe: Seguridad en Messenger (E2EE y forward secrecy)

**Autor:** Carlos Abiecer Velez Cardona

## Qué se implementó

**A1 (`a1_cadena.py`).** Una cadena de claves simétrica. `derivar_clave(cadena, indice)` obtiene una clave de
32 bytes con HKDF-SHA256, de forma determinista. La clase `CadenaClaves` entrega cada clave una sola vez:
deriva la clave del mensaje, avanza la cadena con una derivación de un solo sentido (otra etiqueta HKDF) y
**sobrescribe con ceros** la cadena anterior; la clave de mensaje también se borra tras usarse. `cifrar` usa
AES-256-GCM (cifrado autenticado).

**A2 (`a2_ratchet.py`).** Un Double Ratchet reducido con la clase `Ratchet` (métodos `enviar`, `recibir` y
`cambiar_direccion`). Dos participantes intercambian 6 mensajes en memoria (3 de Alice a Bob, 2 de Bob a Alice,
1 de Alice a Bob); en cada cambio de dirección quien habla genera un par **X25519** nuevo y renueva la clave
raíz con HKDF. Cada mensaje usa una clave derivada con HMAC-SHA256 que se descarta al usarse. La recepción
es transaccional: si un mensaje se rechaza (alterado o repetido), el estado no cambia.

**Pruebas.** 9 pruebas con pytest (`python -m pytest -q`), una por fila de la plantilla. Un atacante simulado
recibe una copia del estado secreto robado más todo el tráfico, e intenta cuanto ese estado permite
(combinar sus claves privadas con las públicas vistas, avanzar cadenas, usar el propio protocolo). Cada prueba
de seguridad incluye un **control**: se comprueba que el mismo atacante sí descifra cuando debería poder
hacerlo, para que el resultado "no descifrable" sea significativo.

| Prueba | Propiedad | Esperado | Obtenido | Estado |
| --- | --- | --- | --- | --- |
| A1-01 | determinismo | misma clave | misma clave | OK |
| A1-02 | unicidad | 10 claves distintas | 10 claves distintas | OK |
| A1-03 | cifrado | 10/10 correctos | 10/10 correctos | OK |
| A1-04 | borrado | no recuperable | no recuperable | OK |
| A2-01 | descifrado | 6/6 correctos | 6/6 correctos | OK |
| A2-02 | integridad | rechazado | rechazado | OK |
| A2-03 | repetición | rechazado | rechazado | OK |
| A2-04 | forward secrecy | no descifrable | no descifrable | OK |
| A2-05 | post-compromise | no descifrable | no descifrable | OK |

Resultado: **9 de 9 pruebas en OK (100 %)**; no hay filas en FALLA que justificar.

## Diferencias

Frente a la especificación de Signal (Perrin y Marlinspike, 2016) y al protocolo real:

- **Sin X3DH:** el secreto inicial compartido se genera aleatoriamente y se entrega a ambos; no hay claves de
  identidad ni prekeys. Por eso no se evalúa FS del primer mensaje frente al secreto inicial.
- **Cifrado de mensajes:** se usa AES-256-GCM con clave y nonce derivados de la clave de mensaje; la
  especificación sugiere AES-256-CBC con HMAC-SHA256. Ambos son cifrado autenticado.
- **Momento del nuevo par DH:** la especificación genera el par nuevo al *recibir* una clave DH distinta;
  aquí se genera en `cambiar_direccion` (justo antes de hablar). El resultado criptográfico es el mismo y
  permite definir con claridad "estado robado antes del cambio de dirección".
- **Sin cifrado de cabeceras:** la cabecera (clave pública DH, PN, N) viaja en claro, aunque autenticada.
- **Mensajes salteados:** se guardan hasta `MAX_SALTO = 10` claves; la especificación recomienda además
  expirarlas, cosa que aquí no se hace.
- **Sin red, servidor ni persistencia:** todo ocurre en un solo proceso.
- **Resultado de A2-05:** la recuperación tras compromiso ocurre cuando el participante comprometido genera
  su siguiente par DH. El control de la prueba muestra que robar el estado de Alice sí revela m4 y m5 (la
  respuesta de Bob se calcula con la clave DH que Alice aún tenía) y que m6 vuelve a ser seguro. Es el
  comportamiento esperado del Double Ratchet, no un fallo.

## Limitaciones

- **Borrado de memoria en Python:** solo se sobrescriben los `bytearray`. Los `bytes` inmutables, el recolector
  de basura y la biblioteca `cryptography` pueden dejar copias de las claves en memoria; un borrado robusto
  requiere lenguajes con control de memoria.
- **Es un modelo educativo:** no hay autenticación de identidades (X3DH), ni verificación de huellas, ni
  protección de metadatos. Un servidor malicioso podría suplantar claves en un sistema real así.
- **Modelo del atacante de las pruebas:** el atacante simulado prueba una familia grande pero finita de
  derivaciones; es evidencia empírica, no una prueba formal de seguridad (la formal está en Cohn-Gordon et al., 2017).
- **Alcance de los mensajes perdidos:** solo se toleran hasta 10 mensajes salteados por cadena.
- **Sin pruebas de concurrencia ni de rendimiento**; el estado no se guarda en disco.
