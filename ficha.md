# Ficha: cifrado extremo a extremo y secreto hacia adelante

## Definición

El **cifrado extremo a extremo (E2EE)** hace que un mensaje se cifre en el dispositivo del emisor y solo se
descifre en el del receptor; el servidor que lo transporta solo ve texto cifrado. Protege la
**confidencialidad** y la **integridad** del contenido frente a la red, al servidor y a quien lo intercepte.

**No protege:** (1) los *metadatos* (quién habla con quién, cuándo, cuánto); (2) un dispositivo comprometido
(malware, robo del teléfono desbloqueado), porque el mensaje existe en claro en los extremos; (3) copias de
seguridad sin cifrar o capturas de pantalla; (4) a quien reenvía el mensaje; ni (5) la autenticidad de la clave
del contacto si los usuarios no verifican su huella (el servidor podría entregar una clave falsa: ataque de
intermediario) [1][3].

## Amenaza

El **secreto hacia adelante (forward secrecy, FS)** garantiza que, si un atacante obtiene hoy las claves de
una conversación, **no puede descifrar los mensajes anteriores**. Mitiga el ataque de *"grabar ahora, descifrar
después"*: un adversario que guarda todo el tráfico cifrado y más tarde consigue una clave (por robo de
dispositivo, orden judicial o filtración). Sin FS, una sola clave de larga duración abriría todo el historial.
La propiedad complementaria, la **recuperación tras compromiso** (*post-compromise security*), asegura que la
conversación vuelve a ser segura tras un tiempo si el atacante deja de tener acceso [1][2].

## Mecanismo

Signal usa el algoritmo **Double Ratchet** [2], con dos "ratchets" (trinquetes) que solo giran en un sentido:

1. **Ratchet simétrico (cadena de claves):** cada mensaje usa una clave nueva obtenida con una función KDF de
   un solo sentido (HMAC-SHA256) a partir de la clave de cadena; la clave del mensaje se **borra** tras usarse
   y la cadena avanza. Como la KDF no se puede invertir, robar la cadena hoy no revela las claves pasadas: esto
   da **FS**.
2. **Ratchet Diffie-Hellman:** cada vez que cambia la dirección de la conversación, quien responde genera un
   par **X25519** nuevo y mezcla el secreto DH en la clave raíz con HKDF. Como el par nuevo es aleatorio y
   efímero, un atacante que robó el estado anterior queda fuera: esto da **recuperación tras compromiso**.

El secreto inicial se acuerda con **X3DH** [3], que usa claves efímeras y prekeys para que FS valga desde el
primer mensaje. El análisis formal de estas propiedades se hizo en [1].

## Fuentes

1. K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt, D. Stebila. *A Formal Security Analysis of the Signal
   Messaging Protocol.* IEEE European Symposium on Security and Privacy (EuroS&P), 2017, pp. 451-466.
   <https://eprint.iacr.org/2016/1013>
2. T. Perrin, M. Marlinspike. *The Double Ratchet Algorithm*, Revisión 1, 2016. Signal.
   <https://signal.org/docs/specifications/doubleratchet/>

