# Seguridad — Protocolo v2 (challenge-response)

El token **nunca viaja por el cable**. El cliente se autentica mediante
challenge-response:

1. Cliente → Servidor: `{"type": "hello", "protocol_version": 2}`
2. Servidor → Cliente: `{"type": "challenge", "nonce": "<hex 32 bytes>", "protocol_version": 2}`
3. Cliente → Servidor: `{"type": "auth", "mac": "<HMAC-SHA256(token_utf8, nonce) en hex>"}`
4. Servidor → Cliente: `{"type": "auth_ok", "protocol_version": 2}`
   o `{"type": "error", "reason": "auth_failed|protocol_version_mismatch|rate_limited|server_error"}`

Esto protege contra un MITM que haya comprometido el certificado del servidor
o que el cliente lo haya aceptado por error: sin el token no puede fabricar
un HMAC válido.

## Requisitos de implementación (Kotlin / otros clientes)

- Generar o recibir el nonce como 32 bytes (hex en JSON).
- Calcular `HMAC-SHA256` con clave = UTF-8 del token y mensaje = bytes del nonce.
- Enviar el digest en hex minúsculas (o mayúsculas; el servidor compara en binario).
- No reutilizar nonces: cada handshake el servidor genera uno nuevo con CSPRNG.
- Tras `revoked` o `replaced`, no reconectar con el mismo token/sesión.
- TLS sigue siendo obligatorio en LAN (salvo opt-in explícito).

## Constantes

| Constante            | Valor |
|----------------------|-------|
| `PROTOCOL_VERSION`   | 2     |
| `NONCE_SIZE`         | 32 bytes |
| `HANDSHAKE_TIMEOUT`  | 5 s (por mensaje del handshake) |
| `MIN_TOKEN_LEN`      | 16 (recomendado ≥ 32) |

## Caudal mínimo sostenible

`READ_CHUNK / min(DEFAULT_IDLE_TIMEOUT, heartbeat_timeout)` ≈ 364 B/s con
defaults (`READ_CHUNK=16 KiB`, idle=60 s, heartbeat 15×3=45 s).