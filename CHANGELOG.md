# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [0.4.0] — 2026-10-03

### Added
- Límites configurables por constructor en `WiFiServer` y `WiFiClient`:
  `max_payload`, `handshake_timeout`, `send_timeout`, `revoke_timeout`,
  `idle_timeout`, `max_preauth_connections`, semáforos de handshake/preauth,
  parámetros del rate limiter y `auth_fail_delay`.
- `on_session_terminated` en `WiFiClient`: callback invocado cuando el servidor
  envía `replaced` o `revoked`, sin marcar la sesión como `auth_rejected`.
- `set_token(..., update_provider=True)`: permite rotar el token cuando hay
  un `token_provider` activo.
- `generate_token(nbytes=32)` exportado como helper público
  (`secrets.token_urlsafe`).
- `stop_timeout` configurable en `Peer` (espera a handlers pendientes al
  detenerse).
- `on_handler_error` soporta callbacks síncronos y asíncronos; recibe el
  nombre del evento correcto.

### Changed
- Heartbeat: `_last_seen` y `_last_pong` se inicializan a `None` y solo se
  actualizan con actividad real. Una conexión recién establecida pero
  silenciosa ya no parece viva durante `heartbeat_timeout` segundos.
- `MessageStream.last_rx` también arranca en `None` (misma razón).
- `_on_connect` ya no resetea los timestamps de actividad.
- Heartbeat usa tres fuentes de actividad (en orden): `_last_pong`,
  `transport.last_rx_time()` y `_last_seen`.
- `Peer.stop()` es idempotente, más simple y con timeout configurable.
- Validación de payload en `Peer.send()` (defensa en profundidad: claves
  deben ser `str`).
- TLS endurecido en cliente: fuera de loopback se exige
  `verify_mode=CERT_REQUIRED` y `check_hostname=True` (salvo
  `allow_insecure_tls=True`).

### Fixed
- **BLOCKER**: deadlock en `send()` (servidor y cliente). El lock ya no se
  re-adquiere al cerrar la conexión tras un timeout de envío.
- Código muerto eliminado (`_token_digest`).
- Race y limpieza incorrecta de timestamps al desconectar/reconectar.

### Security
- Validación más estricta del `SSLContext` del cliente fuera de loopback.
- Warnings explícitos cuando se activa `allow_insecure_lan` o
  `allow_insecure_tls`.

---

## [0.3.0] — 2026-09

### Added
- Protocolo v2: challenge-response con HMAC-SHA256 sobre nonce de 32 bytes.
  El token compartido **nunca** viaja en claro.
- Rate limiter por IP (ventana, máximo de fallos, duración de bloqueo y
  límite de IPs rastreadas configurables).
- Semáforos de pre-auth y de handshake concurrentes para mitigar DoS.
- Pre-validación de JSON antes de `json.loads`:
  profundidad máxima, enteros gigantes y exceso de claves (anti JSON-bomb
  y C-stack overflow).
- `token_provider` en `WiFiServer` para rotación dinámica del token.
- `set_token(disconnect_current=True)`: revoca la sesión activa enviando
  `{"type": "revoked"}`.
- `on_auth_error` en `WiFiClient` (soporta sync y async).
- Heartbeat configurable en `Peer` con factor de timeout.
- `max_pending_handlers` para limitar handlers concurrentes.
- Soporte opcional de zeroconf / mDNS (`enable_zeroconf`).
- Validación de `service_name` (solo letras, dígitos y guión; máx. 63 chars).
- `AuthRejected` y `TransientAuthError` para distinguir fallos terminales
  de fallos recuperables.
- Payload máximo reducido a 1 MiB (antes 10 MiB).

### Fixed
- Bypass de seguridad con `host=""` (ya no se considera loopback).
- Validación de longitud de nonce y MAC.
- Race en `Peer.stop()` al cancelar handlers pendientes.
- Pérdida de `on_disconnect` en algunos caminos de error.
- Race al revocar sesión.
- Estado `_connected` limpio tras fallos.
- Evicción correcta en el rate limiter (no se desbloquean atacantes activos).
- Timeout al enviar mensajes del handshake.
- Version mismatch de protocolo no cuenta para el rate limit.
- Razones de error validadas (solo caracteres seguros).
- Aviso cuando se usa modo inseguro.
- Soporte IPv6 en el registro zeroconf.
- Preservación de la traza original en `IncompleteReadError`.

### Security
- TLS mínimo forzado a 1.2+; se rechazan explícitamente SSLv2/3 y TLS 1.0/1.1.
- Comparación de MAC en tiempo constante.
- Delay artificial tras fallos de autenticación.
- Límites de tamaño diferenciados: 4 KiB en handshake, 1 MiB post-auth.

---

## [0.2.0] — 2026-08 (interno)

- Primera versión usable del transporte WiFi con autenticación por token
  en claro (protocolo v1, reemplazado en 0.3.0).
- API `Peer` básica con handlers de eventos.
- Framing length-prefixed JSON.

---

## [0.1.0] — 2026-07 (interno)

- Prototipo inicial de comunicación PC ↔ móvil sobre TCP.
