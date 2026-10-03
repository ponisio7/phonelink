# phonelink

Comunicación segura PC ↔ móvil sobre TCP con TLS, pensada para redes locales.

`phonelink` es una librería **asyncio** que ofrece una API de alto nivel (`Peer`) sobre transportes (actualmente WiFi/TCP). Incluye autenticación por token con challenge-response HMAC-SHA256, TLS 1.2+, heartbeat, rate limiting, reconexión automática y límites anti-DoS.

```python
from phonelink import Peer, WiFiServer, generate_token

TOKEN = generate_token()  # secrets.token_urlsafe(32)

peer = Peer(WiFiServer(token=TOKEN, host="127.0.0.1", port=8888))
peer.on("chat", lambda msg: print(msg["payload"]["text"]))
await peer.start()
```

| Característica | Detalle |
|---|---|
| **Transporte** | TCP con framing `[4 bytes BE length][JSON UTF-8]` |
| **Autenticación** | Challenge-response HMAC-SHA256 (el token **nunca** viaja en claro) |
| **Cifrado** | TLS 1.2+ obligatorio fuera de loopback |
| **Robustez** | Heartbeat ping/pong, reconexión con backoff, rate limit por IP |
| **Protocolo** | Versionado (`protocol_version = 2`) |

---

## Instalación

```bash
pip install phonelink
```

Requiere **Python 3.10+**.

Para descubrimiento mDNS (opcional):

```bash
pip install phonelink[zeroconf]
```

---

## Ejemplo mínimo (loopback, sin TLS)

Ideal para pruebas en la misma máquina. Sin certificados.

### Servidor

```python
import asyncio
from phonelink import Peer, WiFiServer, generate_token

TOKEN = generate_token()
print(f"Token: {TOKEN}")  # Cópialo al cliente

async def main() -> None:
    peer = Peer(WiFiServer(token=TOKEN, host="127.0.0.1", port=8888))

    async def on_chat(msg):
        texto = msg["payload"]["text"]
        print(f"Cliente dice: {texto}")
        await peer.send("chat", {"text": f"recibido: {texto}"})

    peer.on("chat", on_chat)
    await peer.start()
    print("Servidor en 127.0.0.1:8888 (Ctrl+C para salir)")
    try:
        await asyncio.Event().wait()
    finally:
        await peer.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

### Cliente

```python
import asyncio
from phonelink import Peer, WiFiClient

TOKEN = "..."  # el mismo que imprimió el servidor

async def main() -> None:
    peer = Peer(WiFiClient("127.0.0.1", token=TOKEN, port=8888))

    async def on_chat(msg):
        print(f"Servidor dice: {msg['payload']['text']}")

    peer.on("chat", on_chat)
    await peer.start(timeout=5.0)
    await peer.send("chat", {"text": "hola"})
    await asyncio.sleep(2)
    await peer.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Ejemplo recomendado (LAN + TLS)

Para PC y móvil en la misma WiFi. **Usa siempre TLS fuera de loopback.**

### 1. Genera un token fuerte

```python
from phonelink import generate_token
print(generate_token())  # ~43 caracteres, URL-safe
```

### 2. Genera un certificado autofirmado

```bash
# Sustituye 192.168.1.42 por la IP real del PC
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=192.168.1.42" \
  -addext "subjectAltName=IP:192.168.1.42,DNS:localhost"
```

### 3. Servidor

```python
import asyncio
import ssl
from pathlib import Path
from phonelink import Peer, WiFiServer, generate_token

TOKEN = generate_token()  # o léelo de una variable de entorno
CERT = Path("server.crt")
KEY = Path("server.key")

def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    return ctx

async def main() -> None:
    peer = Peer(WiFiServer(
        token=TOKEN,
        host="0.0.0.0",          # escucha en toda la LAN
        port=8888,
        ssl_context=build_ssl_context(),
    ))

    async def on_chat(msg):
        print(f"Móvil dice: {msg['payload']['text']}")
        await peer.send("chat", {"text": "recibido"})

    peer.on("chat", on_chat)
    await peer.start()
    print("Servidor TLS en 0.0.0.0:8888")
    try:
        await asyncio.Event().wait()
    finally:
        await peer.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

### 4. Cliente

```python
import asyncio
import ssl
from pathlib import Path
from phonelink import Peer, WiFiClient

TOKEN = "..."                 # el mismo del servidor
HOST = "192.168.1.42"         # IP del PC
CERT = Path("server.crt")     # copia del certificado del servidor

def build_client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(CERT))
    ctx.check_hostname = True   # obligatorio fuera de loopback
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

async def main() -> None:
    peer = Peer(WiFiClient(
        HOST,
        token=TOKEN,
        port=8888,
        ssl_context=build_client_ssl_context(),
    ))

    async def on_chat(msg):
        print(f"PC dice: {msg['payload']['text']}")

    peer.on("chat", on_chat)
    await peer.start(timeout=10.0)
    await peer.send("chat", {"text": "hola desde el móvil"})
    await asyncio.sleep(2)
    await peer.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

> **Nunca uses `ssl.CERT_NONE` en LAN.** El token se autentica por HMAC, pero sin TLS cualquiera en la misma red puede interceptar el tráfico. Si realmente aceptas el riesgo, pasa `allow_insecure_tls=True` (cliente) o `allow_insecure_lan=True` (servidor); ambos emiten un warning.

---

## API

### `Peer`

Fachada de alto nivel sobre cualquier `Transport`. Gestiona eventos, heartbeat y aislamiento de handlers.

```python
peer = Peer(
    transport,
    heartbeat=15.0,                  # segundos entre pings (0 = desactivado)
    heartbeat_timeout_factor=3.0,    # timeout = heartbeat * factor
    max_pending_handlers=64,         # límite de handlers concurrentes
    on_handler_error=None,           # callback(event, exc) sync o async
    stop_timeout=5.0,                # timeout al cancelar handlers en stop()
)
```

| Método | Descripción |
|--------|-------------|
| `peer.on(event, handler)` | Registra un handler para un evento. Devuelve `self` (encadenable). |
| `peer.on_any(handler)` | Handler para eventos sin handler específico. |
| `await peer.start(timeout=None)` | Inicia el transporte. |
| `await peer.send(event, payload=None)` | Envía `{"type": event, "payload": payload}`. |
| `await peer.stop()` | Cancela handlers pendientes y cierra el transporte (idempotente). |

El `Peer` responde automáticamente a `ping` con `pong`. Los eventos `ping`, `pong`, `replaced` y `revoked` están **reservados** y no pueden registrarse con `on()`.

**Contrato del heartbeat**
- Se envía un `ping` cada `heartbeat` segundos.
- Se considera actividad real: un `pong` recibido, cualquier mensaje de aplicación, o bytes recibidos en el socket (`last_rx_time()`).
- Si no hay actividad durante `heartbeat * heartbeat_timeout_factor` segundos, se cierra la conexión.

### `WiFiServer`

```python
WiFiServer(
    token: str,
    host: str = "127.0.0.1",
    port: int = 8888,
    service_name: str = "phonelink-pc",
    ssl_context: ssl.SSLContext | None = None,
    allow_insecure_lan: bool = False,
    max_handshakes: int = 8,
    enable_zeroconf: bool = False,
    require_strong_token: bool = True,
    rate_limit: bool = True,
    token_provider: Callable[[], str] | None = None,
    # límites configurables (v0.4+)
    max_payload: int = 1_048_576,          # 1 MiB
    handshake_timeout: float = 5.0,
    send_timeout: float = 15.0,
    revoke_timeout: float = 3.0,
    idle_timeout: float = 60.0,
    max_preauth_connections: int = 32,
    ...
)
```

- Sin `ssl_context` solo se permite `host` loopback (salvo `allow_insecure_lan=True`).
- `token` mínimo 16 caracteres si `require_strong_token=True` (recomendado 32+).
- `token_provider`: callable que se consulta en cada handshake; permite rotación sin reiniciar.
- `enable_zeroconf=True` requiere `pip install phonelink[zeroconf]`.
- `set_token(token, *, disconnect_current=False, update_provider=False)`: rota el token. Con `disconnect_current=True` envía `{"type": "revoked"}` al cliente activo.

### `WiFiClient`

```python
WiFiClient(
    host: str,
    token: str,
    port: int = 8888,
    reconnect: bool = True,
    max_backoff: float = 30.0,
    connect_timeout: float = 10.0,
    ssl_context: ssl.SSLContext | None = None,
    allow_insecure_lan: bool = False,
    allow_insecure_tls: bool = False,
    min_stable_seconds: float = 3.0,
    on_auth_error: Callable[[str], Any] | None = None,
    on_session_terminated: Callable[[str], Any] | None = None,
    # límites configurables (v0.4+)
    max_payload: int = 1_048_576,
    handshake_timeout: float = 5.0,
    send_timeout: float = 15.0,
    idle_timeout: float = 60.0,
)
```

- Reintenta con backoff exponencial ante fallos **transitorios** (`rate_limited`, errores de red).
- **No** reintenta ante fallos terminales (`auth_failed`, `protocol_version_mismatch`, `revoked`).
- `on_auth_error(reason)` se invoca en cada fallo de autenticación.
- `on_session_terminated(reason)` se invoca cuando el servidor envía `replaced` o `revoked` (la sesión termina sin marcarse como auth rechazada).

### Helpers y excepciones

```python
from phonelink import (
    generate_token,       # secrets.token_urlsafe(32)
    ProtocolError,        # framing / JSON inválido
    AuthRejected,         # auth terminal (no reintentar)
    TransientAuthError,   # auth temporal (reintentar)
    Transport,            # interfaz abstracta para nuevos transportes
)
```

---

## Seguridad

| Medida | Detalle |
|--------|---------|
| **Token** | Mínimo 16 caracteres. Comparación en tiempo constante (`secrets.compare_digest`). |
| **HMAC** | Challenge-response: el servidor envía un nonce de 32 bytes; el cliente responde con `HMAC-SHA256(token, nonce)`. El token **nunca** viaja por el cable. |
| **TLS** | Obligatorio fuera de loopback. Mínimo TLS 1.2. Se rechazan SSLv2/3 y TLS 1.0/1.1. |
| **Rate limit** | 5 fallos de auth por IP en 60 s → bloqueo de 5 min (configurable). |
| **Límites** | Payload máximo 1 MiB (configurable). Handshake limitado a 4 KiB. Pre-validación de profundidad JSON, enteros gigantes y número de claves. |
| **Rotación** | `server.set_token(nuevo, disconnect_current=True)` cierra la sesión y el cliente recibe `revoked`. |

Si usas `allow_insecure_lan=True` o `allow_insecure_tls=True`, el tráfico (o la verificación del certificado) queda desprotegido. Solo hazlo en redes de confianza absoluta.

---

## Protocolo (v2)

Formato en el cable:

```
+------------------+----------------------+
| 4 bytes BE length | N bytes JSON UTF-8  |
+------------------+----------------------+
```

### Handshake

```
Cliente                         Servidor
   |                               |
   |  {"type":"hello",             |
   |   "protocol_version":2}       |
   |------------------------------>|
   |                               |
   |  {"type":"challenge",         |
   |   "nonce":"<64 hex>",         |
   |   "protocol_version":2}       |
   |<------------------------------|
   |                               |
   |  {"type":"auth",              |
   |   "mac":"<64 hex HMAC>"}      |
   |------------------------------>|
   |                               |
   |  {"type":"auth_ok",           |
   |   "protocol_version":2}       |
   |<------------------------------|
   |                               |
   |     (mensajes de aplicación)  |
```

Errores posibles del servidor:

```json
{"type": "error", "reason": "auth_failed"}
{"type": "error", "reason": "protocol_version_mismatch"}
{"type": "error", "reason": "rate_limited"}
{"type": "error", "reason": "server_error"}
```

### Mensajes de aplicación

```json
{"type": "chat", "payload": {"text": "hola"}}
```

### Mensajes de control (reservados)

| Tipo | Dirección | Significado |
|------|-----------|-------------|
| `ping` / `pong` | bidireccional | Heartbeat |
| `replaced` | servidor → cliente | Otro cliente tomó la sesión |
| `revoked` | servidor → cliente | El token fue rotado |

Los nombres de evento de usuario no pueden ser `ping`, `pong`, `replaced` ni `revoked`.

---

## Ejemplos completos

En el repositorio (`examples/`):

- `ejemplo_pc.py` — servidor con TLS (o loopback sin TLS si no hay certificados).
- `ejemplo_cliente.py` — cliente con verificación del certificado del servidor.

---

## Extender la librería

Para añadir un nuevo transporte (BLE, WebSocket, etc.) implementa la interfaz `Transport`:

```python
from phonelink import Transport, Peer

class MiTransporte(Transport):
    async def start(self, timeout=None): ...
    async def send(self, obj): ...
    async def disconnect(self): ...
    async def stop(self): ...
    def is_connected(self) -> bool: ...
    def last_rx_time(self) -> float | None: ...

peer = Peer(MiTransporte(...))
```

---

## Estado y roadmap

- ✅ WiFi (TCP + TLS + zeroconf opcional)
- ⏳ BLE
- ⏳ WebSocket

---

## Licencia

MIT. Ver [LICENSE](LICENSE).
