import asyncio
import pytest

from phonelink.protocol import (
    HEADER_SIZE,
    HANDSHAKE_MAX,
    MAX_PAYLOAD,
    MessageStream,
    ProtocolError,
    encode,
    read_message,
)


def test_encode_prefijo_longitud():
    raw = encode({"a": 1})
    assert len(raw) > HEADER_SIZE
    # Los primeros 4 bytes son la longitud big-endian
    n = int.from_bytes(raw[:HEADER_SIZE], "big")
    assert n == len(raw) - HEADER_SIZE


def test_encode_payload_demasiado_grande():
    with pytest.raises(ProtocolError):
        encode({"x": "a" * (MAX_PAYLOAD + 1)})


async def test_roundtrip_un_mensaje():
    reader = asyncio.StreamReader()
    reader.feed_data(encode({"hola": "mundo"}))
    reader.feed_eof()
    msg = await read_message(reader)
    assert msg == {"hola": "mundo"}


async def test_roundtrip_varios_mensajes_seguidos():
    reader = asyncio.StreamReader()
    for i in range(5):
        reader.feed_data(encode({"n": i}))
    reader.feed_eof()
    for i in range(5):
        assert await read_message(reader) == {"n": i}


async def test_read_message_incompleto():
    reader = asyncio.StreamReader()
    # Anuncia 100 bytes pero solo entrega 10
    reader.feed_data((100).to_bytes(4, "big") + b"0123456789")
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await read_message(reader)


async def test_read_message_json_invalido():
    reader = asyncio.StreamReader()
    payload = b"{no es json}"
    reader.feed_data(len(payload).to_bytes(4, "big") + payload)
    reader.feed_eof()
    with pytest.raises(ProtocolError):
        await read_message(reader)


async def test_read_message_limite_handshake():
    reader = asyncio.StreamReader()
    payload = b"x" * (HANDSHAKE_MAX + 1)
    reader.feed_data(len(payload).to_bytes(4, "big") + payload)
    reader.feed_eof()
    with pytest.raises(ProtocolError):
        await read_message(reader, max_size=HANDSHAKE_MAX)


async def test_message_stream_send_recv():
    """Envía por un MessageStream y recibe por el otro extremo del pipe."""
    # Pipe en memoria usando dos StreamReader/Writer conectados
    server_reader = asyncio.StreamReader()
    server_writer = None

    # Truco: usamos un socketpair para tener StreamReader/Writer reales
    import socket
    a, b = socket.socketpair()
    r1, w1 = await asyncio.open_connection(sock=a)
    r2, w2 = await asyncio.open_connection(sock=b)

    s1 = MessageStream(r1, w1)
    s2 = MessageStream(r2, w2)

    await s1.send({"tipo": "saludo", "n": 42})
    recibido = await s2.recv()
    assert recibido == {"tipo": "saludo", "n": 42}

    await s2.send({"tipo": "respuesta"})
    assert await s1.recv() == {"tipo": "respuesta"}

    await s1.close()
    await s2.close()


async def test_message_stream_envios_concurrentes():
    """Varios sends concurrentes no deben intercalar bytes."""
    import socket
    a, b = socket.socketpair()
    r1, w1 = await asyncio.open_connection(sock=a)
    r2, w2 = await asyncio.open_connection(sock=b)
    s1 = MessageStream(r1, w1)
    s2 = MessageStream(r2, w2)

    async def enviar(n: int):
        await s1.send({"n": n, "relleno": "x" * 1000})

    await asyncio.gather(*[enviar(i) for i in range(20)])

    recibidos = set()
    for _ in range(20):
        m = await asyncio.wait_for(s2.recv(), timeout=2.0)
        recibidos.add(m["n"])
    assert recibidos == set(range(20))

    await s1.close()
    await s2.close()

async def test_read_message_rechaza_nan():
    reader = asyncio.StreamReader()
    payload = b'{"x": NaN}'
    reader.feed_data(len(payload).to_bytes(4, "big") + payload)
    reader.feed_eof()
    with pytest.raises(ProtocolError):
        await read_message(reader)