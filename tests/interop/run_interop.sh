#!/usr/bin/env bash
set -euo pipefail

TOKEN="${TOKEN:-interop-token-12345678901234567890}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PHONELINK_SRC="$(cd "$HERE/../../../src" && pwd)"

export PYTHONPATH="$PHONELINK_SRC"

echo "=== Python server <-> Kotlin client ==="
python3 "$HERE/py_server.py" "$TOKEN" &
PY_PID=$!
trap 'kill $PY_PID 2>/dev/null || true' EXIT

# Esperar a que el server imprima PORT=
for i in $(seq 1 50); do
    if kill -0 "$PY_PID" 2>/dev/null; then
        PORT=$(head -n1 /dev/stdin < <(python3 -c "pass") 2>/dev/null || true)
        break
    fi
done

# Más simple: leer stdout del server con coproc
kill $PY_PID 2>/dev/null || true
wait $PY_PID 2>/dev/null || true
trap - EXIT

echo "Usa los tests de Kotlin (InteropTest) para la orquestación real."
