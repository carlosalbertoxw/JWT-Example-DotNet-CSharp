#!/usr/bin/env bash
#
# Prueba de humo del contrato común de los ejemplos JWT (PHP, Java y .NET).
#
# Recorre el flujo completo contra una API en marcha y falla en el primer paso
# que no cumpla el contrato: health, catálogo público sin precio, login,
# /api/auth/me, catálogo con precio, crear producto (Admin sí, User no),
# rotación del refresh token, detección de reuso y logout.
#
# Uso:   scripts/smoke.sh http://localhost:8000
# Requiere: bash, curl y jq. El mismo script vive en los tres repositorios de API.

set -euo pipefail

BASE="${1:?Uso: smoke.sh URL_BASE (p. ej. http://localhost:8000)}"
BASE="${BASE%/}"
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

STATUS=""
BODY=""

fail() {
    echo "FALLO: $*" >&2
    exit 1
}

# request MÉTODO RUTA [ACCESS_TOKEN] [JSON] -> deja el resultado en STATUS y BODY
request() {
    local method=$1 path=$2 token=${3:-} data=${4:-}
    local args=(--silent --show-error --output "$BODY_FILE" --write-out '%{http_code}'
        --request "$method" --header 'Accept: application/json')
    if [[ -n "$token" ]]; then
        args+=(--header "Authorization: Bearer $token")
    fi
    if [[ -n "$data" ]]; then
        args+=(--header 'Content-Type: application/json' --data "$data")
    fi
    STATUS="$(curl "${args[@]}" "$BASE$path")"
    BODY="$(cat "$BODY_FILE")"
}

# expect CÓDIGO DESCRIPCIÓN [FILTRO_JQ que debe dar true]
expect() {
    local code=$1 description=$2 filter=${3:-}
    [[ "$STATUS" == "$code" ]] || fail "$description: se esperaba HTTP $code y llegó $STATUS. Cuerpo: $BODY"
    if [[ -n "$filter" ]]; then
        jq -e "$filter" >/dev/null <<<"$BODY" || fail "$description: el cuerpo no cumple '$filter'. Cuerpo: $BODY"
    fi
    echo "ok  $description"
}

login() {
    request POST /api/auth/login "" "{\"username\":\"$1\",\"password\":\"$2\"}"
}

request GET /health
expect 200 "health"

request GET /api/products/public
expect 200 "catálogo público sin precio" 'length > 0 and all(.[]; has("price") | not)'

request GET /api/products
expect 401 "catálogo completo sin token"

login admin incorrecta
expect 401 "login con contraseña incorrecta"

login admin 'Admin123!'
expect 200 "login de admin" \
    '(.access_token | type == "string") and (.refresh_token | type == "string")
     and .token_type == "Bearer" and (.expires_in | type == "number")'
ADMIN_ACCESS="$(jq -r .access_token <<<"$BODY")"
ADMIN_REFRESH="$(jq -r .refresh_token <<<"$BODY")"

request GET /api/auth/me "$ADMIN_ACCESS"
expect 200 "/api/auth/me" '.username == "admin" and .role == "Admin"'

request GET /api/products "$ADMIN_ACCESS"
expect 200 "catálogo completo con precio" 'length > 0 and all(.[]; has("price"))'

request POST /api/products "$ADMIN_ACCESS" '{"name":"Prueba de humo","description":"CI","price":12.5}'
expect 201 "Admin crea un producto" '.name == "Prueba de humo" and .price == 12.5'

login user 'User123!'
expect 200 "login de user"
USER_ACCESS="$(jq -r .access_token <<<"$BODY")"
USER_REFRESH="$(jq -r .refresh_token <<<"$BODY")"

request POST /api/products "$USER_ACCESS" '{"name":"No","price":1}'
expect 403 "User no puede crear productos"

request POST /api/auth/refresh "" "{\"refresh_token\":\"$ADMIN_REFRESH\"}"
expect 200 "refresh rota el par de tokens" ".refresh_token != \"$ADMIN_REFRESH\""
ROTATED_REFRESH="$(jq -r .refresh_token <<<"$BODY")"

request POST /api/auth/refresh "" "{\"refresh_token\":\"$ADMIN_REFRESH\"}"
expect 401 "reusar un refresh token ya rotado"

request POST /api/auth/refresh "" "{\"refresh_token\":\"$ROTATED_REFRESH\"}"
expect 401 "tras el reuso se revocan todas las sesiones del usuario"

request POST /api/auth/logout "" "{\"refresh_token\":\"$USER_REFRESH\"}"
expect 200 "logout sin access token"

request POST /api/auth/refresh "" "{\"refresh_token\":\"$USER_REFRESH\"}"
expect 401 "el refresh token cerrado ya no renueva"

echo "Prueba de humo superada contra $BASE"
