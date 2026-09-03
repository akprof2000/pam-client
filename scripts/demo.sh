#!/usr/bin/env bash
# demo.sh — проверка утилиты pamget «под ключ» на локальном стенде.
#
# Скрипт поднимает имитацию сервера PAM (fakepam), запрашивает у него
# все четыре типа записей и показывает поведение проверки TLS.
# Реальный сервер и настоящий токен для этого не нужны.
#
# Запуск:  ./scripts/demo.sh
# Остановка стенда выполняется автоматически при выходе.

set -euo pipefail

# --- Параметры по умолчанию (переопределяются переменными окружения) -------
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8443}"
TOKEN="${PAM_TOKEN:-00000000-0000-0000-0000-000000000001}"
GROUP="${GROUP:-/Example/Common/Test/test_accounts}"
SERVER="https://${HOST}:${PORT}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"   # дальше работаем относительными путями: их одинаково понимают
               # и Linux, и Go под Windows (Git Bash отдаёт пути вида /c/...)
WORKDIR="$(mktemp -d)"
CERT="${WORKDIR}/fakepam.pem"

# Под Git Bash на Windows пути вида /tmp/... не понимает нативный exe,
# поэтому переводим путь в формат C:/... (на Linux cygpath отсутствует).
if command -v cygpath >/dev/null 2>&1; then
  CERT="$(cygpath -m "${CERT}")"
fi

# Если рядом лежат собранные бинарники — используем их, иначе go run.
if [[ -x "${ROOT}/pamget" && -x "${ROOT}/fakepam" ]]; then
  PAMGET=("${ROOT}/pamget"); FAKEPAM=("${ROOT}/fakepam")
else
  PAMGET=(go run ./cmd/pamget); FAKEPAM=(go run ./cmd/fakepam)
fi

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "${SRV_PID}" 2>/dev/null || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

echo "==> Поднимаю тестовый сервер PAM на ${SERVER}"
"${FAKEPAM[@]}" -addr "${HOST}:${PORT}" -token "${TOKEN}" -cert-out "${CERT}" >/dev/null 2>&1 &
SRV_PID=$!

# Ждём появления файла сертификата — признак того, что сервер стартовал.
for _ in $(seq 1 30); do
  [[ -f "${CERT}" ]] && break
  sleep 0.5
done
if [[ ! -f "${CERT}" ]]; then
  echo "Сервер не стартовал за 15 секунд" >&2
  exit 1
fi

run() { echo; echo "--- $1"; shift; "$@"; }

echo
echo "==> Список записей, доступных токену"
"${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -ca "${CERT}" -list

for name in static_user_credentials static_secret_data static_ssl_certificate static_ssh_key; do
  run "${name}" "${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -ca "${CERT}" \
    -secret "${GROUP}/${name}" -comment "demo.sh"
done

run "весь ответ в JSON" "${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -ca "${CERT}" \
  -secret "${GROUP}/static_ssh_key" -json

echo
echo "--- один запрос, все поля в переменные оболочки (-env)"
eval "$("${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -ca "${CERT}"   -secret "${GROUP}/static_user_credentials" -env -comment "demo.sh")"
echo "тип:    ${PAM_KIND}"
echo "логин:  ${PAM_USERNAME}"
echo "пароль: ${PAM_PASSWORD}"

run "отдельное поле (passphrase)" "${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -ca "${CERT}" \
  -secret "${GROUP}/static_ssh_key" -field passphrase

echo
echo "--- проверка TLS включена: без доверенного CA запрос обязан упасть"
if "${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -secret "${GROUP}/static_secret_data"; then
  echo "ОШИБКА: самоподписанный сертификат был принят" >&2
  exit 1
fi
echo "(ожидаемая ошибка выше — проверка сертификата работает)"

echo
echo "--- тот же запрос с -insecure проходит"
"${PAMGET[@]}" -server "${SERVER}" -token "${TOKEN}" -insecure -secret "${GROUP}/static_secret_data"

echo
echo "--- неверный токен -> 401"
if "${PAMGET[@]}" -server "${SERVER}" -token "wrong-token" -ca "${CERT}" -secret "${GROUP}/static_secret_data"; then
  echo "ОШИБКА: неверный токен был принят" >&2
  exit 1
fi

echo
echo "==> Все проверки пройдены"
