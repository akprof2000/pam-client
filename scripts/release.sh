#!/usr/bin/env bash
# release.sh — сборка релизных архивов.
#
# Собирает две команды (pamget и fakepam) под Windows и Linux (CentOS 7+)
# и раскладывает их по архивам в каталоге dist/:
#
#   dist/pam-client_<версия>_windows_amd64.zip
#   dist/pam-client_<версия>_linux_amd64.tar.gz
#
# Запуск:  ./scripts/release.sh [версия]
# Версия по умолчанию берётся из git-тега, иначе "dev".
#
# Кросс-компиляция в Go делается переменными GOOS/GOARCH и не требует
# ни компилятора C, ни целевой машины: CGO в проекте не используется.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
DIST="${ROOT}/dist"
NAME="pam-client"

# -s -w убирают отладочную информацию: бинарник заметно меньше.
# -X подставляет значение в переменную пакета на этапе сборки.
LDFLAGS="-s -w -X main.version=${VERSION}"

rm -rf "${DIST}"
mkdir -p "${DIST}"

echo "==> Проверки перед сборкой"
go vet ./...
go test ./...

# make_zip упаковывает каталог в zip тем инструментом, который есть в системе:
# zip (Linux/macOS), иначе python3, иначе PowerShell (Windows).
make_zip() {
  local dir="$1" name="$2"
  if command -v zip >/dev/null 2>&1; then
    (cd "${dir}" && zip -qr "${name}.zip" "${name}")
  elif command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    local py; py="$(command -v python3 || command -v python)"
    (cd "${dir}" && "${py}" -c "import shutil,sys; shutil.make_archive(sys.argv[1],'zip',root_dir='.',base_dir=sys.argv[1])" "${name}")
  elif command -v powershell >/dev/null 2>&1; then
    (cd "${dir}" && powershell -NoProfile -Command "Compress-Archive -Path '${name}' -DestinationPath '${name}.zip' -Force")
  else
    echo "не найден инструмент для создания zip (zip/python3/powershell)" >&2
    return 1
  fi
}

build() {
  local goos="$1" goarch="$2" ext="$3"
  local stage="${DIST}/${NAME}_${VERSION}_${goos}_${goarch}"
  mkdir -p "${stage}"

  echo "==> Сборка ${goos}/${goarch}"
  for cmd in pamget fakepam; do
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
      go build -trimpath -ldflags "${LDFLAGS}" -o "${stage}/${cmd}${ext}" "./cmd/${cmd}"
  done

  # В архив кладём документацию и демонстрационные скрипты.
  cp README.md LICENSE "${stage}/" 2>/dev/null || cp README.md "${stage}/"
  if [[ "${goos}" == "windows" ]]; then
    cp scripts/demo.ps1 "${stage}/"
    make_zip "${DIST}" "$(basename "${stage}")"
  else
    cp scripts/demo.sh "${stage}/"
    chmod +x "${stage}/demo.sh"
    (cd "${DIST}" && tar -czf "$(basename "${stage}").tar.gz" "$(basename "${stage}")")
  fi
  rm -rf "${stage}"
}

build linux   amd64 ""
build linux   arm64 ""
build windows amd64 ".exe"

echo "==> Контрольные суммы"
(cd "${DIST}" && sha256sum ./* > SHA256SUMS && cat SHA256SUMS)

echo
echo "==> Готово: ${DIST}"
ls -lh "${DIST}"
