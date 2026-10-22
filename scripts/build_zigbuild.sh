#!/usr/bin/env bash
set -euo pipefail

BUILD_COMMAND=build
if [[ "${USE_ZIGBUILD}" == "true" ]]; then
  BUILD_COMMAND=zigbuild
  export MAKEFLAGS="CC_MM="
fi

read -r -a BUILD_VARIANTS <<< "${VARIANTS}"
for VARIANT in "${BUILD_VARIANTS[@]}"; do
  FEATURES="${VARIANT}"
  if [[ -n "${EXTRA_FEATURES}" ]]; then
    FEATURES+=",${EXTRA_FEATURES}"
  fi

  echo "Building ${TARGET} (${FEATURES})"
  cargo +stable "${BUILD_COMMAND}" --locked --release \
    --target "${TARGET}" -F "${FEATURES}" -p clash-rs

  # Both variants use the same binary path; package before the next build.
  PKG_NAME="clash-rs-${VARIANT}-${TARGET}"
  STAGING_DIR="dist/${VARIANT}/${PKG_NAME}"
  mkdir -p "${STAGING_DIR}"
  cp "target/${TARGET}/release/${BINARY_NAME}" "${STAGING_DIR}/"
  cp README.md LICENSE "${STAGING_DIR}/"

  (
    cd "dist/${VARIANT}"
    case "${ARCHIVE_EXT}" in
      zip) zip -r "${PKG_NAME}.zip" "${PKG_NAME}" ;;
      tar.gz) tar -czf "${PKG_NAME}.tar.gz" "${PKG_NAME}" ;;
      *) echo "Unsupported archive extension: ${ARCHIVE_EXT}" >&2; exit 1 ;;
    esac
  )
done
