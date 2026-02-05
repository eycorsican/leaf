#!/usr/bin/env bash
set -euo pipefail

domain="${1:-}"
out_dir="${2:-}"

if [[ -z "${domain}" ]]; then
  echo "usage: $0 <domain> [out_dir]" >&2
  exit 2
fi

if [[ -z "${out_dir}" ]]; then
  out_dir="cert-${domain}"
fi

mkdir -p "${out_dir}"

ca_key="${out_dir}/ca.key"
ca_crt="${out_dir}/ca.crt"
server_key="${out_dir}/server.key"
server_csr="${out_dir}/server.csr"
server_ext="${out_dir}/server.ext"
server_crt="${out_dir}/server.crt"

openssl genrsa -out "${ca_key}" 2048
openssl req -x509 -new -key "${ca_key}" -sha256 -days 3650 -subj "/CN=leaf-quic-ca" -out "${ca_crt}"

openssl genrsa -out "${server_key}" 2048
openssl req -new -key "${server_key}" -subj "/CN=${domain}" -out "${server_csr}"

cat > "${server_ext}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${domain}
EOF

openssl x509 -req -in "${server_csr}" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
  -out "${server_crt}" -days 825 -sha256 -extfile "${server_ext}"

rm -f "${server_csr}" "${server_ext}" "${out_dir}/ca.srl"

echo "generated:"
echo "  ${ca_crt}"
echo "  ${server_crt}"
echo "  ${server_key}"
echo
echo "server inbound:"
echo "  certificate=${server_crt}"
echo "  certificateKey=${server_key}"
echo
echo "client conf (put CA into [Certificate.<name>], then tls-cert=<name>):"
cat "${ca_crt}"
