storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address                 = "0.0.0.0:8200"
  tls_cert_file           = "/vault/ssl/self_signed_certificate.pem"
  tls_key_file            = "/vault/ssl/private_key.pem"
  tls_disable_client_certs = true
}

ui                = true
api_addr          = "https://0.0.0.0:8200"
default_lease_ttl = "48h"
max_lease_ttl     = "168h"