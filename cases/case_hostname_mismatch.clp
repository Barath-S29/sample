(printout t crlf "Loading CASE: Hostname Mismatch" crlf)
(reset)

(assert
  (tls-error
    (error-code CERT_HOSTNAME_MISMATCH)
    (error-message "hostname mismatch")
    (error-category hostname-mismatch)
    (severity high))

  (certificate
    (common-name "www.example.com")
    (subject-alt-names "www.example.com" "example.com")
    (not-before "2024-01-01T00:00:00Z")
    (not-after "2025-12-01T00:00:00Z")
    (signature-algorithm "sha256WithRSAEncryption")
    (key-size 2048)
    (issuer "DigiCert SHA2 Secure Server CA")
    (serial-number "05:AA:BB:CC:DD:EE:FF:00")
    (is-self-signed no))

  (certificate-chain
    (chain-length 3)
    (has-intermediate yes)
    (root-trusted yes)
    (chain-complete yes)
    (missing-certificates))

  (environment
    (client-os "macOS 14.0")
    (server-type "nginx/1.20.2")
    (requested-hostname "api.example.com")
    (sni-value "api.example.com")
    (sni-sent yes)
    (current-timestamp "2026-04-12T10:00:00Z"))

  (connection
    (protocol-version "TLSv1.3")
    (cipher-suite "TLS_AES_256_GCM_SHA384")
    (ocsp-stapling yes)
    (hsts-enabled yes)
    (server-location "external"))

  (DaysToExpiry (-133.0 0) (-133.0 1) (-133.0 0))
  (KeySize (2048.0 0) (2048.0 1) (2048.0 0)))
