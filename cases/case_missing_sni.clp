(printout t crlf "Loading CASE: Missing SNI" crlf)
(reset)

(assert
  (tls-error
    (error-code HANDSHAKE_FAILURE)
    (error-message "TLS handshake failure")
    (error-category handshake-failure)
    (severity high))

  (certificate
    (common-name "default.example.com")
    (subject-alt-names "default.example.com")
    (not-before "2024-01-01T00:00:00Z")
    (not-after "2025-12-01T00:00:00Z")
    (signature-algorithm "sha256WithRSAEncryption")
    (key-size 2048)
    (issuer "Example CA")
    (serial-number "07:99:88:77:66:55:44:33")
    (is-self-signed no))

  (certificate-chain
    (chain-length 3)
    (has-intermediate yes)
    (root-trusted yes)
    (chain-complete yes)
    (missing-certificates))

  (environment
    (client-os "Windows Server 2012")
    (server-type "nginx/1.18.0")
    (requested-hostname "app.example.com")
    (sni-value "")
    (sni-sent no)
    (current-timestamp "2026-04-12T10:00:00Z"))

  (connection
    (protocol-version "TLSv1.3")
    (cipher-suite "TLS_AES_256_GCM_SHA384")
    (ocsp-stapling yes)
    (hsts-enabled yes)
    (server-location "external"))

  (fuzzy-input (name DaysToExpiry) (value -133.0))
  (fuzzy-input (name KeySize) (value 2048.0)))
