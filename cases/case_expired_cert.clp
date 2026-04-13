; ============================================================================
; CASE: EXPIRED CERTIFICATE (PROBABILISTIC & FUZZY)
; ============================================================================

(deffacts expired-case-facts
  ; Basic TLS Error from client
  (tls-error 
    (error-code CERT_HAS_EXPIRED) 
    (error-message "certificate has expired") 
    (error-category certificate-invalid) 
    (severity critical))

  ; Certificate details
  (certificate 
    (common-name "expired.example.com") 
    (subject-alt-names "expired.example.com")
    (not-before "2023-01-01T00:00:00Z")
    (not-after "2024-01-01T00:00:00Z")
    (signature-algorithm "sha256WithRSAEncryption")
    (key-size 2048)
    (is-self-signed no))

  ; Chain info
  (certificate-chain 
    (chain-complete yes)
    (has-intermediate yes)
    (root-trusted yes))

  ; Environment context
  (environment 
    (requested-hostname "expired.example.com")
    (sni-sent yes)
    (current-timestamp "2026-04-01T00:00:00Z"))

  ; NEW for Deliverable 2: Connection details (Probabilistic)
  (connection
    (protocol-version "TLSv1.3")
    (cipher-suite "TLS_AES_256_GCM_SHA384")
    (ocsp-stapling yes)
    (hsts-enabled yes)
    (server-location "external"))

  ; NEW for Deliverable 2: Fuzzy inputs (Possibilistic)
  (fuzzy-input (name DaysToExpiry) (value -90.0)) ; Expired 90 days ago
  (fuzzy-input (name KeySize) (value 2048.0)))
