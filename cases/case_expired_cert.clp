; ============================================================================
; CASE: EXPIRED CERTIFICATE (PROBABILISTIC & FUZZY)
; ============================================================================
; Expected diagnoses:
;   - expired-certificate  (CF ~0.99, boosted by error code)
;   - fuzzy-risk-assessment via RiskLevel Critical (DaysToExpiry=0 -> CriticallySoon)
; ============================================================================

(printout t crlf "Loading CASE: Expired Certificate" crlf)
(reset)

(assert
  (tls-error
    (error-code CERT_HAS_EXPIRED)
    (error-message "certificate has expired")
    (error-category certificate-invalid)
    (severity critical))

  (certificate
    (common-name "expired.example.com")
    (subject-alt-names "expired.example.com")
    (not-before "2023-01-01T00:00:00Z")
    (not-after "2024-01-01T00:00:00Z")
    (signature-algorithm "sha256WithRSAEncryption")
    (key-size 2048)
    (issuer "DigiCert SHA2 Secure Server CA")
    (serial-number "01:AA:BB:CC:DD:EE:FF:00")
    (is-self-signed no))

  (certificate-chain
    (chain-length 3)
    (has-intermediate yes)
    (root-trusted yes)
    (chain-complete yes)
    (missing-certificates))

  (environment
    (client-os "Ubuntu 22.04")
    (server-type "nginx/1.24.0")
    (requested-hostname "expired.example.com")
    (sni-value "expired.example.com")
    (sni-sent yes)
    (current-timestamp "2026-04-01T00:00:00Z"))

  (connection
    (protocol-version "TLSv1.3")
    (cipher-suite "TLS_AES_256_GCM_SHA384")
    (ocsp-stapling yes)
    (hsts-enabled yes)
    (server-location "external")))

; Fuzzy inputs: certificate expired 90 days ago — treated as 0 days remaining
; (clamped to universe minimum) so DaysToExpiry is fully CriticallySoon.
; KeySize 2048 is fully Standard.
(assert (DaysToExpiry (0 1)))
(assert (KeySize (2048 1)))
