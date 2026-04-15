; ============================================================================
; CASE: MISSING SNI
; ============================================================================
; Expected diagnoses:
;   - sni-missing (CF 0.60 — client on Windows Server 2012 did not send SNI)
;   - fuzzy-risk-assessment via RiskLevel Safe (DaysToExpiry=245 -> Safe)
; ============================================================================

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
    (not-before "2025-01-01T00:00:00Z")
    (not-after "2026-12-01T00:00:00Z")
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
    (server-location "external")))

; Fuzzy inputs: ~245 days until expiry (fully Safe) and standard 2048-bit key.
(assert (DaysToExpiry (245 1)))
(assert (KeySize (2048 1)))
