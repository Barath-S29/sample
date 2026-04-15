; ============================================================================
; CASE: INCOMPLETE CERTIFICATE CHAIN
; ============================================================================
; Expected diagnoses:
;   - incomplete-chain  (CF 0.88, boosted by UNABLE_TO_GET_ISSUER_CERT error code)
;   - fuzzy-risk-assessment via RiskLevel Safe (DaysToExpiry=365 -> Safe)
; ============================================================================

(printout t crlf "Loading CASE: Incomplete Certificate Chain" crlf)
(reset)

(assert
  (tls-error
    (error-code UNABLE_TO_GET_ISSUER_CERT)
    (error-message "unable to get issuer certificate")
    (error-category trust-failure)
    (severity high))

  (certificate
    (common-name "api.example.com")
    (subject-alt-names "api.example.com")
    (not-before "2025-06-01T00:00:00Z")
    (not-after "2026-06-01T00:00:00Z")
    (signature-algorithm "sha256WithRSAEncryption")
    (key-size 2048)
    (issuer "Example Intermediate CA")
    (serial-number "04:12:34:56:78:90:AB:CD")
    (is-self-signed no))

  (certificate-chain
    (chain-length 1)
    (has-intermediate no)
    (root-trusted unknown)
    (chain-complete no)
    (missing-certificates "Example Intermediate CA"))

  (environment
    (client-os "Windows 11")
    (server-type "Apache/2.4.41")
    (requested-hostname "api.example.com")
    (sni-value "api.example.com")
    (sni-sent yes)
    (current-timestamp "2026-04-12T10:00:00Z"))

  (connection
    (protocol-version "TLSv1.3")
    (cipher-suite "TLS_AES_256_GCM_SHA384")
    (ocsp-stapling yes)
    (hsts-enabled yes)
    (server-location "external")))

; Fuzzy inputs: ~50 days until expiry (Soon range) and standard 2048-bit key.
(assert (DaysToExpiry (50 1)))
(assert (KeySize (2048 1)))
