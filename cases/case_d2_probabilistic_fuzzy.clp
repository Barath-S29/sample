; ============================================================================
; CASE: D2 PROBABILISTIC & FUZZY (NEW FEATURES)
; ============================================================================
; This case simulates a legacy server using a weak protocol (TLS 1.0) and a weak key size (1024), which should trigger multiple D2 rules.
; ============================================================================

(deffacts d2-test-facts
  ; Basic Info
  (tls-error 
    (error-code HANDSHAKE_FAILURE) 
    (error-message "handshake failed") 
    (error-category handshake-failure) 
    (severity medium))

  (certificate 
    (common-name "legacy-server.internal") 
    (subject-alt-names "legacy-server.internal")
    (not-before "2026-01-01T00:00:00Z")
    (not-after "2027-01-01T00:00:00Z")
    (signature-algorithm "sha1WithRSAEncryption")
    (key-size 1024)
    (is-self-signed yes)) ; Self-signed

  (certificate-chain 
    (chain-complete no)
    (has-intermediate no)
    (root-trusted no))

  (environment 
    (requested-hostname "legacy-server.internal")
    (sni-sent no)
    (current-timestamp "2026-04-01T00:00:00Z"))

  ; PROBABILISTIC INPUTS
  (connection
    (protocol-version "TLSv1.0")      ; Weak protocol -> insecure-connection
    (cipher-suite "RC4-SHA")          ; Weak cipher -> weak-cipher
    (ocsp-stapling no)                ; Missing OCSP -> revocation-risk
    (hsts-enabled no)                 ; Missing HSTS -> mitm-risk
    (server-location "internal"))     ; Internal location -> internal-self-signed

  ; FUZZY INPUTS
  (DaysToExpiry (5.0 0) (5.0 1) (5.0 0)) ; CriticallySoon -> critical-risk
  (KeySize (1024.0 0) (1024.0 1) (1024.0 0))) ; Weak -> medium-risk
