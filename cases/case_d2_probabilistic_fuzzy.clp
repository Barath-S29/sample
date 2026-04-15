; ============================================================================
; CASE: D2 — PROBABILISTIC & FUZZY (LEGACY SERVER)
; ============================================================================
; This case simulates a degraded legacy server combining multiple risk factors:
;   - Weak protocol (TLSv1.0)   -> feat-weak-protocol    (CF 0.9)
;   - Weak cipher (RC4-SHA)     -> feat-weak-cipher       (CF 0.85)
;   - SHA-1 signature           -> feat-weak-crypto-sha1
;   - Weak key size (1024-bit)  -> feat-weak-crypto-keysize
;   - Self-signed, internal     -> feat-internal-self-signed (CF 0.7)
;   - Missing OCSP              -> feat-missing-ocsp      (CF 0.5)
;   - Missing HSTS              -> feat-missing-hsts      (CF 0.6)
;   - Missing SNI               -> feat-missing-sni
;   - Incomplete chain          -> feat-chain-incomplete
;
; Expected diagnoses:
;   - insecure-connection   (CF ~0.81 = 0.9 * 0.9)
;   - weak-cipher           (CF ~0.765 = 0.85 * 0.9)
;   - weak-crypto           (CF 0.75)
;   - obsolete-system       (CF ~0.855 = 0.9 * 0.95, weak-protocol + weak-key)
;   - internal-self-signed  (CF ~0.49 = 0.7 * 0.7)
;   - revocation-risk       (CF 0.25 = 0.5 * 0.5)
;   - sni-missing           (CF 0.60)
;   - incomplete-chain      (CF 0.88)
;   - fuzzy-risk-assessment via RiskLevel Critical (DaysToExpiry=5 -> CriticallySoon)
; ============================================================================

(printout t crlf "Loading CASE: D2 Probabilistic & Fuzzy (Legacy Server)" crlf)
(reset)

(assert
  (tls-error
    (error-code HANDSHAKE_FAILURE)
    (error-message "handshake failed")
    (error-category handshake-failure)
    (severity medium))

  (certificate
    (common-name "legacy-server.internal")
    (subject-alt-names "legacy-server.internal")
    (not-before "2026-01-01T00:00:00Z")
    (not-after "2026-04-19T00:00:00Z")
    (signature-algorithm "sha1WithRSAEncryption")
    (key-size 1024)
    (issuer "legacy-server.internal")
    (serial-number "00:DE:AD:BE:EF:CA:FE:01")
    (is-self-signed yes))

  (certificate-chain
    (chain-length 1)
    (has-intermediate no)
    (root-trusted no)
    (chain-complete no)
    (missing-certificates))

  (environment
    (client-os "Windows Server 2008")
    (server-type "IIS/7.5")
    (requested-hostname "legacy-server.internal")
    (sni-value "")
    (sni-sent no)
    (current-timestamp "2026-04-14T00:00:00Z"))

  (connection
    (protocol-version "TLSv1.0")
    (cipher-suite "RC4-SHA")
    (ocsp-stapling no)
    (hsts-enabled no)
    (server-location "internal")))

; Fuzzy inputs: 5 days until expiry (fully CriticallySoon) and weak 1024-bit key.
(assert (DaysToExpiry (5 1)))
(assert (KeySize (1024 1)))
