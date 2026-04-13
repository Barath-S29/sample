; ============================================================================
; RULEBASE.CLP - Diagnostic Logic for TLS/PKI Expert System
; ============================================================================
; This file contains the "Rulebase" component (R) of our expert system.
; It defines the production rules (IF-THEN) that the inference engine uses to transform raw evidence into meaningful features, then into diagnoses, and finally into actionable recommendations.
; ============================================================================

; ---------------------------------------------------------
; INITIALIZATION
; ---------------------------------------------------------

; This rule provides immediate feedback to the user that the system 
; is ready for reasoning. It has high salience to ensure it runs first.
(defrule init-banner
  (declare (salience 1000))
  =>
  (printout t "TLS/PKI Diagnosis Expert System Initialized" crlf))

; ---------------------------------------------------------
; FEATURE EXTRACTION RULES
; ---------------------------------------------------------
; These rules analyze the "Factbase" to identify specific high-level 
; technical conditions (Features) that indicate potential problems.

; Identifies an expired certificate by matching a specific TLS error code.
(defrule feat-expired-by-error
  (tls-error (error-code CERT_HAS_EXPIRED))
  =>
  (assert (feature (name is-expired) (value yes)))
  (printout t "Feature: Certificate is EXPIRED" crlf))

; Identifies a certificate that is not yet valid (future start date).
(defrule feat-notyetvalid-by-error
  (tls-error (error-code CERT_NOT_YET_VALID))
  =>
  (assert (feature (name not-yet-valid) (value yes)))
  (printout t "Feature: Certificate is NOT-YET-VALID" crlf))

; Detects the use of the deprecated SHA-1 hashing algorithm.
(defrule feat-weak-crypto-sha1
  (certificate (signature-algorithm "sha1WithRSAEncryption"))
  =>
  (assert (feature (name weak-signature) (value yes)))
  (printout t "Feature: Weak signature algorithm (SHA1)" crlf))

; Flags RSA keys smaller than the industry-standard 2048 bits.
(defrule feat-weak-crypto-keysize
  (certificate (key-size ?k&:(< ?k 2048)))
  =>
  (assert (feature (name weak-key-size) (value yes)))
  (printout t "Feature: Weak key size (<2048)" crlf))

; Identifies an incomplete trust chain based on explicit flag.
(defrule feat-chain-incomplete
  (certificate-chain (chain-complete no))
  =>
  (assert (feature (name chain-incomplete) (value yes)))
  (printout t "Feature: Certificate chain is INCOMPLETE" crlf))

; Specifically flags cases where the intermediate CA certificate is missing.
(defrule feat-missing-intermediate
  (certificate-chain (has-intermediate no))
  =>
  (assert (feature (name missing-intermediate) (value yes)))
  (printout t "Feature: Missing intermediate certificate" crlf))

; Identifies if the Root CA is not recognized by the client's trust store.
(defrule feat-untrusted-root
  (certificate-chain (root-trusted no))
  =>
  (assert (feature (name untrusted-root) (value yes)))
  (printout t "Feature: Root CA is UNTRUSTED" crlf))

; Flags missing Server Name Indication (SNI) which can cause wrong-cert issues.
(defrule feat-missing-sni
  (environment (sni-sent no))
  =>
  (assert (feature (name missing-sni) (value yes)))
  (printout t "Feature: SNI is MISSING" crlf))

; Logic for Hostname Mismatch:
; Matches if the requested hostname is NOT the Common Name (CN) 
; AND is NOT found in the Subject Alternative Name (SAN) list.
(defrule feat-hostname-mismatch
  (environment (requested-hostname ?h))
  (certificate (common-name ?cn) (subject-alt-names $?sans))
  (test (and (neq ?h ?cn) (not (member$ ?h $?sans))))
  =>
  (assert (feature (name hostname-mismatch) (value yes)))
  (printout t "Feature: Hostname mismatch detected" crlf))

; Confirms that the requested hostname exactly matches the certificate identity.
(defrule feat-hostname-exact-match
  (environment (requested-hostname ?h))
  (certificate (common-name ?cn))
  (test (eq ?h ?cn))
  =>
  (assert (feature (name hostname-match) (value yes)))
  (printout t "Feature: Hostname EXACT match found" crlf))

; ---------------------------------------------------------
; FEATURE EXTRACTION RULES (PROBABILISTIC)
; ---------------------------------------------------------

; Identifies use of deprecated TLS protocols (1.0 or 1.1).
(defrule feat-weak-protocol
  (connection (protocol-version ?v&"TLSv1.0"|"TLSv1.1"))
  =>
  (assert (feature (name weak-protocol) (value yes) (cf 0.9)))
  (printout t "Feature: Weak Protocol (" ?v ") detected (CF: 0.9)" crlf))

; Logic for Self-Signed Certs: Risk depends on network location.
(defrule feat-internal-self-signed
  (certificate (is-self-signed yes))
  (connection (server-location "internal"))
  =>
  (assert (feature (name internal-self-signed) (value yes) (cf 0.7)))
  (printout t "Feature: Internal Self-Signed cert (CF: 0.7)" crlf))

(defrule feat-external-self-signed
  (certificate (is-self-signed yes))
  (connection (server-location "external"))
  =>
  (assert (feature (name external-self-signed) (value yes) (cf 0.95)))
  (printout t "Feature: EXTERNAL Self-Signed cert (HIGH RISK, CF: 0.95)" crlf))

; Identifies lack of HSTS, which increases Man-In-The-Middle (MITM) risk.
(defrule feat-missing-hsts
  (connection (hsts-enabled no))
  =>
  (assert (feature (name missing-hsts) (value yes) (cf 0.6)))
  (printout t "Feature: Missing HSTS (MITM Risk, CF: 0.6)" crlf))

; Identifies missing OCSP stapling, which hinders revocation checks.
(defrule feat-missing-ocsp
  (connection (ocsp-stapling no))
  =>
  (assert (feature (name missing-ocsp) (value yes) (cf 0.5)))
  (printout t "Feature: Missing OCSP stapling (CF: 0.5)" crlf))

; ---------------------------------------------------------
; DIAGNOSIS RULES (PROBABILISTIC)
; ---------------------------------------------------------

; Diagnoses insecure connections based on weak protocols.
(defrule dx-insecure-protocol
  (feature (name weak-protocol) (value yes) (cf ?c))
  =>
  (assert (diagnosis
            (diagnosis-type insecure-connection)
            (confidence medium)
            (confidence-score 0.75)
            (cf (* ?c 0.9))
            (description "Connection uses deprecated TLS version (POODLE/BEAST risk)")))
  (assert (reasoning-trace
            (rule-fired dx-insecure-protocol)
            (evidence-used (str-cat "weak-protocol=" ?c))
            (conclusion "insecure-connection")))
  (printout t "DIAGNOSIS: Insecure Protocol (CF: " (* ?c 0.9) ")" crlf))

; Diagnoses critical MITM danger for external self-signed certs without HSTS.
(defrule dx-high-mitm-danger
  (feature (name external-self-signed) (value yes) (cf ?c1))
  (feature (name missing-hsts) (value yes) (cf ?c2))
  =>
  (bind ?combined-cf (* ?c1 ?c2 1.0))
  (assert (diagnosis
            (diagnosis-type mitm-vulnerability)
            (confidence high)
            (confidence-score 0.90)
            (cf ?combined-cf)
            (description "Extreme risk of Man-In-The-Middle attack on public server")))
  (assert (reasoning-trace
            (rule-fired dx-high-mitm-danger)
            (evidence-used (str-cat "ext-self-signed=" ?c1 " AND missing-hsts=" ?c2))
            (conclusion "mitm-vulnerability")))
  (printout t "DIAGNOSIS: MITM Vulnerability (CF: " ?combined-cf ")" crlf))

; Diagnoses internal self-signed certificates (acceptable in internal networks).
(defrule dx-internal-self-signed
  (feature (name internal-self-signed) (value yes) (cf ?c))
  =>
  (assert (diagnosis
            (diagnosis-type internal-self-signed)
            (confidence medium)
            (confidence-score 0.70)
            (cf ?c)
            (description "Self-signed certificate on internal server (typically acceptable)")))
  (assert (reasoning-trace
            (rule-fired dx-internal-self-signed)
            (evidence-used (str-cat "internal-self-signed=" ?c))
            (conclusion "internal-self-signed")))
  (printout t "DIAGNOSIS: Internal Self-Signed Certificate (CF: " ?c ")" crlf))

; Diagnoses obsolete system configurations.
(defrule dx-obsolete-system
  (feature (name weak-protocol) (value yes) (cf ?c1))
  (feature (name weak-key-size) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type obsolete-system)
            (confidence high)
            (confidence-score 0.88)
            (cf 0.95)
            (description "Server is using multiple legacy security parameters")))
  (printout t "DIAGNOSIS: Obsolete System (CF: 0.95)" crlf))

; Identifies potential privacy issues with revocation checking.
(defrule dx-revocation-warning
  (feature (name missing-ocsp) (value yes) (cf ?c))
  =>
  (assert (diagnosis
            (diagnosis-type revocation-risk)
            (confidence possible)
            (confidence-score 0.40)
            (cf (* ?c 0.5))
            (description "Revocation status cannot be verified quickly (privacy/perf risk)")))
  (printout t "DIAGNOSIS: Revocation Risk (CF: " (* ?c 0.5) ")" crlf))

; ---------------------------------------------------------
; DIAGNOSIS RULES (UPDATED FOR CF)
; ---------------------------------------------------------

; Diagnoses an expired certificate and provides a high-confidence score.
(defrule dx-expired
  (feature (name is-expired) (value yes))
  (tls-error (error-category certificate-invalid))
  =>
  (assert (diagnosis
            (diagnosis-type expired-certificate)
            (confidence definite)
            (confidence-score 0.95)
            (cf 0.99)
            (description "Certificate has expired and is no longer valid")))
  (assert (reasoning-trace
            (rule-fired dx-expired)
            (evidence-used "is-expired=yes, error-category=certificate-invalid")
            (conclusion "expired-certificate")))
  (printout t "DIAGNOSIS: Expired Certificate (CF: 0.99)" crlf))

; Diagnoses trust path issues caused by missing CA certificates.
(defrule dx-chain-incomplete
  (or (feature (name chain-incomplete) (value yes))
      (feature (name missing-intermediate) (value yes)))
  =>
  (assert (diagnosis
            (diagnosis-type incomplete-chain)
            (confidence high)
            (confidence-score 0.85)
            (cf 0.88)
            (description "Certificate chain is incomplete (likely missing intermediate CA cert)")))
  (assert (reasoning-trace
            (rule-fired dx-chain-incomplete)
            (evidence-used "chain-incomplete=yes OR missing-intermediate=yes")
            (conclusion "incomplete-chain")))
  (printout t "DIAGNOSIS: Incomplete Certificate Chain (CF: 0.88)" crlf))

; Identifies use of old/weak ciphers like RC4 or 3DES.
(defrule feat-weak-cipher
  (connection (cipher-suite ?cs&"RC4-SHA"|"DES-CBC3-SHA"))
  =>
  (assert (feature (name weak-cipher) (value yes) (cf 0.85)))
  (printout t "Feature: Weak Cipher (" ?cs ") detected (CF: 0.85)" crlf))

; Diagnoses insecure cipher suites.
(defrule dx-weak-cipher
  (feature (name weak-cipher) (value yes) (cf ?c))
  =>
  (assert (diagnosis
            (diagnosis-type weak-cipher)
            (confidence medium)
            (confidence-score 0.70)
            (cf (* ?c 0.9))
            (description "Connection uses weak or broken encryption algorithms")))
  (printout t "DIAGNOSIS: Weak Cipher Suite (CF: " (* ?c 0.9) ")" crlf))

; ---------------------------------------------------------
; DIAGNOSIS RULES (UPDATED FOR CF)
; ---------------------------------------------------------

; Diagnoses when the certificate was issued for a different domain.
(defrule dx-hostname-mismatch
  (feature (name hostname-mismatch) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type hostname-mismatch)
            (confidence definite)
            (confidence-score 0.92)
            (cf 0.98)
            (description "Requested hostname does not match certificate CN/SAN")))
  (assert (reasoning-trace
            (rule-fired dx-hostname-mismatch)
            (evidence-used "hostname-mismatch=yes")
            (conclusion "hostname-mismatch")))
  (printout t "DIAGNOSIS: Hostname Mismatch (CF: 0.98)" crlf))

; Diagnoses potential SNI-related issues where the server provides a default cert.
(defrule dx-missing-sni
  (feature (name missing-sni) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type sni-missing)
            (confidence medium)
            (confidence-score 0.65)
            (cf 0.60)
            (description "Client did not send SNI; server may return default certificate")))
  (assert (reasoning-trace
            (rule-fired dx-missing-sni)
            (evidence-used "missing-sni=yes")
            (conclusion "sni-missing")))
  (printout t "DIAGNOSIS: Missing SNI (CF: 0.60)" crlf))

; Diagnoses use of insecure cryptographic algorithms or small keys.
(defrule dx-weak-crypto
  (or (feature (name weak-signature) (value yes))
      (feature (name weak-key-size) (value yes)))
  =>
  (assert (diagnosis
            (diagnosis-type weak-crypto)
            (confidence medium)
            (confidence-score 0.70)
            (cf 0.75)
            (description "Weak or deprecated cryptographic parameters detected")))
  (assert (reasoning-trace
            (rule-fired dx-weak-crypto)
            (evidence-used "weak-signature=yes OR weak-key-size=yes")
            (conclusion "weak-crypto")))
  (printout t "DIAGNOSIS: Weak Cryptography (CF: 0.75)" crlf))

; Diagnoses trust issues where the client does not trust the signing CA.
(defrule dx-untrusted-root
  (feature (name untrusted-root) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type untrusted-root)
            (confidence high)
            (confidence-score 0.88)
            (cf 0.90)
            (description "Root CA is not trusted by the client trust store")))
  (assert (reasoning-trace
            (rule-fired dx-untrusted-root)
            (evidence-used "untrusted-root=yes")
            (conclusion "untrusted-root")))
  (printout t "DIAGNOSIS: Untrusted Root CA (CF: 0.90)" crlf))

; Diagnoses certificates used before their activation date.
(defrule dx-not-yet-valid
  (feature (name not-yet-valid) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type not-yet-valid)
            (confidence high)
            (confidence-score 0.86)
            (cf 0.92)
            (description "Certificate validity has not started (clock skew possible)")))
  (assert (reasoning-trace
            (rule-fired dx-not-yet-valid)
            (evidence-used "not-yet-valid=yes")
            (conclusion "not-yet-valid")))
  (printout t "DIAGNOSIS: Certificate Not Yet Valid (CF: 0.92)" crlf))

; ---------------------------------------------------------
; FUZZY LOGIC - FUZZIFICATION RULES
; ---------------------------------------------------------

; Fuzzifies 'DaysToExpiry' into linguistic terms.
(defrule fuzzify-expiry-crit
  (fuzzy-input (name DaysToExpiry) (value ?v&:(<= ?v 10)))
  =>
  (assert (linguistic-variable (name DaysToExpiry) (term CriticallySoon) (degree 1.0))))

(defrule fuzzify-expiry-soon
  (fuzzy-input (name DaysToExpiry) (value ?v&:(and (> ?v 10) (<= ?v 45))))
  =>
  (assert (linguistic-variable (name DaysToExpiry) (term Soon) (degree 1.0))))

(defrule fuzzify-expiry-safe
  (fuzzy-input (name DaysToExpiry) (value ?v&:(> ?v 45)))
  =>
  (assert (linguistic-variable (name DaysToExpiry) (term Safe) (degree 1.0))))

; Fuzzifies 'KeySize' into linguistic terms.
(defrule fuzzify-keysize-weak
  (fuzzy-input (name KeySize) (value ?v&:(< ?v 2048)))
  =>
  (assert (linguistic-variable (name KeySize) (term Weak) (degree 1.0))))

(defrule fuzzify-keysize-standard
  (fuzzy-input (name KeySize) (value ?v&:(>= ?v 2048)))
  =>
  (assert (linguistic-variable (name KeySize) (term Standard) (degree 1.0))))

; ---------------------------------------------------------
; FUZZY REASONING RULES
; ---------------------------------------------------------

; Critical risk takes highest priority - excludes other risk rules from firing
(defrule fuzzy-risk-critical
  (linguistic-variable (name DaysToExpiry) (term CriticallySoon))
  =>
  (assert (linguistic-variable (name RiskLevel) (term Critical) (degree 0.95)))
  (printout t "Fuzzy Inference: Risk is CRITICAL due to imminent expiry." crlf))

; High risk - only fires if no Critical risk exists
(defrule fuzzy-risk-high
  (linguistic-variable (name DaysToExpiry) (term Soon))
  (not (linguistic-variable (name RiskLevel) (term Critical)))
  =>
  (assert (linguistic-variable (name RiskLevel) (term High) (degree 0.80)))
  (printout t "Fuzzy Inference: Risk is HIGH due to approaching expiry." crlf))

; Medium risk - only fires if no Critical or High risk exists
(defrule fuzzy-risk-medium-weak-key
  (linguistic-variable (name KeySize) (term Weak))
  (not (linguistic-variable (name RiskLevel) (term Critical)))
  (not (linguistic-variable (name RiskLevel) (term High)))
  =>
  (assert (linguistic-variable (name RiskLevel) (term Medium) (degree 0.60)))
  (printout t "Fuzzy Inference: Risk is MEDIUM due to weak key size." crlf))

; Low risk - only fires if no higher risk exists
(defrule fuzzy-risk-low-safe
  (linguistic-variable (name DaysToExpiry) (term Safe))
  (linguistic-variable (name KeySize) (term Standard))
  (not (linguistic-variable (name RiskLevel) (term Critical)))
  (not (linguistic-variable (name RiskLevel) (term High)))
  (not (linguistic-variable (name RiskLevel) (term Medium)))
  =>
  (assert (linguistic-variable (name RiskLevel) (term Low) (degree 0.20)))
  (printout t "Fuzzy Inference: Risk is LOW (Safe expiry + Standard key)." crlf))

; Fuzzy Mapping to Diagnosis
(defrule dx-fuzzy-risk
  (linguistic-variable (name RiskLevel) (term ?t) (degree ?d))
  =>
  (assert (diagnosis
            (diagnosis-type fuzzy-risk-assessment)
            (confidence medium)
            (confidence-score ?d)
            (cf ?d)
            (description (str-cat "Overall security risk level is: " ?t))))
  (printout t "DIAGNOSIS: Fuzzy Risk Level: " ?t " (Degree: " ?d ")" crlf))

; Fuzzy Priority Rules
(defrule fuzzy-priority-immediate
  (linguistic-variable (name RiskLevel) (term Critical))
  =>
  (assert (feature (name priority) (value immediate) (cf 0.99))))

(defrule fuzzy-priority-medium
  (linguistic-variable (name RiskLevel) (term Medium))
  =>
  (assert (feature (name priority) (value medium) (cf 0.60))))

(defrule fuzzy-priority-low
  (linguistic-variable (name RiskLevel) (term Low))
  =>
  (assert (feature (name priority) (value low) (cf 0.20))))

; Combines Fuzzy logic with probabilistic outcomes.
(defrule rec-fuzzy-critical
  (linguistic-variable (name RiskLevel) (term Critical))
  =>
  (assert (recommendation
            (action-description "URGENT: Replace certificate and review security policy")
            (priority immediate)
            (steps "Perform emergency rotation" "Review all internal PKI standards"))))

(defrule rec-fuzzy-low
  (linguistic-variable (name RiskLevel) (term Low))
  =>
  (assert (recommendation
            (action-description "Routine maintenance: No immediate action required")
            (priority low)
            (steps "Monitor validity window" "Perform standard rotation in 60 days"))))

; Increases confidence if the specific OpenSSL error code for expiry is present.
(defrule boost-expired-if-errorcode
  ?d <- (diagnosis (diagnosis-type expired-certificate) (confidence-score ?s))
  (tls-error (error-code CERT_HAS_EXPIRED))
  =>
  (modify ?d (confidence-score (min 0.99 (+ ?s 0.03))))
  (printout t "Confidence BOOSTED for expired-certificate diagnosis" crlf))

; Increases confidence in chain issues if the specific issuer-missing code is present.
(defrule boost-chain-if-common-openssl
  ?d <- (diagnosis (diagnosis-type incomplete-chain) (confidence-score ?s))
  (tls-error (error-code UNABLE_TO_GET_ISSUER_CERT))
  =>
  (modify ?d (confidence-score (min 0.95 (+ ?s 0.07))))
  (printout t "Confidence BOOSTED for incomplete-chain diagnosis" crlf))

; ---------------------------------------------------------
; RECOMMENDATION RULES
; ---------------------------------------------------------
; These rules provide the user with clear steps to resolve the diagnosis.

(defrule rec-expired
  (diagnosis (diagnosis-type expired-certificate))
  =>
  (assert (recommendation
            (action-description "Renew the TLS certificate immediately")
            (priority immediate)
            (steps
              "Contact CA or use ACME (e.g., Let's Encrypt)"
              "Generate new Certificate Signing Request (CSR)"
              "Install renewed cert on the server"
              "Verify chain completeness"
              "Re-test with SSL checker tool"))))

(defrule rec-chain
  (diagnosis (diagnosis-type incomplete-chain))
  =>
  (assert (recommendation
            (action-description "Install the missing intermediate certificate(s)")
            (priority high)
            (steps
              "Download intermediate CA cert from the CA website"
              "Configure server (Nginx/Apache) to present full chain"
              "Restart server software"
              "Verify with 'openssl s_client -connect host:443'"))))

(defrule rec-hostname
  (diagnosis (diagnosis-type hostname-mismatch))
  =>
  (assert (recommendation
            (action-description "Fix hostname / certificate identity mismatch")
            (priority high)
            (steps
              "Confirm the hostname the client is using to connect"
              "Issue a new certificate containing the correct SANs"
              "Update DNS or virtual host configuration if necessary"
              "Redeploy and re-test connection"))))

(defrule rec-sni
  (diagnosis (diagnosis-type sni-missing))
  =>
  (assert (recommendation
            (action-description "Enable SNI on the client or specify server name")
            (priority medium)
            (steps
              "Ensure client library/browser supports SNI"
              "Set correct SNI/ServerName in client configuration"
              "Re-test connection to verify correct cert is served"))))

(defrule rec-weak
  (diagnosis (diagnosis-type weak-crypto))
  =>
  (assert (recommendation
            (action-description "Upgrade cryptographic parameters for the certificate")
            (priority medium)
            (steps
              "Use SHA-256 or better signature algorithm"
              "Use RSA 2048-bit or higher, or ECDSA keys"
              "Rotate and reissue certificate"
              "Retest client compatibility"))))

(defrule rec-untrusted
  (diagnosis (diagnosis-type untrusted-root))
  =>
  (assert (recommendation
            (action-description "Update client trust store or use a trusted CA")
            (priority high)
            (steps
              "Install missing root CA certificate in client trust store"
              "Switch to a publicly trusted CA for public-facing services"
              "Re-test certificate validation on the client"))))

(defrule rec-notyetvalid
  (diagnosis (diagnosis-type not-yet-valid))
  =>
  (assert (recommendation
            (action-description "Synchronize system time and verify validity window")
            (priority high)
            (steps
              "Check system clock synchronization (e.g., NTP)"
              "Fix clock skew if detected"
              "Re-test certificate validity against current time"))))

(defrule rec-internal-self-signed
  (diagnosis (diagnosis-type internal-self-signed))
  =>
  (assert (recommendation
            (action-description "Internal self-signed certificate is acceptable for internal use")
            (priority low)
            (steps
              "Ensure this server is not exposed to external networks"
              "Distribute root CA to internal trust stores if needed by other services"
              "Plan certificate rotation schedule"
              "Consider internal PKI for larger deployments"))))
