; ============================================================================
; RULEBASE.CLP - Diagnostic Logic for TLS/PKI Expert System
; ============================================================================
; This file contains the "Rulebase" component (R) of our expert system.
; It defines the production rules (IF-THEN) that the inference engine uses
; to transform raw evidence into meaningful features, then into diagnoses,
; and finally into actionable recommendations.
;
; UNCERTAINTY MODELS USED:
;   - Probabilistic: Certainty Factors Theory via FuzzyCLIPS native
;     (assert ... CF x.x) and (declare (CF x.x)) syntax.
;   - Possibilistic: Fuzzy Logic Theory via FuzzyCLIPS native fuzzy
;     deftemplate pattern matching (e.g., (DaysToExpiry CriticallySoon)).
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
; FEATURE EXTRACTION RULES (CRISP / CERTAIN)
; ---------------------------------------------------------
; These rules analyze the Factbase to identify specific high-level
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
; FEATURE EXTRACTION RULES (PROBABILISTIC - CERTAINTY FACTORS)
; ---------------------------------------------------------
; These rules use FuzzyCLIPS native CF syntax:
;   (declare (CF x.x)) sets the rule's CF.
;   (assert ... CF x.x) attaches a CF to the asserted fact.
; FuzzyCLIPS automatically combines fact CF * rule CF for the output.

; Identifies use of deprecated TLS protocols (1.0 or 1.1).
; CF 0.9 — nearly certain this is a weak protocol risk.
(defrule feat-weak-protocol
  (declare (CF 0.9))
  (connection (protocol-version ?v&"TLSv1.0"|"TLSv1.1"))
  =>
  (assert (feature (name weak-protocol) (value yes)))
  (printout t "Feature: Weak Protocol (" ?v ") detected (CF: 0.9)" crlf))

; Logic for Self-Signed Certs: Risk depends on network location.
; Internal self-signed is less critical (CF 0.7).
(defrule feat-internal-self-signed
  (declare (CF 0.7))
  (certificate (is-self-signed yes))
  (connection (server-location "internal"))
  =>
  (assert (feature (name internal-self-signed) (value yes)))
  (printout t "Feature: Internal Self-Signed cert (CF: 0.7)" crlf))

; External self-signed is high risk (CF 0.95).
(defrule feat-external-self-signed
  (declare (CF 0.95))
  (certificate (is-self-signed yes))
  (connection (server-location "external"))
  =>
  (assert (feature (name external-self-signed) (value yes)))
  (printout t "Feature: EXTERNAL Self-Signed cert (HIGH RISK, CF: 0.95)" crlf))

; Identifies lack of HSTS, which increases Man-In-The-Middle (MITM) risk.
; CF 0.6 — moderate confidence this is a meaningful risk indicator.
(defrule feat-missing-hsts
  (declare (CF 0.6))
  (connection (hsts-enabled no))
  =>
  (assert (feature (name missing-hsts) (value yes)))
  (printout t "Feature: Missing HSTS (MITM Risk, CF: 0.6)" crlf))

; Identifies missing OCSP stapling, which hinders revocation checks.
; CF 0.5 — uncertain whether this is an active problem or just a configuration gap.
(defrule feat-missing-ocsp
  (declare (CF 0.5))
  (connection (ocsp-stapling no))
  =>
  (assert (feature (name missing-ocsp) (value yes)))
  (printout t "Feature: Missing OCSP stapling (CF: 0.5)" crlf))

; Identifies use of old/weak ciphers like RC4 or 3DES.
; CF 0.85 — high confidence these are insecure.
(defrule feat-weak-cipher
  (declare (CF 0.85))
  (connection (cipher-suite ?cs&"RC4-SHA"|"DES-CBC3-SHA"))
  =>
  (assert (feature (name weak-cipher) (value yes)))
  (printout t "Feature: Weak Cipher (" ?cs ") detected (CF: 0.85)" crlf))

; ---------------------------------------------------------
; DIAGNOSIS RULES (PROBABILISTIC - CERTAINTY FACTORS)
; ---------------------------------------------------------
; Rule CF is declared via (declare (CF x.x)).
; FuzzyCLIPS propagates: CF_output = CF_fact * CF_rule automatically.

; Diagnoses insecure connections based on weak protocols.
; Rule CF 0.9 — the weak protocol feature strongly implies insecure connection.
(defrule dx-insecure-protocol
  (declare (CF 0.9))
  (feature (name weak-protocol) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type insecure-connection)
            (confidence medium)
            (confidence-score 0.75)
            (cf 0.75)
            (description "Connection uses deprecated TLS version (POODLE/BEAST risk)")))
  (assert (reasoning-trace
            (rule-fired dx-insecure-protocol)
            (evidence-used "weak-protocol=yes")
            (conclusion "insecure-connection")))
  (printout t "DIAGNOSIS: Insecure Protocol" crlf))

; Diagnoses critical MITM danger for external self-signed certs without HSTS.
; Both features must be present; rule CF 0.95 reflects high confidence.
(defrule dx-high-mitm-danger
  (declare (CF 0.95))
  (feature (name external-self-signed) (value yes))
  (feature (name missing-hsts) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type mitm-vulnerability)
            (confidence high)
            (confidence-score 0.90)
            (cf 0.90)
            (description "Extreme risk of Man-In-The-Middle attack on public server")))
  (assert (reasoning-trace
            (rule-fired dx-high-mitm-danger)
            (evidence-used "external-self-signed=yes AND missing-hsts=yes")
            (conclusion "mitm-vulnerability")))
  (printout t "DIAGNOSIS: MITM Vulnerability" crlf))

; Diagnoses internal self-signed certificates (acceptable in internal networks).
; Rule CF 0.7 — moderate confidence; internal use is generally tolerable.
(defrule dx-internal-self-signed
  (declare (CF 0.7))
  (feature (name internal-self-signed) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type internal-self-signed)
            (confidence medium)
            (confidence-score 0.70)
            (cf 0.70)
            (description "Self-signed certificate on internal server (typically acceptable)")))
  (assert (reasoning-trace
            (rule-fired dx-internal-self-signed)
            (evidence-used "internal-self-signed=yes")
            (conclusion "internal-self-signed")))
  (printout t "DIAGNOSIS: Internal Self-Signed Certificate" crlf))

; Diagnoses obsolete system configurations (weak protocol AND weak key together).
; Rule CF 0.95 — combination of two legacy indicators is very strong evidence.
(defrule dx-obsolete-system
  (declare (CF 0.95))
  (feature (name weak-protocol) (value yes))
  (feature (name weak-key-size) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type obsolete-system)
            (confidence high)
            (confidence-score 0.88)
            (cf 0.88)
            (description "Server is using multiple legacy security parameters")))
  (printout t "DIAGNOSIS: Obsolete System" crlf))

; Identifies potential privacy issues with revocation checking.
; Rule CF 0.5 — possible issue but not definitive.
(defrule dx-revocation-warning
  (declare (CF 0.5))
  (feature (name missing-ocsp) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type revocation-risk)
            (confidence possible)
            (confidence-score 0.40)
            (cf 0.40)
            (description "Revocation status cannot be verified quickly (privacy/perf risk)")))
  (printout t "DIAGNOSIS: Revocation Risk" crlf))

; Diagnoses an expired certificate and provides a high-confidence score.
; No rule CF declared — certainty is crisp (definite from error code).
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

; Diagnoses insecure cipher suites.
; Rule CF 0.9 — weak cipher strongly implies weak encryption risk.
(defrule dx-weak-cipher
  (declare (CF 0.9))
  (feature (name weak-cipher) (value yes))
  =>
  (assert (diagnosis
            (diagnosis-type weak-cipher)
            (confidence medium)
            (confidence-score 0.70)
            (cf 0.70)
            (description "Connection uses weak or broken encryption algorithms")))
  (printout t "DIAGNOSIS: Weak Cipher Suite" crlf))

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
; Rule CF 0.6 — moderate confidence; missing SNI may or may not cause problems.
(defrule dx-missing-sni
  (declare (CF 0.6))
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
; CONFIDENCE BOOSTING RULES
; ---------------------------------------------------------

; Increases confidence if the specific OpenSSL error code for expiry is present.
(defrule boost-expired-if-errorcode
  ?d <- (diagnosis (diagnosis-type expired-certificate) (confidence-score ?s))
  (tls-error (error-code CERT_HAS_EXPIRED))
  (not (feature (name boost-expired-done)))
  =>
  (modify ?d (confidence-score (min 0.99 (+ ?s 0.03))))
  (assert (feature (name boost-expired-done) (value yes)))
  (printout t "Confidence BOOSTED for expired-certificate diagnosis" crlf))

; Increases confidence in chain issues if the specific issuer-missing code is present.
(defrule boost-chain-if-common-openssl
  ?d <- (diagnosis (diagnosis-type incomplete-chain) (confidence-score ?s))
  (tls-error (error-code UNABLE_TO_GET_ISSUER_CERT))
  (not (feature (name boost-chain-done)))
  =>
  (modify ?d (confidence-score (min 0.95 (+ ?s 0.07))))
  (assert (feature (name boost-chain-done) (value yes)))
  (printout t "Confidence BOOSTED for incomplete-chain diagnosis" crlf))

; ---------------------------------------------------------
; FUZZY LOGIC - FUZZIFICATION
; ---------------------------------------------------------
; In FuzzyCLIPS, fuzzification is done at assertion time, not via separate rules.
; Case files assert crisp values using fuzzy fact syntax and FuzzyCLIPS
; automatically computes membership degrees against all linguistic terms.
;
; Example assertions in case files:
;   (assert (DaysToExpiry (7 1)))    ; crisp 7 days — engine computes membership
;   (assert (KeySize (1024 1)))      ; crisp 1024 bits — engine computes membership
;
; Alternatively, assert using a linguistic term directly:
;   (assert (DaysToExpiry CriticallySoon))
;   (assert (KeySize Weak))
;
; No explicit fuzzification rules are needed — FuzzyCLIPS handles this natively.

; ---------------------------------------------------------
; FUZZY REASONING RULES
; ---------------------------------------------------------
; These rules use FuzzyCLIPS native fuzzy pattern matching.
; The pattern (DaysToExpiry CriticallySoon) fires with a match degree
; proportional to how much the asserted value overlaps with the
; 'CriticallySoon' membership function — partial overlaps produce partial firing.
; Rule CF is declared via (declare (CF x.x)).

; Critical risk: certificate is imminently expiring.
; Rule CF 0.95 — imminent expiry is a near-certain critical risk.
(defrule fuzzy-risk-critical
  (declare (CF 0.95))
  (DaysToExpiry CriticallySoon)
  =>
  (assert (RiskLevel Critical))
  (printout t "Fuzzy Inference: Risk is CRITICAL due to imminent expiry." crlf))

; High risk: certificate expiry is approaching.
; Only fires if no Critical risk has already been established.
; Rule CF 0.8 — approaching expiry is a strong but not absolute risk signal.
(defrule fuzzy-risk-high
  (declare (CF 0.8))
  (DaysToExpiry Soon)
  (not (RiskLevel Critical))
  =>
  (assert (RiskLevel High))
  (printout t "Fuzzy Inference: Risk is HIGH due to approaching expiry." crlf))

; Medium risk: key size is weak but expiry is not imminent.
; Only fires if no Critical or High risk exists.
; Rule CF 0.6 — weak key is a meaningful but lower-urgency risk.
(defrule fuzzy-risk-medium-weak-key
  (declare (CF 0.6))
  (KeySize Weak)
  (not (RiskLevel Critical))
  (not (RiskLevel High))
  =>
  (assert (RiskLevel Medium))
  (printout t "Fuzzy Inference: Risk is MEDIUM due to weak key size." crlf))

; Low risk: certificate is safe and key size is standard.
; Only fires when no higher risk level has been established.
; Rule CF 0.2 — good posture, but never zero risk in security.
(defrule fuzzy-risk-low-safe
  (declare (CF 0.2))
  (DaysToExpiry Safe)
  (KeySize Standard)
  (not (RiskLevel Critical))
  (not (RiskLevel High))
  (not (RiskLevel Medium))
  =>
  (assert (RiskLevel Low))
  (printout t "Fuzzy Inference: Risk is LOW (Safe expiry + Standard key)." crlf))

; ---------------------------------------------------------
; FUZZY OUTPUT TO DIAGNOSIS MAPPING
; ---------------------------------------------------------
; Maps the fuzzy RiskLevel output to a crisp diagnosis fact.
; FuzzyCLIPS provides the matched linguistic term via pattern binding.
; The degree slot captures the fuzzy membership of the inferred risk level.

; NOTE: get-fs-value requires a fact-index and x-value — it cannot extract a
; scalar from a linguistic term binding. Instead we map the matched term to a
; static CF score that reflects the centre of each membership function.
; dx-fuzzy-risk: split into 4 explicit-term rules.
; In FuzzyCLIPS, binding ?t from (RiskLevel ?t) yields a fuzzy set object,
; NOT a printable symbol. Matching each term directly avoids the comparison bug.

(defrule dx-fuzzy-risk-critical
  (RiskLevel Critical)
  (not (diagnosis (diagnosis-type fuzzy-risk-assessment)))
  =>
  (assert (diagnosis
            (diagnosis-type fuzzy-risk-assessment)
            (confidence high)
            (confidence-score 0.97)
            (cf 0.97)
            (description "Overall security risk level is: Critical")))
  (printout t "DIAGNOSIS: Fuzzy Risk Level: Critical" crlf))

(defrule dx-fuzzy-risk-high
  (RiskLevel High)
  (not (RiskLevel Critical))
  (not (diagnosis (diagnosis-type fuzzy-risk-assessment)))
  =>
  (assert (diagnosis
            (diagnosis-type fuzzy-risk-assessment)
            (confidence high)
            (confidence-score 0.80)
            (cf 0.80)
            (description "Overall security risk level is: High")))
  (printout t "DIAGNOSIS: Fuzzy Risk Level: High" crlf))

(defrule dx-fuzzy-risk-medium
  (RiskLevel Medium)
  (not (RiskLevel Critical))
  (not (RiskLevel High))
  (not (diagnosis (diagnosis-type fuzzy-risk-assessment)))
  =>
  (assert (diagnosis
            (diagnosis-type fuzzy-risk-assessment)
            (confidence medium)
            (confidence-score 0.50)
            (cf 0.50)
            (description "Overall security risk level is: Medium")))
  (printout t "DIAGNOSIS: Fuzzy Risk Level: Medium" crlf))

(defrule dx-fuzzy-risk-low
  (RiskLevel Low)
  (not (RiskLevel Critical))
  (not (RiskLevel High))
  (not (RiskLevel Medium))
  (not (diagnosis (diagnosis-type fuzzy-risk-assessment)))
  =>
  (assert (diagnosis
            (diagnosis-type fuzzy-risk-assessment)
            (confidence medium)
            (confidence-score 0.15)
            (cf 0.15)
            (description "Overall security risk level is: Low")))
  (printout t "DIAGNOSIS: Fuzzy Risk Level: Low" crlf))

; ---------------------------------------------------------
; FUZZY PRIORITY FEATURE RULES
; ---------------------------------------------------------
; These assert crisp 'priority' features from the fuzzy RiskLevel output,
; maintaining the same priority escalation logic as before.

(defrule fuzzy-priority-immediate
  (RiskLevel Critical)
  =>
  (assert (feature (name priority) (value immediate) (cf 0.99))))

(defrule fuzzy-priority-medium
  (RiskLevel Medium)
  =>
  (assert (feature (name priority) (value medium) (cf 0.60))))

(defrule fuzzy-priority-low
  (RiskLevel Low)
  =>
  (assert (feature (name priority) (value low) (cf 0.20))))

; ---------------------------------------------------------
; FUZZY-DRIVEN RECOMMENDATION RULES
; ---------------------------------------------------------
; These fire based on the fuzzy RiskLevel output and provide
; appropriate recommendations, preserving the original logic.

; Critical fuzzy risk triggers emergency certificate replacement recommendation.
(defrule rec-fuzzy-critical
  (RiskLevel Critical)
  =>
  (assert (recommendation
            (action-description "URGENT: Replace certificate and review security policy")
            (priority immediate)
            (steps "Perform emergency rotation" "Review all internal PKI standards"))))

; Low fuzzy risk triggers routine maintenance recommendation.
(defrule rec-fuzzy-low
  (RiskLevel Low)
  =>
  (assert (recommendation
            (action-description "Routine maintenance: No immediate action required")
            (priority low)
            (steps "Monitor validity window" "Perform standard rotation in 60 days"))))

; ---------------------------------------------------------
; RECOMMENDATION RULES (CRISP DIAGNOSIS-DRIVEN)
; ---------------------------------------------------------

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
