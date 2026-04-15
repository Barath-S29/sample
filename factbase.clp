; ============================================================================
; FACTBASE.CLP - Knowledge Representation for TLS/PKI Diagnosis
; ============================================================================

; This file defines the "Factbase" component (F) of our expert system's knowledge (K = F U R).
; It specifies the templates (data structures) used to represent observable evidence,
; internal derived features, and final diagnostic outputs.
; These templates allow the system to store information about certificates, the
; environment in which they are used, and the logical conclusions reached by the
; inference engine.

; ----------------------------------------------------------------------------
; STANDARD (CRISP) TEMPLATES
; ----------------------------------------------------------------------------

; The 'tls-error' template represents low-level error data typically captured
; from a client (like OpenSSL or a browser) or a server log.
; It bridges the gap between raw system errors and high-level diagnosis.
(deftemplate tls-error
  (slot error-code     (type SYMBOL))  ; The specific technical error string (e.g., CERT_HAS_EXPIRED).
  (slot error-message  (type STRING))  ; A human-readable description of the error for the user.
  (slot error-category (type SYMBOL))  ; Broad classification (e.g., certificate-invalid).
  (slot severity       (type SYMBOL))) ; Importance of the error (e.g., critical, warning).

; The 'certificate' template represents the core attributes of a
; Public Key Infrastructure (PKI) certificate. This information is
; used to verify validity windows, cryptographic strength, and ownership.
(deftemplate certificate
  (slot common-name         (type STRING))             ; The primary hostname assigned to the certificate.
  (multislot subject-alt-names (type STRING))          ; List of additional hostnames or IP addresses.
  (slot not-before          (type STRING))             ; The start of the certificate's validity period.
  (slot not-after           (type STRING))             ; The expiration date of the certificate.
  (slot signature-algorithm (type STRING))             ; The hash and encryption algorithm used.
  (slot key-size            (type INTEGER))            ; The bit-length of the public key.
  (slot issuer              (type STRING))             ; The Certificate Authority (CA) that signed this.
  (slot serial-number       (type STRING))             ; Unique identifier for the certificate.
  (slot is-self-signed      (type SYMBOL) (default no))) ; Indicates if the cert was signed by itself.

; The 'certificate-chain' template manages the hierarchical relationship
; between the server certificate, intermediate CAs, and the Root CA.
(deftemplate certificate-chain
  (slot chain-length         (type INTEGER))                      ; Total number of certificates in the path.
  (slot has-intermediate     (allowed-values yes no unknown))     ; Whether intermediate CA certs were sent.
  (slot root-trusted         (allowed-values yes no unknown))     ; Whether the root is in the trust store.
  (slot chain-complete       (allowed-values yes no unknown))     ; Final determination of trust path.
  (multislot missing-certificates (type STRING)))                 ; List of specific missing certificates.

; The 'environment' template captures the context of the connection attempt.
(deftemplate environment
  (slot client-os          (type STRING))              ; The operating system of the client.
  (slot server-type        (type STRING))              ; The web server software.
  (slot requested-hostname (type STRING))              ; The hostname the client tried to connect to.
  (slot sni-value          (type STRING))              ; The hostname value sent in the SNI TLS extension.
  (slot sni-sent           (allowed-values yes no unknown)) ; Whether the client initiated SNI.
  (slot current-timestamp  (type STRING)))             ; The current system time.

; The 'connection' template stores technical details of the TLS connection.
(deftemplate connection
  (slot protocol-version  (type STRING))               ; TLS/SSL version (e.g., "TLSv1.0", "TLSv1.3").
  (slot cipher-suite      (type STRING))               ; The active encryption suite.
  (slot ocsp-stapling     (allowed-values yes no unknown)) ; If the server sent OCSP status info.
  (slot hsts-enabled      (allowed-values yes no unknown)) ; If HTTP Strict Transport Security is active.
  (slot server-location   (type STRING) (default "external"))) ; "internal" or "external" network.

; The 'feature' template stores derived high-level logical facts extracted from
; raw templates above. This abstraction makes the rulebase more modular.
; NOTE: The 'cf' slot here stores Certainty Factors for probabilistic features,
; handled natively by FuzzyCLIPS via (assert ... CF x.x) syntax in rules.
(deftemplate feature
  (slot name  (type SYMBOL)) ; A logical label (e.g., 'is-expired', 'hostname-mismatch').
  (slot value (type SYMBOL)) ; The value of the feature (usually 'yes' or 'no').
  (slot cf    (type FLOAT) (range -1.0 1.0) (default 1.0))) ; Certainty Factor for this feature.

; The 'diagnosis' template provides the final conclusion of the system.
(deftemplate diagnosis
  (slot diagnosis-type   (type SYMBOL))                          ; Categorization of the root cause.
  (slot confidence       (allowed-values definite high medium possible)) ; Qualitative certainty.
  (slot confidence-score (type FLOAT))                           ; Quantitative score (0.0 to 1.0).
  (slot cf               (type FLOAT) (range -1.0 1.0) (default 0.0)) ; Certainty Factor.
  (slot description      (type STRING)))                         ; Detailed explanation of the problem.

; The 'recommendation' template offers actionable advice once a diagnosis is reached.
(deftemplate recommendation
  (slot action-description (type STRING))              ; High-level description of what needs to be done.
  (slot priority           (allowed-values immediate high medium low)) ; Urgency of the repair.
  (multislot steps         (type STRING)))             ; A sequential list of specific technical steps.

; The 'reasoning-trace' template stores the logical path the system took to
; reach a conclusion. This is critical for the "explainability" requirement.
(deftemplate reasoning-trace
  (slot rule-fired     (type SYMBOL))  ; The name of the rule that was triggered.
  (slot evidence-used  (type STRING))  ; A summary of the facts that satisfied the rule's conditions.
  (slot conclusion     (type STRING))) ; The logical deduction made by this rule.


; ----------------------------------------------------------------------------
; FUZZYCLIPS FUZZY TEMPLATES
; ----------------------------------------------------------------------------
; These replace the old 'fuzzy-input' and 'linguistic-variable' crisp templates.
; FuzzyCLIPS natively handles membership functions, fuzzification, and
; fuzzy pattern matching through these deftemplate declarations.

; 'DaysToExpiry' fuzzy variable: universe of discourse is 0 to 365 days.
; Linguistic terms model certificate urgency with overlapping membership functions
; to allow partial truth (e.g., 25 days is partially 'CriticallySoon' AND 'Soon').
(deftemplate DaysToExpiry
  0 365 days
  (
   (CriticallySoon (0 1) (10 1) (20 0))    ; Fully critical at 0-10 days, fades to 0 at 20.
   (Soon           (10 0) (30 1) (45 1) (60 0)) ; Ramps up from 10, fully soon 30-45, fades to 0 at 60.
   (Safe           (45 0) (90 1) (365 1))   ; Ramps from 0 at 45 days, fully safe from 90 onward.
  )
)

; 'KeySize' fuzzy variable: universe of discourse is 512 to 8192 bits.
; Linguistic terms capture the security strength of the public key.
(deftemplate KeySize
  512 8192 bits
  (
   (Weak     (512 1) (1024 1) (2048 0))  ; Fully weak up to 1024 bits, fades to 0 at 2048.
   (Standard (1024 0) (2048 1) (8192 1)) ; Ramps from 0 at 1024, fully standard from 2048 onward.
  )
)

; 'RiskLevel' fuzzy output variable: universe of discourse is 0.0 to 1.0 (normalized risk score).
; This is the fuzzy output asserted by fuzzy inference rules and optionally defuzzified.
(deftemplate RiskLevel
  0.0 1.0
  (
   (Low      (0.0 1) (0.2 1) (0.4 0))   ; Low risk: fully low from 0.0-0.2, fades to 0 at 0.4.
   (Medium   (0.2 0) (0.5 1) (0.7 0))   ; Medium risk: peaks at 0.5, symmetric triangle.
   (High     (0.6 0) (0.8 1) (0.9 1))   ; High risk: ramps from 0.6, fully high at 0.8-0.9.
   (Critical (0.85 0) (0.95 1) (1.0 1)) ; Critical risk: ramps from 0.85, fully critical at 0.95+.
  )
)
