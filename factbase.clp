; ============================================================================
; FACTBASE.CLP - Knowledge Representation for TLS/PKI Diagnosis
; ============================================================================

; This file defines the "Factbase" component (F) of our expert system's knowledge (K = F U R). 
; It specifies the templates (data structures) used to represent observable evidence, internal derived features, and final diagnostic outputs.
; These templates allow the system to store information about certificates, the environment in which they are used, and the logical conclusions reached by the inference engine.

; The 'tls-error' template represents low-level error data typically captured from a client (like OpenSSL or a browser) or a server log.
; It bridges the gap between raw system errors and high-level diagnosis.


(deftemplate tls-error
  (slot error-code (type SYMBOL))       ; The specific technical error string (e.g., CERT_HAS_EXPIRED).
  (slot error-message (type STRING))   ; A human-readable description of the error for the user.
  (slot error-category (type SYMBOL))   ; Broad classification (e.g., certificate-invalid) to group related issues.
  (slot severity (type SYMBOL)))        ; Importance of the error (e.g., critical, warning).

; The 'certificate' template represents the core attributes of a 
; Public Key Infrastructure (PKI) certificate. This information is 
; used to verify validity windows, cryptographic strength, and ownership.
(deftemplate certificate
  (slot common-name (type STRING))              ; The primary hostname assigned to the certificate.
  (multislot subject-alt-names (type STRING))    ; List of additional hostnames or IP addresses the cert is valid for.
  (slot not-before (type STRING))               ; The start of the certificate's validity period.
  (slot not-after (type STRING))                ; The expiration date of the certificate.
  (slot signature-algorithm (type STRING))      ; The hash and encryption algorithm used for the signature (e.g., sha256WithRSAEncryption).
  (slot key-size (type INTEGER))                ; The bit-length of the public key (e.g., 2048, 4096).
  (slot issuer (type STRING))                   ; The Certificate Authority (CA) that signed this certificate.
  (slot serial-number (type STRING))            ; Unique identifier for the certificate within the CA's records.
  (slot is-self-signed (type SYMBOL) (default no))) ; Indicates if the cert was signed by itself (typical for root CAs).

; The 'certificate-chain' template manages the hierarchical relationship 
; between the server certificate, intermediate CAs, and the Root CA.
; A complete chain is essential for the client to establish trust.
(deftemplate certificate-chain
  (slot chain-length (type INTEGER))           ; Total number of certificates in the provided path.
  (slot has-intermediate (allowed-values yes no unknown)) ; Whether intermediate CA certs were sent by the server.
  (slot root-trusted (allowed-values yes no unknown))     ; Whether the root of the chain is in the client's trust store.
  (slot chain-complete (allowed-values yes no unknown))    ; Final determination if the trust path can be fully built.
  (multislot missing-certificates (type STRING)))          ; List of specific certificates identified as missing from the chain.


; The 'environment' template captures the context of the connection attempt.
; This allows the system to diagnose issues related to client-server 
; compatibility, such as Server Name Indication (SNI) mismatches.
(deftemplate environment
  (slot client-os (type STRING))               ; The operating system of the client (e.g., Windows, Linux).
  (slot server-type (type STRING))             ; The web server software (e.g., Nginx, Apache).
  (slot requested-hostname (type STRING))      ; The hostname the client actually tried to connect to.
  (slot sni-value (type STRING))               ; The hostname value sent in the SNI TLS extension.
  (slot sni-sent (allowed-values yes no unknown)) ; Whether the client initiated the SNI handshake.
  (slot current-timestamp (type STRING)))      ; The current system time, used for clock-skew and expiration checks.

; The 'connection' template stores technical details of the established or attempted TLS connection, allowing for security-focused diagnostics.
(deftemplate connection
  (slot protocol-version (type STRING))         ; TLS/SSL version (e.g., "TLSv1.0", "TLSv1.3").
  (slot cipher-suite (type STRING))             ; The active encryption suite (e.g., "AES256-SHA").
  (slot ocsp-stapling (allowed-values yes no unknown)) ; If the server sent OCSP status info.
  (slot hsts-enabled (allowed-values yes no unknown))  ; If HTTP Strict Transport Security is active.
  (slot server-location (type STRING) (default "external"))) ; "internal" or "external" network.

; The 'feature' template stores derived high-level logical facts extracted from raw templates above.  
; This abstraction makes the rulebase more modular and easier to read.
(deftemplate feature
  (slot name (type SYMBOL))   ; A logical label (e.g., 'is-expired', 'hostname-mismatch').
  (slot value (type SYMBOL))  ; The value of the feature (usually 'yes' or 'no').
  (slot cf (type FLOAT) (range -1.0 1.0) (default 1.0))) ; Certainty Factor for this feature.

; The 'diagnosis' template provides the final conclusion of the system.
; It maps technical features to a problem type and provides a confidence level to help the user prioritize their troubleshooting efforts.
(deftemplate diagnosis
  (slot diagnosis-type (type SYMBOL))           ; Categorization of the root cause (e.g., expired-certificate).
  (slot confidence (allowed-values definite high medium possible)) ; Qualitative assessment of the conclusion's certainty.
  (slot confidence-score (type FLOAT))          ; Quantitative score representing the system's certainty (0.0 to 1.0).
  (slot cf (type FLOAT) (range -1.0 1.0) (default 0.0)) ; Probabilistic Certainty Factor (-1.0 to 1.0).
  (slot description (type STRING)))             ; Detailed explanation of the problem for the user.

; The 'recommendation' template offers actionable advice once a diagnosis is reached. This directly assists the user in resolving the identified TLS/PKI misconfiguration.
(deftemplate recommendation
  (slot action-description (type STRING))       ; High-level description of what needs to be done.
  (slot priority (allowed-values immediate high medium low)) ; Urgency of the repair.
  (multislot steps (type STRING)))              ; A sequential list of specific technical steps to fix the issue.

; ---------------------------------------------------------
; FUZZYCLIPS: Fuzzy variables (native fuzzy facts)
; ---------------------------------------------------------
; In FuzzyCLIPS, fuzzy variables are defined using deftemplate with a universe
; of discourse and named linguistic terms (membership functions).
;
; These definitions replace the prior "manual fuzzification" approach.
; Crisp inputs should be asserted as singleton triples, e.g.:
;   (assert (DaysToExpiry (5 0) (5 1) (5 0)))
;   (assert (KeySize (1024 0) (1024 1) (1024 0)))

(deftemplate DaysToExpiry
  -365 365 days
  ((CriticallySoon (-365 1) (10 1) (11 0))
   (Soon (10 0) (11 1) (45 1) (46 0))
   (Safe (45 0) (46 1) (365 1))))

(deftemplate KeySize
  0 8192 bits
  ((Weak (0 1) (2047 1) (2048 0))
   (Standard (2047 0) (2048 1) (8192 1))))

; The 'linguistic-variable' template is kept for downstream fuzzy-derived
; summaries (e.g., RiskLevel term + degree) that are asserted by rules.
(deftemplate linguistic-variable
  (slot name (type SYMBOL))
  (slot term (type SYMBOL))
  (slot degree (type FLOAT) (range 0.0 1.0))) ; Membership degree (mu).

; The 'reasoning-trace' template stores the logical path the system took to reach a conclusion.
; This is critical for the "explainability" requirement of the project.
(deftemplate reasoning-trace
  (slot rule-fired (type SYMBOL))        ; The name of the rule that was triggered.
  (slot evidence-used (type STRING))     ; A summary of the facts that satisfied the rule's conditions.
  (slot conclusion (type STRING)))       ; The logical deduction made by this rule.

