; ============================================================================
; UI.CLP - User Interface and Interaction Functions
; ============================================================================

; ============================================================================
; SECTION 1 — OUTPUT RULES (fire automatically during run)
; ============================================================================
; Salience -5  : section headers  (fire first within output phase)
; Salience -10 : per-fact printers (fire once per matching fact)
; Salience -20 : "none found" fallbacks (fire only if no facts matched)

(defrule print-diagnoses-header
  (declare (salience -5))
  (output-phase diagnoses)
  =>
  (printout t crlf "CURRENT DIAGNOSES:" crlf "==================" crlf))

(defrule print-recommendations-header
  (declare (salience -5))
  (output-phase recommendations)
  =>
  (printout t crlf "RECOMMENDATIONS:" crlf "=================" crlf))

(defrule print-reasoning-header
  (declare (salience -5))
  (output-phase reasoning)
  =>
  (printout t crlf "REASONING TRACE (EXPLAINABILITY):" crlf "=================================" crlf))

(defrule print-diagnosis
  (declare (salience -10))
  (output-phase diagnoses)
  (diagnosis
    (diagnosis-type ?t)
    (confidence ?c)
    (cf ?cf)
    (description ?d))
  =>
  (printout t "  [" ?t "]" crlf
            "    Confidence : " ?c crlf
            "    CF         : " ?cf crlf
            "    Description: " ?d crlf crlf))

(defrule print-recommendation
  (declare (salience -10))
  (output-phase recommendations)
  (recommendation
    (action-description ?a)
    (priority ?p)
    (steps $?steps))
  =>
  (printout t "  ACTION   : " ?a crlf
            "  Priority : " ?p crlf
            "  Steps    :" crlf)
  (progn$ (?s $?steps)
    (printout t "    - " ?s crlf))
  (printout t crlf))

(defrule print-reasoning-trace
  (declare (salience -10))
  (output-phase reasoning)
  (reasoning-trace
    (rule-fired ?r)
    (evidence-used ?e)
    (conclusion ?c))
  =>
  (printout t "  Rule Fired        : " ?r crlf
            "  Evidence Used     : " ?e crlf
            "  Conclusion Reached: " ?c crlf crlf))

(defrule print-no-diagnoses
  (declare (salience -20))
  (output-phase diagnoses)
  (not (diagnosis (diagnosis-type ?)))
  =>
  (printout t "  No diagnoses found." crlf crlf))

(defrule print-no-recommendations
  (declare (salience -20))
  (output-phase recommendations)
  (not (recommendation (action-description ?)))
  =>
  (printout t "  No recommendations found." crlf crlf))


; ============================================================================
; SECTION 2 — DISPLAY FUNCTION STUBS
; ============================================================================
; These keep backward compatibility with any script calling show-* directly.
; Actual output is produced by the print-* rules during (run).

(deffunction show-diagnoses ()
  (printout t "(Diagnoses printed by rules during (run). Call (run-diagnosis) to rerun.)" crlf))

(deffunction show-recommendations ()
  (printout t "(Recommendations printed by rules during (run). Call (run-diagnosis) to rerun.)" crlf))

(deffunction show-reasoning ()
  (printout t "(Reasoning trace printed by rules during (run). Call (run-diagnosis) to rerun.)" crlf))


; ============================================================================
; SECTION 3 — MAIN ENTRY POINTS
; ============================================================================

(deffunction run-diagnosis ()
  (printout t crlf
    "================================================================" crlf
    "  TLS/PKI CERTIFICATE DIAGNOSIS EXPERT SYSTEM (PROBABILISTIC)  " crlf
    "================================================================" crlf)
  ; Phase 1: Run all inference rules with NO output-phase facts asserted.
  ; This fires init-banner, feat-*, dx-*, fuzzy-*, boost-*, rec-* rules
  ; and populates diagnosis/recommendation/reasoning-trace facts cleanly.
  (run)
  ; Phase 2-4: Assert each output-phase fact individually and call (run)
  ; so only that section's print-* rules activate each time.
  (assert (output-phase diagnoses))
  (run)
  (assert (output-phase recommendations))
  (run)
  (assert (output-phase reasoning))
  (run)
  (printout t "================================================================" crlf
              "  Diagnosis complete." crlf
              "================================================================" crlf crlf))


; ============================================================================
; SECTION 4 — INTERACTIVE INPUT MODE
; ============================================================================

(deffunction yn->sym (?s)
  (bind ?x (lowcase ?s))
  (if (or (eq ?x "yes") (eq ?x "y")) then (return yes))
  (if (or (eq ?x "no")  (eq ?x "n")) then (return no))
  (return unknown))

(deffunction collect-user-input ()
  (printout t crlf "--- INTERACTIVE DATA COLLECTION ---" crlf)

  (printout t "Enter TLS Error Code (e.g. CERT_HAS_EXPIRED): ")
  (bind ?err (readline))

  (printout t "Enter Error Category (e.g. certificate-invalid): ")
  (bind ?cat (readline))

  (printout t "Enter Severity (critical/high/medium/low): ")
  (bind ?sev (readline))

  (printout t "What hostname did you try to connect to?: ")
  (bind ?host (readline))

  (printout t "What is the certificate's Common Name (CN)?: ")
  (bind ?cn (readline))

  (printout t "Enter Subject Alt Names (space separated): ")
  (bind ?sans (explode$ (readline)))

  (printout t "Certificate 'Not Before' date: ")
  (bind ?nb (readline))

  (printout t "Certificate 'Not After' date: ")
  (bind ?na (readline))

  (printout t "Signature Algorithm: ")
  (bind ?sig (readline))

  (printout t "Key size (e.g. 2048): ")
  (bind ?ks (read))

  (printout t "Is the cert self-signed? (y/n): ")
  (bind ?iss (yn->sym (readline)))

  (printout t "Is the intermediate cert present? (y/n): ")
  (bind ?hi (yn->sym (readline)))

  (printout t "Is the root trusted? (y/n): ")
  (bind ?rt (yn->sym (readline)))

  (printout t "Is the chain complete? (y/n): ")
  (bind ?cc (yn->sym (readline)))

  (printout t "Was SNI sent by the client? (y/n): ")
  (bind ?snis (yn->sym (readline)))

  (printout t "What was the SNI value?: ")
  (bind ?sniv (readline))

  (printout t "TLS Protocol Version (e.g. TLSv1.2): ")
  (bind ?prot (readline))

  (printout t "Cipher Suite (e.g. AES256-SHA): ")
  (bind ?ciph (readline))

  (printout t "Is OCSP stapling active? (y/n): ")
  (bind ?ocsp (yn->sym (readline)))

  (printout t "Is HSTS enabled? (y/n): ")
  (bind ?hsts (yn->sym (readline)))

  (printout t "Server location (internal/external): ")
  (bind ?loc (readline))

  (printout t "Current system timestamp: ")
  (bind ?now (readline))

  (printout t "--- FUZZY INPUTS (for possibilistic reasoning) ---" crlf)
  (printout t "How many days until certificate expiry?: ")
  (bind ?days (read))

  (printout t "Confirm Key Size again for fuzzification (e.g. 2048): ")
  (bind ?fks (read))

  (assert
    (tls-error
      (error-code      ?err)
      (error-message   "User provided")
      (error-category  ?cat)
      (severity        ?sev))
    (certificate
      (common-name         ?cn)
      (subject-alt-names   ?sans)
      (not-before          ?nb)
      (not-after           ?na)
      (signature-algorithm ?sig)
      (key-size            ?ks)
      (issuer              "Unknown")
      (serial-number       "N/A")
      (is-self-signed      ?iss))
    (certificate-chain
      (chain-length         0)
      (has-intermediate     ?hi)
      (root-trusted         ?rt)
      (chain-complete       ?cc)
      (missing-certificates))
    (environment
      (client-os           "Unknown")
      (server-type         "Unknown")
      (requested-hostname  ?host)
      (sni-value           ?sniv)
      (sni-sent            ?snis)
      (current-timestamp   ?now))
    (connection
      (protocol-version  ?prot)
      (cipher-suite      ?ciph)
      (ocsp-stapling     ?ocsp)
      (hsts-enabled      ?hsts)
      (server-location   ?loc)))

  (assert (DaysToExpiry (?days 1)))
  (assert (KeySize (?fks 1))))

(deffunction collect-and-run ()
  (reset)
  (collect-user-input)
  (run-diagnosis))
