; ============================================================================
; UI.CLP - User Interface and Interaction Functions
; ============================================================================
; This file provides the "Interface" layer of the expert system.
; It contains functions for:
;   1. Displaying results (diagnoses and recommendations).
;   2. Capturing user input in an interactive session.
;   3. Showing the internal reasoning trace for explainability.
; ============================================================================

; Helper function to convert "yes/no/y/n" strings into CLIPS symbols.
(deffunction yn->sym (?s)
  (bind ?x (lowcase ?s))
  (if (or (eq ?x "yes") (eq ?x "y")) then (return yes))
  (if (or (eq ?x "no") (eq ?x "n")) then (return no))
  (return unknown))

; Iterates through all 'diagnosis' facts and prints them to the terminal.
; Helps the user understand the identified issues and the system's confidence.
(deffunction show-diagnoses ()
  (printout t crlf "CURRENT DIAGNOSES:" crlf "==================" crlf)
  (bind ?count 0)
  (do-for-all-facts ((?d diagnosis)) TRUE
    (bind ?count (+ ?count 1))
    (printout t ?count ". " ?d:diagnosis-type
              " (Confidence: " ?d:confidence
              ", CF: " ?d:cf ")" crlf
              "   " ?d:description crlf))
  (if (= ?count 0) then (printout t "No diagnoses found." crlf))
  (printout t crlf)
  (return ?count))

; Iterates through all 'recommendation' facts and prints actionable steps.
; Provides the "solution" part of the expert system's value proposition.
(deffunction show-recommendations ()
  (printout t crlf "RECOMMENDATIONS:" crlf "=================" crlf)
  (bind ?count 0)
  (do-for-all-facts ((?r recommendation)) TRUE
    (bind ?count (+ ?count 1))
    (printout t ?count ". " ?r:action-description
              " (Priority: " ?r:priority ")" crlf
              "   Steps:" crlf)
    (foreach ?step ?r:steps
      (printout t "   - " ?step crlf)))
  (if (= ?count 0) then (printout t "No recommendations found." crlf))
  (printout t crlf)
  (return ?count))

; Displays the 'reasoning-trace' facts created during rule execution.
; This satisfies the "Explainability" requirement by showing how logic was applied.
(deffunction show-reasoning ()
  (printout t crlf "REASONING TRACE (EXPLAINABILITY):" crlf "=================================" crlf)
  (do-for-all-facts ((?r reasoning-trace)) TRUE
    (printout t "Rule Fired: " ?r:rule-fired crlf
              "  Evidence Used: " ?r:evidence-used crlf
              "  Conclusion Reached: " ?r:conclusion crlf crlf)))

; The main entry point to execute reasoning and display all outputs.
(deffunction run-diagnosis ()
  (printout t crlf
            "================================================================" crlf
            "  TLS/PKI CERTIFICATE DIAGNOSIS EXPERT SYSTEM (PROBABILISTIC)  " crlf
            "================================================================" crlf)
  (run)
  (show-diagnoses)
  (show-recommendations)
  (printout t "To view reasoning trace, call: (show-reasoning)" crlf crlf))

; ---------------------------------------------------------
; INTERACTIVE INPUT MODE
; ---------------------------------------------------------
; Prompts the user for technical details and asserts them as facts.
; This allows a human user to use the system without writing code.
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

  ;; Assert the base facts into the Factbase (F)
  (assert
    (tls-error (error-code ?err) (error-message "User provided") (error-category ?cat) (severity ?sev))
    (certificate
      (common-name ?cn)
      (subject-alt-names ?sans)
      (not-before ?nb)
      (not-after ?na)
      (signature-algorithm ?sig)
      (key-size ?ks)
      (issuer "Unknown")
      (serial-number "N/A")
      (is-self-signed ?iss))
    (certificate-chain
      (chain-length 0)
      (has-intermediate ?hi)
      (root-trusted ?rt)
      (chain-complete ?cc)
      (missing-certificates))
    (environment
      (client-os "Unknown")
      (server-type "Unknown")
      (requested-hostname ?host)
      (sni-value ?sniv)
      (sni-sent ?snis)
      (current-timestamp ?now))
    (connection
      (protocol-version ?prot)
      (cipher-suite ?ciph)
      (ocsp-stapling ?ocsp)
      (hsts-enabled ?hsts)
      (server-location ?loc))
    (fuzzy-input (name DaysToExpiry) (value (float ?days)))
    (fuzzy-input (name KeySize) (value (float ?fks)))))

; Combines input collection and diagnosis into a single command for the user.
(deffunction collect-and-run ()
  (reset)
  (collect-user-input)
  (run-diagnosis))
