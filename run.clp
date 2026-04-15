; ============================================================================
; RUN.CLP - Main Execution Script for TLS/PKI Expert System
; ============================================================================
; This script automates the loading of the Knowledge Base (K) and the
; User Interface (UI). It provides the user with instructions on how to
; interact with the system once loaded.
; NOTE: This file must be run inside FuzzyCLIPS (not standard CLIPS)
; because the factbase uses FuzzyCLIPS fuzzy deftemplate syntax.
; ============================================================================

; Clear any existing facts/rules from memory to ensure a clean state.
(clear)

; Load the Knowledge Base components (F and R).
(load "factbase.clp") ; Defines templates (Knowledge structure)
(load "rulebase.clp") ; Defines logic (Inference rules)

; Load the interaction layer.
(load "ui.clp")       ; Defines functions for UI and explainability

; Provide clear instructions to the user on how to run the expert system.
(printout t crlf "=========================================================" crlf)
(printout t "  TLS/PKI DIAGNOSIS EXPERT SYSTEM LOADED SUCCESSFULY" crlf)
(printout t "=========================================================" crlf)
(printout t "HOW TO RUN TEST CASES:" crlf)
(printout t "  1. Load a case: (batch \"cases/case_expired_cert.clp\")" crlf)
(printout t "  2. Run diagnosis: (run-diagnosis)" crlf)
(printout t crlf)
(printout t "HOW TO RUN INTERACTIVE MODE:" crlf)
(printout t "  - Call: (collect-and-run)" crlf)
(printout t "=========================================================" crlf crlf)
