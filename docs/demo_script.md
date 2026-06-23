# RedSee Demo Script — Member 1 Speaking Parts

## Your Intro (30 seconds)
"RedSee is a dual-mode automated pentesting tool. We scan a target and generate
professional PDF reports — both from the attacker's perspective and the defender's."

## Red Team Demo Cue (say while Member 4 clicks Scan)
"While the scan runs across all four vulnerability modules — SQL injection, XSS,
IDOR, and broken authentication — everything is captured live by our Wazuh SIEM.
One scan, two reports."

## Red Report Generation (say while PDF downloads)
"Member 1's report engine takes those findings and sends them to DeepSeek V4 Pro.
The LLM generates a complete penetration test report with CVSS scores, proof of
concept for each vulnerability, and remediation steps — in about 30 seconds."

## Blue Report Transition (hand off to Member 4 or speak yourself)
"Now here's what makes RedSee unique — we flip to blue team mode. The same attacks
that just ran? Wazuh captured them as SIEM alerts. We feed those back in and get
a defender's report: attack timeline, missed detections, and copy-paste-ready
SIEM rules."

## Fallback Line (if anything fails)
"Let me show you a pre-generated report while we reset." [load findings_fallback.json]