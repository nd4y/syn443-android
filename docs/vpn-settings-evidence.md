# Owned VPN Settings failure evidence

Source8ff3039 run44129925465 failed the retained API37 Always-on scenario.
The final hierarchy contained only an Android ANR dialog, no owned Settings row
or gear, and one focus classified as foreign ANR. Its owner correlation was
unknown. The controller still reported Online with its required health check
passing. All430 instrumentation outcomes passed; the external Always-on case
did not. This is distinct from the earlier controller-death TCP timeout.

The navigation helper correctly refused to dismiss an unknown dialog or restart
a foreign process. No selector defect, Settings-specific ANR or application ANR
has been established. Increasing waits, skipping the actual system test or
restarting another application would not explain this observation.

The following evidence-only revision preserves the original navigation,
package/row/gear checks, protected-keyguard refusal,20s window and single
confirmed Settings-ANR restart. It classifies bytes already returned by the
existing activity launch, without echoing them. On failure a fresh optional
collector reports finite correlation stage/reason/trust and observed counts
capped at2; unobserved counts stay null. Existing diagnostic helpers still
return exactly category/correlated by default. No additional ADB commands,
logcat range or recovery authority is introduced. The existing seven-command,
eight-second owner-observation bound remains.

Six synthetic helper cases run in the existing Actions documents job. They
cover compatibility, each stop stage, bounds/privacy, existing command/deadline
limits, fresh failure evidence and unchanged successful owned navigation.
Exact-source/full-main acceptance is separate. A later passing test does not
establish the original ANR owner or cause, or physical phone stability.
