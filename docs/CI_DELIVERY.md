# CI evidence delivery
All test/build/lint/fuzz/race/security gates are mandatory. Artifact upload is a separate delivery step, allowed to fail with a visible job summary when GitHub storage quota is exhausted.
This does not skip tests, allow empty JUnit evidence, or accept missing APKs. Test logs remain in Actions. Private prerelease assets provide a separate reviewed delivery path.
Both SYN443 repositories are now public. Native AARs, APKs and sanitized reports
are uploaded only after their privacy and secret gates pass. Historical private
repository quota/protection failures are not current visibility evidence. No
billing change, unrelated artifact cleanup or main merge is implied by CI success.
Physical cellular/Doze/energy/native-host gates remain pending and cannot be inferred from CI.

