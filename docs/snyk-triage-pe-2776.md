# Snyk triage: PE-2776

Scan date: 2026-10-16. Tools: `snyk test --all-projects` (SCA) and `snyk code test`. No IaC or container scans, because the repo has no Terraform, k8s manifests or Dockerfiles.

This is the "so nobody has to re-investigate this from scratch" doc. Short version: almost every finding was one old Keycloak version, so the fix was mostly one number.

## Follow-up: Keycloak 26.8.1 (2026-10-19)

Passport is moving to Keycloak **26.8.1**, so the four POMs now target 26.8.1 instead of 26.7.5 (project version and `keycloak.version`). Everything below this section is the 2026-10-16 write-up and is kept for history. **The numbers and the "Still open" list in this section replace the older ones.**

**Rescan on 26.8.1** (`snyk test --all-projects`, unique issue IDs): **0 critical / 9 high / 6 medium / 1 low**, down from 1 / 15 / 13 / 2. The one remaining critical (`httpclient5`) no longer shows up. The 26.8.0 findings in "Still open" below are gone.

What's left:

| Issue | Where | Status |
|---|---|---|
| CVE-2026-15943 (IdP client secret reuse) | `keycloak-services` | **Snyk is wrong.** The 26.8.1 release notes list it as fixed, but Snyk's data hasn't caught up. |
| CVE-2026-18569 (unsigned backchannel logout tokens) | `keycloak-services` | **Snyk is wrong.** Fixed in 26.8.1 per the release notes. |
| CVE-2026-18967 (SAML `OneTimeUse` replay, IdP-initiated flow) | `keycloak-services`, `keycloak-saml-core` | **Really unfixed.** Only matters if a realm has a SAML identity provider with IdP-initiated SSO. These plugins don't touch SAML. |
| `vertx-core`, `vertx-web` 4.5.34 | Keycloak runtime | Fix is 4.5.35. Ships with Keycloak. |
| `guava` 33.6.0-jre, `postgresql` 42.7.13 | Keycloak runtime | Fixes are 33.7.2-jre and 42.7.14. |
| `mysql-connector-j`, `jaxb-core`, `mariadb-java-client`, `h2`, `lit-element-state` | Keycloak runtime | No fix published. |
| `hibernate-validator`, `jakarta.validation-api` | Keycloak runtime | Only pre-release fixes. |

**How this was verified (much more than last time).** The old safety net was "the build passes". For the 26.8.1 bump we did more:

- `mvn clean verify` passes on JDK 21, all three modules.
- **Binary-compatibility scan.** We pulled every `org.keycloak` method the three built jars call (126 in `app-authenticator`, 91 in `sms-authenticator`, 49 in `enforce-mfa`) and checked each against the real 26.8.1 libraries. None are missing. This is the check that would have caught the `Cors.allowedOrigins` rename in 26.6.3 that broke the magic-link jar in Passport. These plugins don't use `Cors`.
- **Booted in a real Keycloak 26.8.1** against Postgres. All 13 providers register (authenticators, required actions, credential providers, action-token handlers, the JPA entity provider and the REST resources). Liquibase runs `challenge-changelog.xml` and creates `APP_AUTH_CHALLENGE`, and Hibernate maps the `Challenge` entity with no errors. The REST endpoints answer with 400 and 401, not 500. The SMS phone-number page (`mobile_number_form.ftl`) renders for a user with the `mobile_number_config` required action.

**Not tested:** sending an SMS (no gateway in the test), the `app-authenticator` device-registration and push flow, Firebase, and the `enforce-mfa` page when it is laid out as the README describes.

**Breaking changes we checked for** (from the Keycloak 26.3.1 to 26.8.1 upgrade guides, plus the code scan):

| Change | Affects these plugins? |
|---|---|
| `Cors.allowedOrigins` renamed in 26.6.3 (private SPI, undocumented in the upgrade guide) | No. No use of `Cors`, and the scan found no missing methods. |
| 26.8.0 Vert.x HTTP client bridge for `getHttpClient()` | No. `ApiSmsService` uses `java.net.http.HttpClient`, not Keycloak's. |
| 26.8.0 JPA persistence unit rename (`keycloak-default` to `<default>`) | No. We don't reference the unit name, and the entity provider boots fine. |
| 26.6.3 / 26.7.0 "extensions must not restart a transaction" | No. No transaction calls in the sources. |
| `UserSessionProvider` (26.6.0), `UserCredentialManager` (26.5.0) API changes | No uses. |
| Email no longer marked verified by non-verification flows (26.8.0) | No uses of `setEmailVerified`. |
| Login-page theme changes | The bundled templates only use `registrationLayout`. No `field.*` macros. |

**One pre-existing bug we found (not caused by 26.8.1, not fixed).** `EnforceMfaAuthenticator` has an error branch for "no 2FA methods available" that renders `enforce-mfa.ftl` without setting `isSetupOptional`. The template reads it with `<#if isSetupOptional = true>`, so FreeMarker throws and the user gets a 500 instead of the intended "illegal state" message. It only fires when `enforce-mfa` is placed in a flow that doesn't match the README layout, and it behaves the same on 26.7.5. Easy fix: set the attribute in the error branch too, or use `isSetupOptional!false` in the template.

**Passport consumes the built jar, so there is one manual step left.** The legacy Passport image copies a prebuilt `netzbegruenung.sms-authenticator-*.jar` that is committed in the Passport repo (`extensions/ds-custom/sms-authenticator/`, currently the `v26.6.1` build). The new build is `sms-authenticator/target/netzbegruenung.sms-authenticator-v26.8.1.jar`. It needs to replace that file over there.

## Before / after (2026-10-16, Keycloak 26.7.5)

Unique issue IDs, not per-module counts. The three Maven modules share the same tree, so raw counts look about 3x worse than reality.

|          | Before | After |
|----------|--------|-------|
| Critical | 15     | 1     |
| High     | 126    | 15    |
| Medium   | 121    | 13    |
| Low      | 8      | 2     |
| Snyk Code | 1 warning | 1 warning (false positive, see below) |

npm (`app-authenticator-cli`) went from 46 findings to 0.

## What changed

**Keycloak 26.6.1 to 26.7.5** (all four POMs, including the project version and `keycloak.version`). 26.7.5 was the version Passport targeted at the time, so we stayed matched to it instead of chasing the newest release (it has since moved to 26.8.1, see above). This drove about 120 of the high/critical findings.

**`firebase-admin` 9.4.3 to 9.11.0** in `app-authenticator`. The only call site is `FirebaseMessaging.send()` in `FcmMessagingService`, so the API surface we touch is tiny.

**npm CLI:**
- `axios` floor raised to `^1.15.2` (locked at 1.20.0). This cleared the criticals and most of the 38 axios issues.
- `uuid` `^9.0.1` to `^11.1.1`. We only call `v4()`, same import, same behavior.
- In-range `npm update` for the transitives (`lodash`, `tmp`, `follow-redirects`, `form-data`).

How it was verified: Maven `clean package` passes on JDK 21. The CLI got a syntax check, `--help`, and an import check of every dependency. **That's the whole safety net.** There are no unit tests in this repo, and I haven't run any of this against a live Keycloak.

## Gotchas

- **The Keycloak deps are `provided`.** Bumping the POM mostly keeps the build honest. The real exposure is whichever Keycloak server you deploy these jars into, so the server needs to be on the same version as the POMs (26.8.1 now).
- **`quarkus.version` is out of sync and was before this change.** The root POM pins `3.15.3.1`, the comment says "keep in sync with the version used by keycloak", Keycloak 26.7.5 used 3.33.4, and Keycloak 26.8.1 uses 3.40.1. It only affects the IDE launcher and the quarkus build goal, and the build passes, so I left it alone. Worth a cleanup someday.
- **`firebase-admin` isn't shaded into the `app-authenticator` jar.** The built jar has zero firebase classes, and the module has no shade plugin (only `sms-authenticator` does, for libphonenumber). So I can't tell from this repo how `firebase-admin` reaches the Keycloak runtime. If nothing provides it, push notifications would throw `NoClassDefFoundError`. I did not change packaging. Someone who knows how this gets deployed should confirm.
- **Don't swap package versions inside `app-authenticator-cli/package-lock.json` by hand.** Use `npm update` so the tree stays consistent.

## Still open (as of 2026-10-16, superseded by the 26.8.1 follow-up above)

Grouped by cause, 31 unique issues across the Maven modules.

**Fixed only in Keycloak 26.8.0 (newer than Passport's 26.7.5).** `keycloak-services` (5 issues), `keycloak-saml-core` (2) and `keycloak-authz-policy-common` (1). These clear when Passport moves to 26.8.x, so bump both together. I didn't go ahead of Passport.

**Transitive from the Keycloak runtime, newer fix exists.** `vertx-core` and `vertx-web` 4.5.34 (fix 4.5.35), `parsson` 1.1.7 (1.1.8), `postgresql` 42.7.13 (42.7.14). These ship with Keycloak, so they're fixed by a Keycloak release that picks them up, not by us.

**No fix published.** `mysql-connector-j` 9.6.0, `jaxb-core` 4.0.8, `mariadb-java-client` 3.5.9, `h2` 2.4.240, `lit-element-state` 1.7.0.

**Transitive from `firebase-admin` 9.11.0** (the one remaining critical lives here). `httpclient5` 5.5.2 is the critical (certificate validation, fixed in 5.6.4). Also `httpcore5-h2` 5.3.6, `guava` 33.5.0-jre (fix 33.7.2-jre) and `opentelemetry-api` 1.57.0 (fix 1.62.0). I could pin these with `dependencyManagement` in `app-authenticator/pom.xml`. I held back because there are no tests, the packaging question above is unresolved, and overriding Google's HTTP stack blind felt like the wrong risk. It needs a decision from you.

**Other.** `hibernate-validator` and `jakarta.validation-api` have only pre-release fixes.

## False positive: Snyk Code

**`javascript/JwtDecodeMethod` at `app-authenticator-cli/authenticator.js:67`**

Snyk Code doesn't honor inline suppressions, so this keeps showing up until it's ignored in the Snyk UI. Paste-ready justification:

> False positive. `jose.decodeJwt` reads the `sub` claim from an action-token URL that the person running this CLI pastes in themselves. The CLI has no key to verify it with, and Keycloak verifies the token server-side when the setup request is made. The claim is only used as a user ID in that request. The only party who can supply a forged token is the person running the tool against their own account, so there's no trust boundary being crossed.
