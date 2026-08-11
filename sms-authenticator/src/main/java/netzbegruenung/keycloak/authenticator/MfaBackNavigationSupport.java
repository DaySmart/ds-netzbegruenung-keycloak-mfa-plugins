package netzbegruenung.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * "Try a different method" support for the MFA verify leaf screens: returns the user to
 * ds-mfa-method-selector's picker without re-running password validation.
 *
 * Duplicated per-module (matching this repo's MfaAttributeResolver convention) rather than
 * pulled in as a shared library dependency.
 */
public final class MfaBackNavigationSupport {

	private static final String TRY_DIFFERENT_METHOD_FORM_FIELD = "tryDifferentMethod";
	private static final String MFA_METHOD_SELECTOR_PROVIDER_ID = "ds-mfa-method-selector";

	private MfaBackNavigationSupport() {}

	public static boolean isTryDifferentMethodRequested(AuthenticationFlowContext context) {
		return "true".equals(context.getHttpRequest().getDecodedFormParameters().getFirst(TRY_DIFFERENT_METHOD_FORM_FIELD));
	}

	/**
	 * Controls whether the "Try a Different Method" link renders at all: with only one
	 * credential enrolled there's nothing else to switch to, so showing it is a dead-end click
	 * (harmless since the crash-prone case is already fixed at the source in
	 * ds-mfa-method-selector, but confusing UX). Deliberately simplified vs.
	 * ds-mfa-method-selector's own getAvailableMethods(): this is a display-only nicety, not a
	 * safety check, so it doesn't replicate the mfaOptions org/realm-attribute filtering — a
	 * user with 2 credentials but only 1 currently allowed by policy will still see the button,
	 * which at worst re-sends a code for the same method rather than causing any actual harm.
	 */
	public static boolean hasMultipleAvailableMethods(UserModel user) {
		if (user == null) {
			return false;
		}
		long count = Stream.of("otp", "mobile-number", "webauthn-passwordless")
				.filter(type -> user.credentialManager().isConfiguredFor(type))
				.count();
		return count > 1;
	}

	/**
	 * clearExecutionStatus() is called directly (not the full resetFlow()) so every other auth
	 * note (ds_selected_mfa_type included) survives untouched; whatever login step(s) run before
	 * ds-mfa-method-selector (password validation — could be ds-user-auth-validator, stock
	 * auth-username-password-form, or something else depending on the realm) have their status
	 * restored immediately after so they're never re-attempted. attempted() (not success()) marks
	 * only this leaf ATTEMPTED and its containing conditional subflow FAILED — neither is treated
	 * as "done" for flow completion (AuthenticationProcessor.isSuccessful() only accepts SUCCESS),
	 * so a later re-pick of the same method still requires a genuinely valid code. Using success()
	 * here instead would permanently satisfy the subflow and let a later re-pick of the same
	 * method skip verification entirely — verified via bytecode, not assumed.
	 */
	public static void backToMethodPicker(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		List<String> idsToPreserve = findExecutionIdsBeforeMethodSelector(context);

		var beforeClear = authSession.getExecutionStatus();
		var preserved = idsToPreserve.stream()
				.filter(beforeClear::containsKey)
				.collect(Collectors.toMap(id -> id, beforeClear::get));

		authSession.clearExecutionStatus();

		preserved.forEach(authSession::setExecutionStatus);

		context.attempted();
	}

	/**
	 * Identifies "the login step(s)" positionally — everything with a lower priority than
	 * ds-mfa-method-selector, within the SAME flow it lives in — rather than by a specific
	 * hardcoded provider ID (generalizes across realms regardless of which password
	 * authenticator they use). Walks UP the ancestry of the CURRENT execution (context.
	 * getExecution() -> getParentFlow() -> the execution embedding that flow -> its parent, and
	 * so on) rather than searching the whole realm for an authenticator matching
	 * ds-mfa-method-selector's provider ID: a realm can have more than one flow tree containing
	 * that provider ID (e.g. an old unbound copy left over from a rename), and a realm-wide
	 * search has no way to tell which one is actually live for this session — it can silently
	 * latch onto the wrong flow's priority numbers, preserving nothing relevant.
	 */
	private static List<String> findExecutionIdsBeforeMethodSelector(AuthenticationFlowContext context) {
		RealmModel realm = context.getRealm();
		String flowId = context.getExecution().getParentFlow();

		while (flowId != null) {
			List<AuthenticationExecutionModel> siblings = realm.getAuthenticationExecutionsStream(flowId)
					.collect(Collectors.toList());

			Optional<AuthenticationExecutionModel> methodSelector = siblings.stream()
					.filter(exec -> MFA_METHOD_SELECTOR_PROVIDER_ID.equals(exec.getAuthenticator()))
					.findFirst();

			if (methodSelector.isPresent()) {
				int selectorPriority = methodSelector.get().getPriority();
				return siblings.stream()
						.filter(exec -> exec.getPriority() < selectorPriority)
						.map(AuthenticationExecutionModel::getId)
						.collect(Collectors.toList());
			}

			String childFlowId = flowId;
			flowId = realm.getAuthenticationFlowsStream()
					.flatMap(flow -> realm.getAuthenticationExecutionsStream(flow.getId()))
					.filter(exec -> exec.isAuthenticatorFlow() && childFlowId.equals(exec.getFlowId()))
					.findFirst()
					.map(AuthenticationExecutionModel::getParentFlow)
					.orElse(null);
		}

		return List.of();
	}
}
