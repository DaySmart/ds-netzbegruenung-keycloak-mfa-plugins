package netzbegruenung.keycloak.authenticator.helpers;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.Constants;
import netzbegruenung.keycloak.authenticator.adapters.AuthenticationFlowContextAdapter;
import netzbegruenung.keycloak.authenticator.adapters.RequiredActionContextAdapter;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import netzbegruenung.keycloak.authenticator.interfaces.UnifiedContext;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.util.Locale;
import java.util.Optional;

public class SmsHelper {

    /*
     * Send a new code and create the SMS_LOGIN_TEMPLATE form
     * 
     * @param context The unified context
     * @param config The authenticator config
     * @param session The keycloak session
     */
    public static void sendCode(
        UnifiedContext context,
        AuthenticatorConfigModel config,
        KeycloakSession session,
        UserModel user,
        String mobileNumber,
        RealmModel realm) throws IOException {

        if (config == null || config.getConfig() == null) {
            throw new IllegalStateException("SMS authenticator not configured");
        }

        String lengthStr = config.getConfig().get("length");
        if (lengthStr == null) throw new IllegalStateException("SMS length not configured");
        int length = Integer.parseInt(lengthStr);

        String ttlStr = config.getConfig().get("ttl");
        if (ttlStr == null) throw new IllegalStateException("TTL not configured");
        int ttl = Integer.parseInt(ttlStr);

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote("code", code);
        authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

        // Record when this code was sent
        authSession.setAuthNote("lastCodeSent", Long.toString(System.currentTimeMillis()));

        Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
        Locale locale = session.getContext().resolveLocale(user);
        String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
        String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

        SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

        context.challenge(context.form().setAttribute("realm", realm).createForm(Constants.SMS_LOGIN_TEMPLATE));
    }

    /**
     * Send a new code and create the SMS_LOGIN_TEMPLATE form for authentication flow
     * 
     * @param context The unified context
     * @param logger The logger
     */
    public static void authenticate(AuthenticationFlowContext context, Logger logger) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();
		Optional<CredentialModel> model = context.getUser().credentialManager().getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		String mobileNumber;

		try {
			mobileNumber = JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
		} catch (IOException e1) {
			logger.warn(e1.getMessage(), e1);
			return;
		}

		try {
            UnifiedContext unifiedContext = new AuthenticationFlowContextAdapter(context);
			SmsHelper.sendCode(unifiedContext, config, session, user, mobileNumber, realm);
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

    /**
     * Send a new code and create the SMS_LOGIN_TEMPLATE form for required action
     * 
     * @param context The unified context
     * @param logger The logger
     */
    public static void requiredActionChallenge(RequiredActionContext context, Logger logger) {
		try {
            AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
            KeycloakSession session = context.getSession();
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			String mobileNumber = authSession.getAuthNote("mobile_number");

			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

            UnifiedContext unifiedContext = new RequiredActionContextAdapter(context);
			SmsHelper.sendCode(unifiedContext, config, session, user, mobileNumber, realm);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

    /**
     * Handle resend if requested
     * 
     * @param context The unified context
     * @param logger The logger
     * @return true if resend was requested, false otherwise
     */
    public static boolean handleResendIfRequested(UnifiedContext context, Logger logger) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();

		// Check if user clicked the resend code link. If so, generate & send again (Stay in the same step
		if ("resend".equals(form.getFirst("resend"))) {
			logger.info("Resend form value received.");

            AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			long now = System.currentTimeMillis();
			long lastSentTime = Optional.ofNullable(authSession.getAuthNote("lastCodeSent"))
										.map(Long::parseLong).orElse(0L);
            long cooldownMs = Long.parseLong(
                config.getConfig().getOrDefault(
                    "smsResendCooldownMs",
                    String.valueOf(Constants.SMS_COOLDOWN_MS)
                    )
                );

            long timeDiff = now - lastSentTime;
			if (timeDiff < cooldownMs) {
				long secondsLeft = (cooldownMs - timeDiff) / 1000;
                secondsLeft = (secondsLeft == 0) ? 1 : secondsLeft;
                
				context.challenge(context.form()
								.setError("errorSmsCooldown", secondsLeft)
								.createForm(Constants.SMS_LOGIN_TEMPLATE));
				return true;          // Stay in the same auth step. Resend attempted, cooldown error shown
			}

            Object baseContext = context.getBaseContext();

            if (baseContext instanceof AuthenticationFlowContext) {
                authenticate((AuthenticationFlowContext) baseContext, logger);   // cool-down passed → send fresh code
            } else if (baseContext instanceof RequiredActionContext) {
                requiredActionChallenge((RequiredActionContext) baseContext, logger);   // cool-down passed → send fresh code
            }
			
			return true;
		}

        return false; // Resend not requested
    }
}
