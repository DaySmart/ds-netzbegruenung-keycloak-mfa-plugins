package netzbegruenung.keycloak.authenticator.helpers;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.Constants;
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
    // Send a new code and create the TPL_CODE form
    public static void sendCode(
        AuthenticationFlowContext context,
        AuthenticatorConfigModel config,
        KeycloakSession session,
        UserModel user,
        String mobileNumber,
        RealmModel realm) throws IOException {

        int length = Integer.parseInt(config.getConfig().get("length"));
        int ttl = Integer.parseInt(config.getConfig().get("ttl"));

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

    // Send a new code and create the TPL_CODE form
    public static void sendCode(
        RequiredActionContext context,
        AuthenticatorConfigModel config,
        KeycloakSession session,
        UserModel user,
        String mobileNumber,
        RealmModel realm) throws IOException {

		int length = Integer.parseInt(config.getConfig().get("length"));
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

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
			SmsHelper.sendCode(context, config, session, user, mobileNumber, realm);
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

    public static void requiredActionChallenge(RequiredActionContext context, Logger logger) {
		try {
            AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
            KeycloakSession session = context.getSession();
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			String mobileNumber = authSession.getAuthNote("mobile_number");

			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			SmsHelper.sendCode(context, config, session, user, mobileNumber, realm);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

    public static boolean handleResendIfRequested(UnifiedContext context, Logger logger) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();

		// Check if user clicked the resend code link. If so, generate & send again (Stay in the same step
		if ("resend".equals(form.getFirst("resend"))) {
			logger.info("Resend form value received.");
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			long now = System.currentTimeMillis();
			long lastSentTime = Optional.ofNullable(authSession.getAuthNote("lastCodeSent"))
										.map(Long::parseLong).orElse(0L);

			if (now - lastSentTime < Constants.SMS_COOLDOWN_MS) {
				// Too soon – redisplay the same page with an error message
				context.challenge(context.form()
								.setError("error_sms_cooldown")
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
