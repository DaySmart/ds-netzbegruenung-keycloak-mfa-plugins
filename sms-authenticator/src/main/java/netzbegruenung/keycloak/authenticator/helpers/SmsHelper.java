package netzbegruenung.keycloak.authenticator.helpers;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.Constants;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

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

        context.challenge(context.form().setAttribute("realm", realm).createForm(Constants.TPL_CODE));
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

        context.challenge(context.form().setAttribute("realm", realm).createForm(Constants.TPL_CODE));
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
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();
			KeycloakSession session = context.getSession();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
            // Kevin Kamrowski - this TODO above was added by the original author of this SPI.
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			SmsHelper.sendCode(context, config, session, user, mobileNumber, realm);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}
}
