package netzbegruenung.keycloak.authenticator;

public class Constants {
    // SMS_LOGIN_TEMPLATE is the template used to render the SMS 2FA login page
    public static final String SMS_LOGIN_TEMPLATE = "login-sms.ftl";

    // SMS_COOLDOWN_MS is in milliseconds and is used to throttle SMS resend requests
	public static final long SMS_COOLDOWN_MS = 30_000L;

    // Private constructor to prevent instantiation
    private Constants() {}
}
