package netzbegruenung.keycloak.authenticator;

public class Constants {
    public static final String SMS_LOGIN_TEMPLATE = "login-sms.ftl";
	public static final long SMS_COOLDOWN_MS = 30_000L;

    // Private constructor to prevent instantiation
    private Constants() {}
}
