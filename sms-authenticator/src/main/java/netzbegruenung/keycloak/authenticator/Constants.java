package netzbegruenung.keycloak.authenticator;

public class Constants {
    // SMS_LOGIN_TEMPLATE is the template used to render the SMS 2FA login page
    public static final String SMS_LOGIN_TEMPLATE = "login-sms.ftl";

    // MASKED_MFA_PHONE_NUMBER_COOKIE is the cookie name for the masked MFA phone number used on SMS 2FA forms
    public static final String MASKED_MFA_PHONE_NUMBER_COOKIE = "masked_mfa_phone";

    // SMS_COOLDOWN_MS is in milliseconds and is used to throttle SMS resend requests
	public static final long SMS_COOLDOWN_MS = 30_000L;

    // SMS_COOLDOWN_MS_KEY is the key for the SMS cooldown in milliseconds in the SMS authenticator config
    public static final String SMS_COOLDOWN_MS_KEY = "smsResendCooldownMs";

    // Private constructor to prevent instantiation
    private Constants() {}
}
