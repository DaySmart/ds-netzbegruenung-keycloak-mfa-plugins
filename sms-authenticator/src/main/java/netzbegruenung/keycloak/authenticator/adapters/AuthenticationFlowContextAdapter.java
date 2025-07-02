package netzbegruenung.keycloak.authenticator.adapters;

import netzbegruenung.keycloak.authenticator.interfaces.UnifiedContext;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/*
 * Adapter for AuthenticationFlowContext
 * 
 * This adapter provides a unified context for authentication flow.
 * It is used to avoid code duplication and to make the code more readable.
 */
public class AuthenticationFlowContextAdapter implements UnifiedContext {
    private final AuthenticationFlowContext context;

    public AuthenticationFlowContextAdapter(AuthenticationFlowContext context) {
        this.context = context;
    }

    public Object getBaseContext() {
        return context;
    }

    public MultivaluedMap<String, String> getFormParameters() {
        return context.getHttpRequest().getDecodedFormParameters();
    }

    public AuthenticationSessionModel getAuthenticationSession() {
        return context.getAuthenticationSession();
    }

    public void challenge(Response response) {
        context.challenge(response);
    }

    public LoginFormsProvider form() {
        return context.form();
    }

    public HttpRequest getHttpRequest() {
        return context.getHttpRequest();
    }

    public RealmModel getRealm() {
        return context.getRealm();
    }
}
