package netzbegruenung.keycloak.authenticator.adapters;

import netzbegruenung.keycloak.authenticator.interfaces.UnifiedContext;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/*
 * Adapter for RequiredActionContext
 * 
 * This adapter provides a unified context for required action.
 * It is used to avoid code duplication and to make the code more readable.
 */
public class RequiredActionContextAdapter implements UnifiedContext {
    private final RequiredActionContext context;

    public RequiredActionContextAdapter(RequiredActionContext context) {
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
