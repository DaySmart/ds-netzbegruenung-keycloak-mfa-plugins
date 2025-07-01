package netzbegruenung.keycloak.authenticator.interfaces;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.http.HttpRequest;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public interface UnifiedContext {
    Object getBaseContext();
    MultivaluedMap<String, String> getFormParameters();
    AuthenticationSessionModel getAuthenticationSession();
    void challenge(Response response);
    LoginFormsProvider form();
    HttpRequest getHttpRequest();
}
