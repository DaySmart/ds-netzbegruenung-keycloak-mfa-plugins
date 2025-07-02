package netzbegruenung.keycloak.authenticator.interfaces;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

 /* 
 * Unified context for authentication flow and required action
 * 
 * This interface provides a unified context for authentication flow and required action.
 * It is used to avoid code duplication and to make the code more readable.
 */
public interface UnifiedContext {
    Object getBaseContext();
    MultivaluedMap<String, String> getFormParameters();
    AuthenticationSessionModel getAuthenticationSession();
    void challenge(Response response);
    LoginFormsProvider form();
    HttpRequest getHttpRequest();
    RealmModel getRealm();
}
