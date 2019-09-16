package azkaban.security.aad;

import azkaban.utils.Props;
import com.microsoft.aad.adal4j.AuthenticationContext;


/**
 * Represents a type of Azure Active Directory credential (examples: refresh token, client id/client secret) that can
 * be turned into an OAuth access token.
 */
public interface AADCredentials {
  /**
   * Use these credentials to get an access token given the following authentication context.
   * @param props Job properties (will contain things such as Azkaban clientId)
   * @param context authContext to use to talk to AAD
   * @return
   */
  public String getAccessToken(Props props, AuthenticationContext context);
}
