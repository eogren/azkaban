package azkaban.security.aad;

import azkaban.utils.Props;
import com.microsoft.aad.adal4j.AuthenticationContext;
import java.util.Objects;


/**
 * Represents an OAuth application that has a clientId and clientSecret.
 */
public class AADClientSecret implements AADCredentials {
  private final String _clientId;
  private final String _clientSecret;

  public AADClientSecret(String clientId, String clientSecret) {
    _clientId = clientId;
    _clientSecret = clientSecret;
  }

  public String getClientId() {
    return _clientId;
  }

  public String getClientSecret() {
    return _clientSecret;
  }

  @Override
  public String getAccessToken(Props props, AuthenticationContext context) {
    throw new UnsupportedOperationException("unimpl so far");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AADClientSecret that = (AADClientSecret) o;
    return Objects.equals(_clientId, that._clientId) && Objects.equals(_clientSecret, that._clientSecret);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_clientId, _clientSecret);
  }
}
