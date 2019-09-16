package azkaban.security.aad;

import azkaban.utils.Props;
import com.microsoft.aad.adal4j.AuthenticationContext;
import java.nio.charset.StandardCharsets;


public class MockAADCredentials implements AADCredentials {
  public static final String EXPECTED_ACCESS_TOKEN = "MyCoolAccessToken";
  public static final byte[] EXPECTED_ACCESS_TOKEN_BYTES = EXPECTED_ACCESS_TOKEN.getBytes(StandardCharsets.UTF_8);

  public MockAADCredentials(String username) {

  }

  @Override
  public String getAccessToken(Props props, AuthenticationContext context) {
    return EXPECTED_ACCESS_TOKEN;
  }
}
