package azkaban.security.aad;

import azkaban.utils.Props;
import org.apache.log4j.Logger;


public class MockCredentialRetriever implements IAADCredentialsRetriever {
  public MockCredentialRetriever(Props prop) {

  }

  @Override
  public AADCredentials getTokensForUser(String username) {
    if (username.equals("myuser")) {
      return new MockAADCredentials(username);
    }

    throw new IllegalArgumentException("only myuser is supported");
  }
}
