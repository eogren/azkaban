package azkaban.security.aad;

import azkaban.utils.Props;
import org.junit.Assert;
import org.junit.Test;


public class CredentialsRetrieverFromPropsTest {
  @Test
  public void testCredsFromProps() {
    Props props = new Props();

    props.put("azkaban.aad.credentials.user1.client_id", "5555");
    props.put("azkaban.aad.credentials.user1.client_secret", "6666");
    props.put("azkaban.aad.credentials.user2.client_id", "6666");
    props.put("azkaban.aad.credentials.user2.client_secret", "7777");

    CredentialsRetrieverFromProps retriever = new CredentialsRetrieverFromProps(props);
    Assert.assertEquals(
        new AADClientSecret("5555", "6666"),
        retriever.getTokensForUser("user1")
    );
    Assert.assertEquals(
        new AADClientSecret("6666", "7777"),
        retriever.getTokensForUser("user2")
    );
  }
}
