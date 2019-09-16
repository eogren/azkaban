package azkaban.security.aad;

import azkaban.Constants;
import azkaban.utils.Props;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;


public class AADCredentialProviderTest {
  @Test
  public void testUsesDefaultKey() {
    Credentials creds = new Credentials();
    Logger logger = Logger.getLogger(AADCredentialProviderTest.class);
    Props props = getDefaultProps();

    AADCredentialProvider provider = new AADCredentialProvider(creds, props, logger);
    provider.register("myuser");

    Assert.assertArrayEquals(MockAADCredentials.EXPECTED_ACCESS_TOKEN_BYTES,
        creds.getSecretKey(new Text(Constants.ConfigurationKeys.AZAKABN_AAD_KEY_FOR_CREDS_DEFAULT)));
  }

  @Test
  public void testCanOverrideKey() {
    Credentials creds = new Credentials();
    Logger logger = Logger.getLogger(AADCredentialProviderTest.class);
    Props props = getDefaultProps();
    String myNewKey = "myNewKey";

    props.put(Constants.ConfigurationKeys.AZKABAN_AAD_KEY_FOR_CREDS, myNewKey);

    AADCredentialProvider provider = new AADCredentialProvider(creds, props, logger);
    provider.register("myuser");

    Assert.assertArrayEquals(MockAADCredentials.EXPECTED_ACCESS_TOKEN_BYTES,
        creds.getSecretKey(new Text(myNewKey)));
  }

  private static Props getDefaultProps() {
    Props props = new Props();
    props.put(Constants.ConfigurationKeys.AZKABAN_AAD_CREDENTIAL_RETRIEVER_NAME, MockCredentialRetriever.class.getName());
    props.put(Constants.ConfigurationKeys.AZKABAN_AAD_AUTHORITY, "https://localhost:88776/foo");
    return props;
  }
}
