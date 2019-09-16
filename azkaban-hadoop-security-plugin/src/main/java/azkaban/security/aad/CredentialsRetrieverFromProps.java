package azkaban.security.aad;

import azkaban.utils.Props;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;


public class CredentialsRetrieverFromProps implements IAADCredentialsRetriever {
  private static Logger LOG = Logger.getLogger(CredentialsRetrieverFromProps.class);
  public static String PROPS_PREFIX = "azkaban.aad.credentials.";

  private Map<String, AADCredentials> _creds;

  public CredentialsRetrieverFromProps(Props props) {
    _creds = new HashMap<>();

    /* Extract properties:
        azkaban.aad.credentials.eogren.client_id -> 1234
        azkaban.aad.credentials.eogren.client_secret -> 5678
        azkaban.aad.credentials.foo.refresh_token -> 9999

        should reduce down to two AADCredentials entries
     */
    Map<String, String> matchingProps = props.getMapByPrefix(PROPS_PREFIX);
    for (Map.Entry<String, String> entry : matchingProps.entrySet()) {
      String[] substrings = entry.getKey().split("\\.", 2);
      String user = substrings[0];
      String field = substrings[1];

      if (field.equals("client_id")) {
        LOG.info("Adding AADCredential for user " + user + ", client_id " + entry.getValue());
        String clientSecret = matchingProps.get(user + ".client_secret");
        if (clientSecret == null) {
          LOG.error("No client secret found! Ignoring");
          continue;
        }

        _creds.put(user, new AADClientSecret(entry.getValue(), clientSecret));
      } else if (field.equals("client_secret")) {
        LOG.debug("Ignoring client_secret field");
      } else {
        LOG.info("Ignoring unknown field type " + field);
      }
    }
  }

  @Override
  public AADCredentials getTokensForUser(String username) {
    return _creds.get(username);
  }
}
