package azkaban.security.aad;

import azkaban.Constants;
import azkaban.security.CredentialProvider;
import azkaban.utils.Props;
import com.microsoft.aad.adal4j.AuthenticationContext;
import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.log4j.Logger;


public class AADCredentialProvider implements CredentialProvider {
  private static final ExecutorService THREAD_POOL = Executors.newFixedThreadPool(2);

  private final Credentials _credsToUse;
  private final Props _props;
  private final Logger _logger;
  private final IAADCredentialsRetriever _credRetriever;
  private final AuthenticationContext _authContext;

  public AADCredentialProvider(Credentials credsToUse, Props props, Logger logger) {
    _credsToUse = credsToUse;
    _props = props;
    _logger = logger;

    _credRetriever = getTokenProvider(props, logger);
    _authContext = getAuthContext(props, logger);
  }


  @Override
  public void register(String user) {
    _logger.info("Adding AAD credentials for username " + user);
    AADCredentials creds = _credRetriever.getTokensForUser(user);
    if (creds == null) {
      _logger.warn("Could not retrieve any credentials. Job will likely fail later.");
      return;
    }
    String accessToken = creds.getAccessToken(_props, _authContext);

    _credsToUse.addSecretKey(getKeyForCreds(_props), accessToken.getBytes(StandardCharsets.UTF_8));
  }

  private static AuthenticationContext getAuthContext(Props props, Logger logger) {
    String authority = getAuthority(props);
    if (logger.isDebugEnabled()) {
      logger.debug("Initializing authContext with authority " + authority);
    }

    try {
      return new AuthenticationContext(authority, true, THREAD_POOL);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Error parsing authority", e);
    }
  }

  private static IAADCredentialsRetriever getTokenProvider(Props props, Logger logger) {
    String providerClass = props.getString(Constants.ConfigurationKeys.AZKABAN_AAD_CREDENTIAL_RETRIEVER_NAME);
    if (logger.isDebugEnabled()) {
      logger.debug("Loading tokenProvider class name " + providerClass);
    }

    try {
      Class<?> providerClz = Class.forName(providerClass);
      if (!IAADCredentialsRetriever.class.isAssignableFrom(providerClz)) {
        throw new IllegalArgumentException(providerClass + " is not a subclass of IAADCredentialsRetriever");
      }
      Constructor<?> ctor = providerClz.getConstructor(Props.class);

      return (IAADCredentialsRetriever) ctor.newInstance(props);
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException("Class " + providerClass + " not found.", e);
    } catch (NoSuchMethodException e) {
      throw new IllegalArgumentException("Found class " + providerClass + " but no suitable constructor (Props) found.",
          e);
    } catch (ReflectiveOperationException e) {
      throw new IllegalArgumentException("Error building credentials retriever", e);
    }
  }

  private static String getAuthority(Props props) {
    return props.getString(Constants.ConfigurationKeys.AZKABAN_AAD_AUTHORITY);
  }

  private static String getClientId(Props props) {
    return props.getString(Constants.ConfigurationKeys.AZKABAN_AAD_CLIENT_ID);
  }

  private static String getClientSecret(Props props) {
    return props.getString(Constants.ConfigurationKeys.AZKABAN_AAD_CLIENT_SECRET);
  }

  private static Text getKeyForCreds(Props props) {
    if (!props.containsKey(Constants.ConfigurationKeys.AZKABAN_AAD_KEY_FOR_CREDS)) {
      return new Text(Constants.ConfigurationKeys.AZAKABN_AAD_KEY_FOR_CREDS_DEFAULT);
    }

    return new Text(props.getString(Constants.ConfigurationKeys.AZKABAN_AAD_KEY_FOR_CREDS));
  }
}
