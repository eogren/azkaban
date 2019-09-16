package azkaban.security.aad;

public interface IAADCredentialsRetriever {
  public AADCredentials getTokensForUser(String username);
}
