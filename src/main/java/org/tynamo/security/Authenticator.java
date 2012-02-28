package org.tynamo.security;

import java.util.Collection;

import org.apache.shiro.realm.Realm;

/**
 * Replacement for Shiro's Authenticator interface while waiting for https://issues.apache.org/jira/browse/SHIRO-233 to be
 * satisfactorily resolved
 *
 */
public interface Authenticator extends org.apache.shiro.authc.Authenticator, AuthenticationListenerRegistrar {
  /**
   * Sets all realms used by this Authenticator, providing PAM (Pluggable Authentication Module) configuration. 
   * 
   * The operation is copied from org.apache.shiro.authc.pam.ModularRealmAuthenticator. Shiro's design is less than ideal for proxied 
   * interface-based systems because it internally relies on downcasting to specific types. Not all Authenticators need realms but 
   * ModularRealmAuthenticator has its own reference to the realms collection (separate from securityManager) so make the setter 
   * available here.
   *
   * @param realms the realms to consult during authentication attempts.
   */
  public void setRealms(Collection<Realm> realms);
}
