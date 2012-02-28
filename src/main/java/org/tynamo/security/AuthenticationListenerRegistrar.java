package org.tynamo.security;

import org.apache.shiro.authc.AuthenticationListener;

public interface AuthenticationListenerRegistrar {
	public void addAuthenticationListener(AuthenticationListener authenticationListener);
	public void removeAuthenticationListener(AuthenticationListener authenticationListener);

}
