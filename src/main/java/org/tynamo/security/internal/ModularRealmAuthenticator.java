package org.tynamo.security.internal;

import org.apache.shiro.authc.AuthenticationListener;
import org.tynamo.security.Authenticator;

public class ModularRealmAuthenticator extends org.apache.shiro.authc.pam.ModularRealmAuthenticator implements Authenticator {
	@Override
	public void addAuthenticationListener(AuthenticationListener authenticationListener) {
		getAuthenticationListeners().add(authenticationListener);
	}
		
	@Override
	public void removeAuthenticationListener(AuthenticationListener authenticationListener) {
		getAuthenticationListeners().remove(authenticationListener);
	}
}
