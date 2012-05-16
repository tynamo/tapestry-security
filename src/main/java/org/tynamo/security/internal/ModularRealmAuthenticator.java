package org.tynamo.security.internal;

import org.apache.shiro.authc.AuthenticationListener;
import org.tynamo.security.Authenticator;
import org.tynamo.shiro.extension.authc.pam.FirstExceptionStrategy;

public class ModularRealmAuthenticator extends org.apache.shiro.authc.pam.ModularRealmAuthenticator implements Authenticator {

	public ModularRealmAuthenticator() {
		super();
		setAuthenticationStrategy(new FirstExceptionStrategy());
	}

	@Override
	public void addAuthenticationListener(AuthenticationListener authenticationListener) {
		getAuthenticationListeners().add(authenticationListener);
	}

	@Override
	public void removeAuthenticationListener(AuthenticationListener authenticationListener) {
		getAuthenticationListeners().remove(authenticationListener);
	}
}
