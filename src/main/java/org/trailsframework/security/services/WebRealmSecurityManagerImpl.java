package org.trailsframework.security.services;

import java.util.Collection;

import org.jsecurity.realm.Realm;
import org.jsecurity.web.DefaultWebSecurityManager;

public class WebRealmSecurityManagerImpl extends DefaultWebSecurityManager {
	public WebRealmSecurityManagerImpl(final Collection<Realm> realms) {
		super(realms);
	}

}
