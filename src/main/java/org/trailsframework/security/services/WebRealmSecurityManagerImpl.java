package org.trailsframework.security.services;

import java.util.Collection;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.DefaultWebSecurityManager;

/**
 * Needed just to point out to tapestry-ioc the right constructor to use (from the three available in
 * DefaultWebSecurityManager)
 */
public class WebRealmSecurityManagerImpl extends DefaultWebSecurityManager {
	public WebRealmSecurityManagerImpl(final Collection<Realm> realms) {
		super(realms);
	}

}
