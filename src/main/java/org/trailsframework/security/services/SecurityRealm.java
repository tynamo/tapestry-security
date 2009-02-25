package org.trailsframework.security.services;

import java.util.Collection;
import java.util.HashSet;

import org.jsecurity.realm.Realm;

public class SecurityRealm extends HashSet<Realm> {
	private static final long serialVersionUID = 8173749883366301967L;

	public SecurityRealm(final Collection<Realm> realms) {
		super(realms);
	}

}
