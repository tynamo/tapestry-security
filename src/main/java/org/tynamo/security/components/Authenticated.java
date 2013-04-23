package org.tynamo.security.components;

import org.apache.tapestry5.corelib.base.AbstractConditional;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;

/**
 * Render body if subject is authenticated.
 *
 * @see SecurityService#isAuthenticated()
 */
public class Authenticated extends AbstractConditional {

	@Inject
	private SecurityService securityService;

	@Override
	protected boolean test() {
		return securityService.isAuthenticated();
	}
}
