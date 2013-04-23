package org.tynamo.security.components;

import org.apache.tapestry5.corelib.base.AbstractConditional;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;

/**
 * Render body if guest
 *
 * @see SecurityService#isGuest()
 */
public class Guest extends AbstractConditional {
	@Inject
	private SecurityService securityService;

	boolean beforeRenderBody() {
		return test();
	}

	@Override
	protected boolean test() {
		return securityService.isGuest();
	}
}
