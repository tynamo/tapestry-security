package org.tynamo.security.components;

import org.apache.tapestry5.corelib.base.AbstractConditional;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;

/**
 * @see SecurityService#isUser()
 */
public class User extends AbstractConditional {

	@Inject
	private SecurityService securityService;

	@Override
	protected boolean test() {
		return securityService.isUser();
	}

}
