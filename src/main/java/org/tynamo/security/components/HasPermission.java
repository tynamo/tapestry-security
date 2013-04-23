package org.tynamo.security.components;

import org.apache.tapestry5.annotations.Parameter;
import org.apache.tapestry5.corelib.base.AbstractConditional;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;

/**
 * @see SecurityService#hasPermission(String)
 */
public class HasPermission extends AbstractConditional {

	@Inject
	private SecurityService securityService;

	@Parameter(required = true, defaultPrefix="literal")
	private String permission;

	@Override
	protected boolean test() {
		return securityService.hasPermission(permission);
	}
}
