package org.tynamo.security.components;

import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityService;

/**
 * Render a link to login page if subject is not authenticated, else render a link to logout.
 *
 */
public class LoginLink
{

	@Inject
	@Property
	private SecurityService securityService;

	@Inject
	private LoginContextService loginContextService;

	public String onActionFromTynamoLoginLink()
	{
		loginContextService.removeSavedRequest();
		return loginContextService.getLoginPage();
	}

	public void onActionFromTynamoLogoutLink()
	{
		securityService.getSubject().logout();
	}
}
