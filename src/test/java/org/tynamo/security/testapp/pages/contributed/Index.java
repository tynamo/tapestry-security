package org.tynamo.security.testapp.pages.contributed;

import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.annotations.InjectComponent;
import org.apache.tapestry5.corelib.components.Zone;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.testapp.pages.AccessiblePage;

public class Index extends AccessiblePage
{

	@Inject
	private HttpServletRequest request;

	public String getRemoteUser()
	{
		return request.getRemoteUser();
	}

	public String getUserPrincipal()
	{
		return request.getUserPrincipal().getName();
	}

	public boolean isUserInRole(String role)
	{
		return request.isUserInRole(role);
	}

	public boolean isUserInRoleUser()
	{
		return isUserInRole("user");
	}


	public boolean isUserInRoleManager()
	{
		return isUserInRole("manager");
	}
	
	@InjectComponent
	private Zone targetZone;

	public Object onActionFromAjaxLink() {
		return targetZone.getBody();
	}
}
