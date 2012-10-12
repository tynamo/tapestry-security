package org.tynamo.security.testapp.services.ilac;

import org.apache.shiro.authz.annotation.RequiresPermissions;

public interface GammaService
{
	@RequiresPermissions("ilac:action1")
	String invokeRequiresPermissionsILACSuccessWithoutArguments();
	
	@RequiresPermissions("ilac:action2")
	String invokeRequiresPermissionsILACSuccessIfArgumentAllows(Object object);

}