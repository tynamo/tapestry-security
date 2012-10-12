package org.tynamo.security.testapp.services.ilac;

import org.tynamo.security.testapp.services.impl.Invoker;

public class GammaServiceImpl implements GammaService
{
	@Override
	public String invokeRequiresPermissionsILACSuccessIfArgumentAllows(Object object) {
		return Invoker.invoke(getClass(), object);
	}
	
	@Override
	public String invokeRequiresPermissionsILACSuccessWithoutArguments() {
		return Invoker.invoke(getClass());
	}
}