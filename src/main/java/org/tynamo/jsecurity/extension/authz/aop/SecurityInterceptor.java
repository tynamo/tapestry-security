package org.tynamo.jsecurity.extension.authz.aop;

public interface SecurityInterceptor {

	/**
	 * The method which is performed before the method that you want to check.
	 */
	public abstract void intercept();

}