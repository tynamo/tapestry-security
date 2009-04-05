package org.trailsframework.security.services;

public interface HttpServletRequestDecorator {
	public <T> T build(Class<T> serviceInterface, T delegate);

}
