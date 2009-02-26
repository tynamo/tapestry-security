package org.trailsframework.security.services;

import org.apache.tapestry5.services.HttpServletRequestHandler;

public class SecurityFilterChain {
	private String path;

	private HttpServletRequestHandler handler;

	public SecurityFilterChain(String path, HttpServletRequestHandler handler) {
		this.path = path;
		this.handler = handler;
	}

	protected HttpServletRequestHandler getHandler() {
		return handler;
	}

	protected String getPath() {
		return path;
	}
}
