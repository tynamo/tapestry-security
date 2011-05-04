package org.tynamo.security.services.impl;

import org.apache.tapestry5.services.HttpServletRequestHandler;

public class SecurityFilterChain {
	private String path;

	private HttpServletRequestHandler handler;

	public SecurityFilterChain(String path, HttpServletRequestHandler handler) {
		this.path = path;
		this.handler = handler;
	}

	public HttpServletRequestHandler getHandler() {
		return handler;
	}

	public String getPath() {
		return path;
	}
}
