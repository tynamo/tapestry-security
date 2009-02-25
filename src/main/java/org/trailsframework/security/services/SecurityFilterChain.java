package org.trailsframework.security.services;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.apache.tapestry5.services.HttpServletRequestHandler;

public class SecurityFilterChain {
	private String path;

	private List<Filter> filters = new ArrayList<Filter>();

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

	/*
	protected List<Filter> getFilters() {
		return filters;
	}

	public SecurityFilterChain add(Filter filter) {
		return add(filter, null);
	}

	public SecurityFilterChain add(Filter filter, String filterConfig) {
		if (filter instanceof PathMatchingFilter) ((PathMatchingFilter) filter).processPathConfig(path, filterConfig);
		filters.add(filter);
		return this;
	}

	public boolean isEmpty() {
		return filters.size() == 0;
	}
	*/
}
