package org.trailsframework.security.services;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.jsecurity.web.filter.PathMatchingFilter;

public class SecurityFilterChain {
	private String path;

	private List<Filter> filters = new ArrayList<Filter>();

	public SecurityFilterChain(String path) {
		this.path = path;
	}

	public static SecurityFilterChain createChainForPath(String path) {
		return new SecurityFilterChain(path);
	}

	protected String getPath() {
		return path;
	}

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
}
