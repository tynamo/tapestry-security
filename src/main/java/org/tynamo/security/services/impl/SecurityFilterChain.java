package org.tynamo.security.services.impl;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.slf4j.Logger;
import org.tynamo.security.shiro.AccessControlFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

public class SecurityFilterChain {

	/**
	 * Default PatternMatcher for backward compatibility
	 */
	@Deprecated
	private static final PatternMatcher defaultPatternMatcher = new AntPathMatcher();

	private String path;
	private HttpServletRequestHandler handler;
	private PatternMatcher patternMatcher;

	public SecurityFilterChain(String path, HttpServletRequestHandler handler, PatternMatcher patternMatcher) {
		this.path = path;
		this.handler = handler;
		this.patternMatcher = patternMatcher;
	}

	/**
	 * @deprecated in 0.4.5 Use {@link #SecurityFilterChain(String, org.apache.tapestry5.services.HttpServletRequestHandler, org.apache.shiro.util.PatternMatcher)} instead
	 */
	@Deprecated
	public SecurityFilterChain(String path, HttpServletRequestHandler handler) {
		this(path, handler, defaultPatternMatcher);
	}

	public HttpServletRequestHandler getHandler() {
		return handler;
	}

	public boolean matches(String requestURI) {
		return patternMatcher.matches(path, requestURI.toLowerCase());
	}

	public static class Builder {

		private PipelineBuilder pipelineBuilder;
		private String path;
		private List<HttpServletRequestFilter> filters = new ArrayList<HttpServletRequestFilter>();
		private Logger logger;
		private  PatternMatcher patternMatcher;

		public Builder(Logger logger, PipelineBuilder pipelineBuilder, String path, PatternMatcher patternMatcher) {
			this.logger = logger;
			this.pipelineBuilder = pipelineBuilder;
			this.path = path;
			this.patternMatcher = patternMatcher;
		}

		public Builder add(Class<HttpServletRequestFilter> filterType) {
			try {
				filters.add(filterType.newInstance());
			} catch (InstantiationException e) {
				throw new RuntimeException("Couldn't instantiate a filter while building a security chain for path '" + path + "': ", e);
			} catch (IllegalAccessException e) {
				throw new RuntimeException("Couldn't instantiate a filter while building a security chain for path '" + path + "': ", e);
			}
			return this;
		}

		public Builder add(Filter filter) {
			if (filter instanceof AccessControlFilter) add((AccessControlFilter) filter, null);
			else filters.add(new HttpServletRequestFilterWrapper(filter));
			return this;
		}

		public Builder add(AccessControlFilter filter, String config) {
			filter.addConfig(config);
			filters.add(new HttpServletRequestFilterWrapper(filter));
			return this;
		}

		public SecurityFilterChain build() {
			return new SecurityFilterChain(path, pipelineBuilder.build(logger, HttpServletRequestHandler.class, HttpServletRequestFilter.class, filters), patternMatcher);
		}
	}
}
