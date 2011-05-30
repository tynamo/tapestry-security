package org.tynamo.security.services.impl;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.slf4j.Logger;

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
	
	public static class Builder {
		PipelineBuilder pipelineBuilder; 
		String path;
		private List<HttpServletRequestFilter> filters = new ArrayList<HttpServletRequestFilter>();
		private Logger logger;
		
		public Builder (Logger logger, PipelineBuilder pipelineBuilder, String path) {
			this.logger = logger;
			this.pipelineBuilder = pipelineBuilder;
			this.path = path;
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
		
		@Deprecated
		public Builder add(Filter filter) {
			if (filter instanceof PathMatchingFilter) ((PathMatchingFilter) filter).processPathConfig(path, null);
			filters.add(new HttpServletRequestFilterWrapper(filter));
			return this;
		}
		
		@Deprecated
		public Builder add(PathMatchingFilter filter, String pathConfig) {
			filter.processPathConfig(path, pathConfig);
			filters.add(new HttpServletRequestFilterWrapper(filter));
			return this;
		}

		
		public SecurityFilterChain build() {
			return new SecurityFilterChain(path, pipelineBuilder.build(logger, HttpServletRequestHandler.class, HttpServletRequestFilter.class, filters));
		}
		
	}
}
