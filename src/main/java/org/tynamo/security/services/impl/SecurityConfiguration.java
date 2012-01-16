package org.tynamo.security.services.impl;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.tapestry5.services.ApplicationGlobals;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.tynamo.security.services.PageService;

public class SecurityConfiguration implements HttpServletRequestFilter {
	private SecurityManager securityManager;
	private final ServletContext servletContext;
	private final PageService pageService;
	

	private Map<String, SecurityFilterChain> chainMap = new LinkedHashMap<String, SecurityFilterChain>();

	// FIXME make configurable
	// private PatternMatcher pathMatcher = new AntPathMatcher();
	private PatternMatcher pathMatcher = new AntPathMatcher() {
    @Override
		public boolean matches(String pattern, String source) {
    	return super.matches(pattern, source.toLowerCase());
    }
	};

	public SecurityConfiguration(ApplicationGlobals applicationGlobals, final WebSecurityManager securityManager, PageService pageService, final Collection<SecurityFilterChain> chains) {
		this.securityManager = securityManager;
		this.pageService = pageService;
		servletContext = applicationGlobals.getServletContext();
		// The order of securityFilterChains is meaningful, so we need to construct the map ourselves rather
		// than simply use MappedConfiguration
		for (SecurityFilterChain chain : chains) {
			chainMap.put(chain.getPath(), chain);
		}
	}

	private static final class HandlerFilterChain implements FilterChain {
		private HttpServletRequestHandler handler;

		private List<Filter> filters;

		private int index = 0;

		HandlerFilterChain(final HttpServletRequestHandler handler, final List<Filter> filters) {
			this.handler = handler;
			this.filters = filters;
			this.index = 0;
		}

		public void doFilter(final ServletRequest request, final ServletResponse response) throws IOException, ServletException {
			if (this.filters == null || this.filters.size() == this.index) handler.service((HttpServletRequest) request,
					(HttpServletResponse) response);
			else this.filters.get(this.index++).doFilter(request, response, this);
		}

	}

	public boolean service(final HttpServletRequest originalRequest, final HttpServletResponse response, final HttpServletRequestHandler handler)
			throws IOException {
		// TODO consider whether this guard is necessary at all? I think possibly if container forwards the request internally
		// or, more generically, if the same thread/container-level filter mapping handles the request twice 
		if (originalRequest instanceof ShiroHttpServletRequest) return handler.service(originalRequest, response);

		final HttpServletRequest request = new ShiroHttpServletRequest(originalRequest, servletContext, false);

		String requestURI = pageService.getLocalelessPathWithinApplication();

		SecurityFilterChain configureChain = null;
		for (String path : chainMap.keySet()) {
			// If the path does match, then pass on to the subclass implementation for specific checks:
			if (pathMatcher.matches(path, requestURI)) {
				configureChain = chainMap.get(path);
				break;
			}
		}

		final SecurityFilterChain chain = configureChain;

		ThreadContext.bind(securityManager);
		WebSubject subject = new WebSubject.Builder(securityManager, originalRequest, response).buildWebSubject();

		return subject.execute(new Callable<Boolean>() {
			public Boolean call() throws Exception {
				if (chain == null) return handler.service(originalRequest, response);
				else {
					boolean handled = chain.getHandler().service(request, response);
					return handled || handler.service(request, response);
				}
			}
		});
	}
}
