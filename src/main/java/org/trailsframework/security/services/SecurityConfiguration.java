package org.trailsframework.security.services;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.support.WebSubjectThreadState;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;

public class SecurityConfiguration implements HttpServletRequestFilter {
	private SecurityManager securityManager;

	private Map<String, SecurityFilterChain> chainMap = new LinkedHashMap<String, SecurityFilterChain>();

	// FIXME make configurable
	private PatternMatcher pathMatcher = new AntPathMatcher();

	public SecurityConfiguration(final RealmSecurityManager securityManager, final List<SecurityFilterChain> chains) {
		this.securityManager = securityManager;
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

	public boolean service(final HttpServletRequest request, final HttpServletResponse response, final HttpServletRequestHandler handler)
			throws IOException {

		String requestURI = WebUtils.getPathWithinApplication(request);

		SecurityFilterChain chain = null;
		for (String path : chainMap.keySet()) {
			// If the path does match, then pass on to the subclass implementation for specific checks:
			if (pathMatcher.matches(path, requestURI)) {
				chain = chainMap.get(path);
				break;
			}
		}
		boolean handled;

		// WebUtils.bindInetAddressToThread(request);
		// WebUtils.bind(request);
		// WebUtils.bind(response);
		// ThreadContext.bind(securityManager);
		// ThreadContext.bind(securityManager.getSubject());

		WebUtils.bind(request);
		WebUtils.bind(response);
		WebSubject subject = new WebSubject.Builder(securityManager, request, response).buildWebSubject();
		WebSubjectThreadState threadState = new WebSubjectThreadState(subject);
		threadState.bind();
		try {
			if (chain == null) handled = handler.service(request, response);
			else {

				handled = chain.getHandler().service(request, response);
				if (!handled) handled = handler.service(request, response);

			}
		} finally {
			threadState.clear();
			WebUtils.unbindServletResponse();
			WebUtils.unbindServletRequest();
		}
		// ThreadContext.unbindSubject();
		// ThreadContext.unbindSecurityManager();
		// WebUtils.unbindServletResponse();
		// WebUtils.unbindServletRequest();
		// WebUtils.unbindInetAddressFromThread();

		return handled;
	}
}
