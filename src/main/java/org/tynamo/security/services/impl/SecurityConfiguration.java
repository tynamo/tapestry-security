package org.tynamo.security.services.impl;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.Callable;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.tapestry5.services.ApplicationGlobals;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.tynamo.security.internal.services.LoginContextService;

public class SecurityConfiguration implements HttpServletRequestFilter {

	private final SecurityManager securityManager;
	private final ServletContext servletContext;
	private final LoginContextService loginContextService;

	private final Collection<SecurityFilterChain> chains;

	public SecurityConfiguration(ApplicationGlobals applicationGlobals, final WebSecurityManager securityManager, LoginContextService loginContextService, final Collection<SecurityFilterChain> chains) {

		this.securityManager = securityManager;
		this.loginContextService = loginContextService;
		this.servletContext = applicationGlobals.getServletContext();
		this.chains = chains;

	}

	public boolean service(final HttpServletRequest originalRequest, final HttpServletResponse response, final HttpServletRequestHandler handler)
			throws IOException {
		// TODO consider whether this guard is necessary at all? I think possibly if container forwards the request internally
		// or, more generically, if the same thread/container-level filter mapping handles the request twice
		if (originalRequest instanceof ShiroHttpServletRequest) return handler.service(originalRequest, response);

		final HttpServletRequest request = new ShiroHttpServletRequest(originalRequest, servletContext, true);

		final String requestURI = loginContextService.getLocalelessPathWithinApplication();

		final SecurityFilterChain chain = getMatchingChain(requestURI);

		ThreadContext.bind(securityManager);
		WebSubject subject = new WebSubject.Builder(securityManager, originalRequest, response).buildWebSubject();

		try {
		return subject.execute(new Callable<Boolean>() {
			public Boolean call() throws Exception {
				if (chain == null) return handler.service(request, response);
				else {
					boolean handled = chain.getHandler().service(request, response);
					return handled || handler.service(request, response);
				}
			}
		});
		}
		finally {
			/**
			 * final 'clean up' operation that removes the underlying {@link ThreadLocal ThreadLocal} from the thread
			 * at the end of execution to prevent leaks in pooled thread environments.
			 */
			ThreadContext.remove();
		}
	}

	private SecurityFilterChain getMatchingChain(final String requestURI) {
		for (SecurityFilterChain chain : chains) {
			// If the path does match, then pass on to the subclass implementation for specific checks:
			if (chain.matches(requestURI)) {
				return chain;
			}
		}
		return null;
	}
}
