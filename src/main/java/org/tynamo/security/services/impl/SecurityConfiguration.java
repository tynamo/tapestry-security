package org.tynamo.security.services.impl;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.tapestry5.http.services.ApplicationGlobals;
import org.apache.tapestry5.http.services.HttpServletRequestFilter;
import org.apache.tapestry5.http.services.HttpServletRequestHandler;
import org.apache.tapestry5.http.services.RequestGlobals;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityFilterChainHub;

public class SecurityConfiguration implements HttpServletRequestFilter {

	private final SecurityManager securityManager;
	private final ServletContext servletContext;
	private final LoginContextService loginContextService;
	private final SecurityFilterChainHub securityFilterChainHub;

	private Collection<SecurityFilterChain> chains;
	private final RequestGlobals requestGlobals;

	public SecurityConfiguration(ApplicationGlobals applicationGlobals, RequestGlobals requestGlobals,
								 final WebSecurityManager securityManager, LoginContextService loginContextService,
								 final List<SecurityFilterChain> chains,
								 final SecurityFilterChainHub securityFilterChainHub) {

		this.securityManager = securityManager;
		this.loginContextService = loginContextService;
		this.securityFilterChainHub = securityFilterChainHub;
		this.servletContext = applicationGlobals.getServletContext();
		this.requestGlobals = requestGlobals;
		this.chains = chains;
	}

	public boolean service(final HttpServletRequest originalRequest, final HttpServletResponse response, final HttpServletRequestHandler handler)
			throws IOException {
		// TODO consider whether this guard is necessary at all? I think possibly if container forwards the request internally
		// or, more generically, if the same thread/container-level filter mapping handles the request twice
		if (originalRequest instanceof ShiroHttpServletRequest) return handler.service(originalRequest, response);

		final HttpServletRequest request = new ShiroHttpServletRequest(originalRequest, servletContext, true);

		final String requestURI = loginContextService.getLocalelessPathWithinApplication();

		runChainListeners();

		final SecurityFilterChain chain = getMatchingChain(requestURI);

		requestGlobals.storeServletRequestResponse(request, response);

		ThreadContext.bind(securityManager);
		WebSubject subject = new WebSubject.Builder(securityManager, request, response).buildWebSubject();
		ThreadContext.bind(subject);

		try {
			// return subject.execute(new Callable<Boolean>() {
			// public Boolean call() throws Exception {
			if (chain == null) return handler.service(request, response);
			else {
				boolean handled = chain.getHandler().service(request, response);
				return handled || handler.service(request, response);
			}
			// }
			// });
		}
		finally {
			/**
			 * final 'clean up' operation that removes the underlying {@link ThreadLocal ThreadLocal} from the thread
			 * at the end of execution to prevent leaks in pooled thread environments.
			 */
			ThreadContext.remove(subject);
			ThreadContext.remove();
		}
	}

	private void runChainListeners() {
		securityFilterChainHub.commitModifications(chains);
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
