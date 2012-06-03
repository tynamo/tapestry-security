package org.tynamo.security;

import java.io.IOException;
import java.util.List;

import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentEventRequestParameters;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.ComponentRequestHandler;
import org.apache.tapestry5.services.PageRenderRequestParameters;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.ClassInterceptorsCache;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;

public class SecurityComponentRequestFilter implements ComponentRequestFilter {

	private final ComponentClassResolver resolver;
	private final ClassInterceptorsCache classInterceptorsCache;
	private final String loginClassName;
	private final String unauthorizedClassName;
	
	
	public SecurityComponentRequestFilter(LoginContextService loginContextService,
			ComponentClassResolver resolver,
			ClassInterceptorsCache classInterceptorsCache) {
		
		this.resolver = resolver;
		this.classInterceptorsCache = classInterceptorsCache;
		
		loginClassName = resolver.resolvePageNameToClassName(loginContextService.getLoginPage());
		unauthorizedClassName = resolver.resolvePageNameToClassName(loginContextService.getUnauthorizedPage());
		
	}

	@Override
	public void handleComponentEvent(
			ComponentEventRequestParameters parameters,
			ComponentRequestHandler handler) throws IOException {
		
		checkInternal(parameters.getActivePageName());
		handler.handleComponentEvent(parameters);
	}

	@Override
	public void handlePageRender(PageRenderRequestParameters parameters,
			ComponentRequestHandler handler) throws IOException {
		
		checkInternal(parameters.getLogicalPageName());
		handler.handlePageRender(parameters);	
	}

	private void checkInternal(String logicalPageName) {

		String pageClassName = resolver.resolvePageNameToClassName(logicalPageName);
		if (
			!(pageClassName.equals(loginClassName) ||
			  pageClassName.equals(unauthorizedClassName))
					
		) {
			
			String className = resolver.resolvePageNameToClassName(logicalPageName);
			
			List<SecurityInterceptor> interceptors = classInterceptorsCache.get(className);
			
			if (interceptors != null) {
				for (SecurityInterceptor interceptor : interceptors) {
					interceptor.intercept();
				}
			}
			
		}			
	}
}
