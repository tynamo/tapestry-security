package org.googlecode.tapestry5jsecurity;

import java.io.IOException;
import java.util.List;

import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentEventRequestParameters;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.ComponentRequestHandler;
import org.apache.tapestry5.services.PageRenderRequestParameters;

import org.googlecode.jsecurity.extension.authz.aop.SecurityInterceptor;
import org.googlecode.tapestry5jsecurity.services.ClassInterceptorsCache;
import org.googlecode.tapestry5jsecurity.services.PageService;

public class SecurityComponentRequestFilter implements ComponentRequestFilter {

	private final ComponentClassResolver resolver;
	private final ClassInterceptorsCache classInterceptorsCache;
	private final String loginClassName;
	private final String unauthorizedClassName;
	
	
	public SecurityComponentRequestFilter(PageService pageService,
			ComponentClassResolver resolver,
			ClassInterceptorsCache classInterceptorsCache) {
		
		this.resolver = resolver;
		this.classInterceptorsCache = classInterceptorsCache;
		
		loginClassName = resolver.resolvePageNameToClassName(pageService.getLoginPage());
		unauthorizedClassName = resolver.resolvePageNameToClassName(pageService.getUnauthorizedPage());
		
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
