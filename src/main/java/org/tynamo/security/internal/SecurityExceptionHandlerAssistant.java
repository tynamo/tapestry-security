package org.tynamo.security.internal;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.util.StringUtils;
import org.apache.tapestry5.ExceptionHandlerAssistant;
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.internal.structure.Page;
import org.apache.tapestry5.services.Response;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityService;

public class SecurityExceptionHandlerAssistant implements ExceptionHandlerAssistant {
	private final SecurityService securityService;
	private final LoginContextService loginContextService;
	private final HttpServletRequest servletRequest;
	private final Response response;
	private final PageResponseRenderer renderer;
	private final RequestPageCache pageCache;
	public SecurityExceptionHandlerAssistant(final SecurityService securityService, final LoginContextService pageService, final RequestPageCache pageCache, final HttpServletRequest servletRequest, final Response response, final PageResponseRenderer renderer) {
		this.securityService =securityService;
		this.loginContextService = pageService;
		this.pageCache = pageCache;
		this.servletRequest = servletRequest;
		this.response = response;
		this.renderer = renderer;
	}
	@Override
	public Object handleRequestException(Throwable exception, List<Object> exceptionContext) throws IOException {
		if (securityService.isAuthenticated()) {
			String unauthorizedPage = loginContextService.getUnauthorizedPage();
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			if (!StringUtils.hasText(unauthorizedPage)) return null;

			Page page = pageCache.get(unauthorizedPage);
			renderer.renderPageResponse(page);
			return null;
		}

		String contextPath = servletRequest.getContextPath();
  	if ("".equals(contextPath)) contextPath = "/";
  	loginContextService.saveRequest();
		return loginContextService.getLoginPage();
	}
}
