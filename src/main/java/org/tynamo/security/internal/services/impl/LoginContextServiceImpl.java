package org.tynamo.security.internal.services.impl;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.services.LocalizationSetter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.internal.services.LoginContextService;

public class LoginContextServiceImpl implements LoginContextService {

	private String loginPage;
	private String successPage;
	private String unauthorizedPage;
	private final HttpServletRequest request;
	private final HttpServletResponse response;
	private final LocalizationSetter localizationSetter;

	public LoginContextServiceImpl(@Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
		@Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
		@Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl, HttpServletRequest request,
		HttpServletResponse response,
		LocalizationSetter localizationSetter) {
		this.request = request;
		this.response = response;
		this.localizationSetter = localizationSetter;
		this.loginPage = urlToPage(loginUrl);
		this.successPage = urlToPage(successUrl);
		this.unauthorizedPage = urlToPage(unauthorizedUrl);
	}

	@Override
	public String getLoginPage() {
		return loginPage;
	}

	@Override
	public String getSuccessPage() {
		return successPage;
	}

	@Override
	public String getUnauthorizedPage() {
		return unauthorizedPage;
	}

	private static String urlToPage(String url) {
		if (url.charAt(0) == '/') {
			url = url.substring(1);
		}
		return url;
	}

	@Override
	public String getLocalelessPathWithinApplication() {
		String path = WebUtils.getPathWithinApplication(request);
		String locale = getLocaleFromPath(path);
		return locale == null ? path : path.substring(locale.length() + 1);
	}

	public String getLocaleFromPath(String path) {
		// we have to get the possibly encoded locale from the request, but we are not yet in the Tapestry request processing pipeline.
		// the following was copied and modified from AppPageRenderLinkTransformer.decodePageRenderRequest(...)
		String[] split = path.substring(1).split("/");
		if (split.length > 1 && !"".equals(split[0])) {
			String possibleLocaleName = split[0];
			// Might be just the page activation context, or it might be locale then page
			// activation context
			return localizationSetter.isSupportedLocaleName(possibleLocaleName) ? possibleLocaleName : null;
		}
		return null;
	}

	private Cookie createSavedRequestCookie(String contextPath) {
		String requestUri = WebUtils.getPathWithinApplication(request);
		if (request.getQueryString() != null) requestUri += "?" + request.getQueryString();
		Cookie cookie = new Cookie(WebUtils.SAVED_REQUEST_KEY, requestUri);
		cookie.setPath(contextPath);
		return cookie;
	}

	private String getContextPath() {
		String contextPath = request.getContextPath();
		if ("".equals(contextPath)) contextPath = "/";
		return contextPath;
	}

	@Override
	public void saveRequest() {
		saveRequest(getContextPath());
	}

	@Override
	public void saveRequest(String contextPath) {
		response.addCookie(createSavedRequestCookie(contextPath));
	}

	@Override
  public void redirectToSavedRequest(String fallbackUrl) throws IOException {
		Cookie[] cookies = request.getCookies();
		String requestUri = null;
		if (cookies != null) for (Cookie cookie : cookies) if (WebUtils.SAVED_REQUEST_KEY.equals(cookie.getName())) {
			requestUri = cookie.getValue();
			Cookie deleteCookie = createSavedRequestCookie(getContextPath());
			deleteCookie.setMaxAge(0);
			response.addCookie(deleteCookie);
			break;
		}
		if (requestUri == null) requestUri = fallbackUrl;
		WebUtils.issueRedirect(request, response, requestUri);
  }
}
