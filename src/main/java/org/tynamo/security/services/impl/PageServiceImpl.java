package org.tynamo.security.services.impl;

import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.services.LocalizationSetter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.services.PageService;

public class PageServiceImpl implements PageService {

	private String loginPage;
	private String successPage;
	private String unauthorizedPage;
	private final HttpServletRequest request;
	private final LocalizationSetter localizationSetter;

	public PageServiceImpl(@Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
		@Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
		@Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl, HttpServletRequest request,
		LocalizationSetter localizationSetter) {
		this.request = request;
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

}
