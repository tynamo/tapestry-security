package org.tynamo.security.internal.services.impl;

import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.EventContext;
import org.apache.tapestry5.Link;
import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.internal.services.LinkSource;
import org.apache.tapestry5.internal.services.RequestImpl;
import org.apache.tapestry5.internal.services.ResponseImpl;
import org.apache.tapestry5.internal.services.TapestrySessionFactory;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.services.ComponentEventLinkEncoder;
import org.apache.tapestry5.services.ComponentEventRequestParameters;
import org.apache.tapestry5.services.LocalizationSetter;
import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.RequestGlobals;

import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.internal.services.LoginContextService;

public class LoginContextServiceImpl implements LoginContextService {

	protected final String loginPage;
	protected final String defaultSuccessPage;
	protected final String unauthorizedPage;
	protected final HttpServletRequest servletRequest;
	protected final HttpServletResponse servletResponse;
	protected final ComponentEventLinkEncoder linkEncoder;
	protected final TapestrySessionFactory sessionFactory;
	protected final RequestGlobals requestGlobals;
	protected final String requestEncoding;
	private final LinkSource linkSource;
	private final LocalizationSetter localizationSetter;

	public LoginContextServiceImpl(@Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
		@Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
		@Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl,
		@Inject @Symbol(SymbolConstants.CHARSET) String requestEncoding, HttpServletRequest serlvetRequest,
		HttpServletResponse servletResponse, LocalizationSetter localizationSetter, LinkSource linkSource,
		ComponentEventLinkEncoder linkEncoder, TapestrySessionFactory sessionFactory, RequestGlobals requestGlobals) {
		this.servletRequest = serlvetRequest;
		this.servletResponse = servletResponse;
		this.linkSource = linkSource;
		this.linkEncoder = linkEncoder;
		this.sessionFactory = sessionFactory;
		this.requestGlobals = requestGlobals;
		this.localizationSetter = localizationSetter;
		this.requestEncoding = requestEncoding;
		this.loginPage = urlToPage(loginUrl);
		this.defaultSuccessPage = urlToPage(successUrl);
		this.unauthorizedPage = urlToPage(unauthorizedUrl);
	}

	@Override
	public String getLoginPage() {
		return loginPage;
	}

	@Override
	public String getSuccessPage() {
		return defaultSuccessPage;
	}

	@Override
	public String getUnauthorizedPage() {
		return unauthorizedPage;
	}

	@Override
	public String getLoginURL() {
		return getLoginPage();
	}

	@Override
	public String getSuccessURL() {
		return getSuccessPage();
	}

	@Override
	public String getUnauthorizedURL() {
		return getUnauthorizedURL();
	}

	private static String urlToPage(String url) {
		if (url.charAt(0) == '/') {
			url = url.substring(1);
		}
		return url;
	}

	@Override
	public String getLocalelessPathWithinApplication() {
		String path = WebUtils.getPathWithinApplication(servletRequest);
		String locale = getLocaleFromPath(path);
		return locale == null ? path : path.substring(locale.length() + 1);
	}

	@Override
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

	public void removeSavedRequest() {
		Cookie cookie = new Cookie(WebUtils.SAVED_REQUEST_KEY, null);
		cookie.setPath(getContextPath());
		cookie.setMaxAge(0);
		servletResponse.addCookie(cookie);
	}

	// In 0.7 I plan to remove the contextPath param and make this operation protected for easy overriding
	private Cookie createSavedRequestCookie(String contextPath) {
		String requestUri;

		// create a T5 request wrapper so we can take advantage of T5'S link decoding services.
		// The security filter intentionally runs as part of the HttpServletRequest chain, i.e. before T5 request and response wrappers
		// we also need to create the response and store them to requestGlobals because LinkSource uses the request object
		final Request request = new RequestImpl(servletRequest, requestEncoding, sessionFactory);
		requestGlobals.storeRequestResponse(request, new ResponseImpl(servletRequest, servletResponse));
		Cookie cookie = new Cookie(WebUtils.SAVED_REQUEST_KEY, "");
		cookie.setPath(contextPath);

		if (!"GET".equalsIgnoreCase(servletRequest.getMethod())) {
			// POST request? => Redirect to target page via HTTP GET?
			ComponentEventRequestParameters eventParameters = linkEncoder.decodeComponentEventRequest(request);
			// Event URL => Redirect to target page via HTTP GET
			if (eventParameters != null) requestUri = createPageRenderLink(eventParameters);
			else {
				// REST API call? => Don't do redirects but set a delete cookie
				cookie.setMaxAge(0);
				return cookie;
			}
		} else {
			ComponentEventRequestParameters eventParameters = linkEncoder.decodeComponentEventRequest(request);

			// Event URL => Redirect to target page via HTTP GET
			if (eventParameters != null) requestUri = createPageRenderLink(eventParameters);
			else {
				// Page render request? => Keep the same URL
				requestUri = WebUtils.getRequestUri(servletRequest);
				if (servletRequest.getQueryString() != null) requestUri += "?" + servletRequest.getQueryString();
			}
		}

		cookie.setValue(requestUri);
		return cookie;
	}

	private String createPageRenderLink(ComponentEventRequestParameters eventParameters) {
		EventContext eventContext = eventParameters.getPageActivationContext();
		Link link = linkSource.createPageRenderLink(eventParameters.getActivePageName(), true,
			(Object[]) eventContext.toStrings());
		return link.toRedirectURI();
	}

	private String getContextPath() {
		String contextPath = servletRequest.getContextPath();
		if ("".equals(contextPath)) contextPath = "/";
		return contextPath;
	}

	@Override
	public void saveRequest() {
		servletResponse.addCookie(createSavedRequestCookie(getContextPath()));
	}

	@Override
	@Deprecated
	public void saveRequest(String contextPath) {
		servletResponse.addCookie(createSavedRequestCookie(contextPath));
	}

	@Override
	public void redirectToSavedRequest(String fallbackUrl) throws IOException {
		Cookie[] cookies = servletRequest.getCookies();

		String requestUri = null;
		if (cookies != null) for (Cookie cookie : cookies)
			if (WebUtils.SAVED_REQUEST_KEY.equals(cookie.getName())) {
				requestUri = cookie.getValue();
				// delete cookie
				cookie.setMaxAge(0);
				servletResponse.addCookie(cookie);
			break;
		}
		if (requestUri == null)
		// FIXME in 0.7.0, as part of issue #16, we should only prepend contextPath if fallbackUrl doesn't start with a leading slash
			requestUri = fallbackUrl.startsWith(getContextPath()) ? fallbackUrl : getContextPath() + fallbackUrl;

		// don't use response.sendRedirect() as that sends SC_FOUND (i.e. 302) and this redirect is typically invoked
		// as a response to a successful (POST) login request
		servletResponse.setStatus(303);
		servletResponse.setHeader("Location", servletResponse.encodeRedirectURL(requestUri));
		// if you don't flush the buffer, filters can and will change the headers afterwards
		servletResponse.flushBuffer();
//		 servletResponse.sendRedirect(servletResponse.encodeRedirectURL(requestUri));
	}
}
