/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.tynamo.security.shiro;

import static org.apache.shiro.util.StringUtils.split;

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.tynamo.security.internal.services.LoginContextService;

/**
 * Superclass for any filter that controls access to a resource and may redirect the user to the login page
 * if they are not authenticated.  This superclass provides the method
 * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
 * which is used by many subclasses as the behavior when a user is unauthenticated.
 * 
 * This class and the subclasses that are used as Shiro's built-in filters were copied from Shiro 1.1.0
 * and modified locally to implement same behavior as specified in https://issues.apache.org/jira/browse/SHIRO-256
 * We'll revert to using Shiro's filters if the feature gets implemented in Shiro 2.x
 *
 * @since 0.4.0
 */
public abstract class AccessControlFilter extends AdviceFilter {
	// default values - populated by the ChainFactory from symbols 
	public static String TAPESTRY_VERSION, LOGIN_URL, SUCCESS_URL, UNAUTHORIZED_URL;
	public static boolean REDIRECT_TO_SAVED_URL;
	
    protected PatternMatcher pathMatcher = new AntPathMatcher() {
			@Override
			public boolean match(String pattern, String string) {
				return super.match(pattern, string.toLowerCase());
			}
		};
		
		private String[] configElements;

		private String config;
		
		private final LoginContextService loginContextService;
		
		public AccessControlFilter(LoginContextService loginContextService) {
			this.loginContextService = loginContextService;
		}
		
		/*
		 * Same as {@link #setConfig()} except throws an {@link IllegalArgumentException} if config is already set.
		 * Mostly used in the initialization logic  
		 */
		public void addConfig(String config) {
			if (config == null && this.config == null && configElements != null) return;
			if (config != null && config.equals(this.config)) return;
			if (configElements != null) throw new IllegalArgumentException("Configuration is already add for this filter, existing config is " + this.configElements + ". Use setConfig if you want to override the existing configuration");
			setConfig(config);
		}

		
		public void setConfig(String config) {
      if (config != null) configElements = split(config);
      else configElements = new String[0];
      this.config = config;
		}

    /**
     * Constant representing the HTTP 'GET' request method, equal to <code>GET</code>.
     */
    public static final String GET_METHOD = "GET";

    /**
     * Constant representing the HTTP 'POST' request method, equal to <code>POST</code>.
     */
    public static final String POST_METHOD = "POST";

    /**
     * The login url to used to authenticate a user, used when redirecting users if authentication is required.
     */
    private String loginUrl = LOGIN_URL;

    private String successUrl = SUCCESS_URL;
    
    private String unauthorizedUrl = UNAUTHORIZED_URL;
    
    private boolean redirectToSavedUrl = REDIRECT_TO_SAVED_URL;

    /**
     * Returns the success url to use as the default location a user is sent after logging in.  Typically a redirect
     * after login will redirect to the originally request URL; this property is provided mainly as a fallback in case
     * the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @return the success url to use as the default location a user is sent after logging in.
     */
    public String getSuccessUrl() {
        return successUrl;
    }

    /**
     * Sets the default/fallback success url to use as the default location a user is sent after logging in.  Typically
     * a redirect after login will redirect to the originally request URL; this property is provided mainly as a
     * fallback in case the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @param successUrl the success URL to redirect the user to after a successful login.
     */
    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }
    
    
    /**
     * Returns the login URL used to authenticate a user.
     * <p/>
     * Most Shiro filters use this url
     * as the location to redirect a user when the filter requires authentication.  Unless overridden, the
     * {@link #DEFAULT_LOGIN_URL DEFAULT_LOGIN_URL} is assumed, which can be overridden via
     * {@link #setLoginUrl(String) setLoginUrl}.
     *
     * @return the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    public String getLoginUrl() {
        return loginUrl;
    }

    /**
     * Sets the login URL used to authenticate a user.
     * <p/>
     * Most Shiro filters use this url as the location to redirect a user when the filter requires
     * authentication.  Unless overridden, the {@link #DEFAULT_LOGIN_URL DEFAULT_LOGIN_URL} is assumed.
     *
     * @param loginUrl the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getUnauthorizedUrl() {
			return unauthorizedUrl;
		}

		public void setUnauthorizedUrl(String unauthorizedUrl) {
			this.unauthorizedUrl = unauthorizedUrl;
		}

		/**
     * Convenience method that acquires the Subject associated with the request.
     * <p/>
     * The default implementation simply returns
     * {@link org.apache.shiro.SecurityUtils#getSubject() SecurityUtils.getSubject()}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return the Subject associated with the request.
     */
    protected Subject getSubject(ServletRequest request, ServletResponse response) {
        return SecurityUtils.getSubject();
    }

    /**
     * Returns <code>true</code> if the request is allowed to proceed through the filter normally, or <code>false</code>
     * if the request should be handled by the
     * {@link #onAccessDenied(ServletRequest,ServletResponse,Object) onAccessDenied(request,response,mappedValue)}
     * method instead.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return <code>true</code> if the request should proceed through the filter normally, <code>false</code> if the
     *         request should be processed by this filter's
     *         {@link #onAccessDenied(ServletRequest,ServletResponse,Object)} method instead.
     * @throws Exception if an error occurs during processing.
     */
    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception;

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method, retaining the {@code mappedValue} that was used during configuration.
     * <p/>
     * This method immediately delegates to {@link #onAccessDenied(ServletRequest,ServletResponse)} as a
     * convenience in that most post-denial behavior does not need the mapped config again.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the config specified for the filter in the matching request's filter chain.
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     * @since 1.0
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return onAccessDenied(request, response);
    }

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;

    /**
     * Returns <code>true</code> if
     * {@link #isAccessAllowed(ServletRequest,ServletResponse,Object) isAccessAllowed(Request,Response,Object)},
     * otherwise returns the result of
     * {@link #onAccessDenied(ServletRequest,ServletResponse,Object) onAccessDenied(Request,Response,Object)}.
     *
     * @return <code>true</code> if
     *         {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed},
     *         otherwise returns the result of
     *         {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse) onAccessDenied}.
     * @throws Exception if an error occurs.
     */
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return isAccessAllowed(request, response, mappedValue) || onAccessDenied(request, response, mappedValue);
    }
    
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    	  return onPreHandle(request, response, configElements);
    }

    /**
     * Returns <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     * <p/>
     * The default implementation merely returns <code>true</code> if the incoming request matches the configured
     * {@link #getLoginUrl() loginUrl} by calling
     * <code>{@link #pathsMatch(String, String) pathsMatch(loginUrl, request)}</code>.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     */
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
      return pathMatcher.matches(getLoginUrl(), WebUtils.getPathWithinApplication(WebUtils.toHttp(request)));
    }

    /**
     * Convenience method for subclasses to use when a login redirect is required.
     * <p/>
     * This implementation simply calls {@link #saveRequest(javax.servlet.ServletRequest) saveRequest(request)}
     * and then {@link #redirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse) redirectToLogin(request,response)}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
    	saveRequest(request);
    	redirectToLogin(request, response);
    }

    /**
     * Convenience method merely delegates to
     * {@link WebUtils#saveRequest(javax.servlet.ServletRequest) WebUtils.saveRequest(request)} to save the request
     * state for reuse later.  This is mostly used to retain user request state when a redirect is issued to
     * return the user to their originally requested url/resource.
     * <p/>
     * If you need to save and then immediately redirect the user to login, consider using
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)} directly.
     *
     * @param request the incoming ServletRequest to save for re-use later (for example, after a redirect).
     */
    protected void saveRequest(ServletRequest request) {
    	loginContextService.saveRequest();
//    	if (WebUtils.toHttp(request).getSession(false) != null) WebUtils.saveRequest(request);
//    	pageService.getCookies().writeCookieValue(WebUtils.SAVED_REQUEST_KEY, WebUtils.getPathWithinApplication(WebUtils.toHttp(request)));
    }

    /**
     * Convenience method for subclasses that merely acquires the {@link #getLoginUrl() getLoginUrl} and redirects
     * the request to that url.
     * <p/>
     * <b>N.B.</b>  If you want to issue a redirect with the intention of allowing the user to then return to their
     * originally requested URL, don't use this method directly.  Instead you should call
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)}, which will save the current request state so that it can
     * be reconstructed and re-used after a successful login.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
//        String loginUrl = getLoginUrl();
    	String localeName = loginContextService.getLocaleFromPath(WebUtils.getPathWithinApplication(WebUtils.toHttp(request)));
    	String loginUrl = localeName == null ? '/' + loginContextService.getLoginPage() : '/' + localeName + '/' + loginContextService.getLoginPage();
    	
    	// We are not in the response pipeline yet, and it's possible that Tapestry isn't handling this response, but it's still probably 
    	// better than sending a 302 and the full the page
    	if ("XMLHttpRequest".equals(WebUtils.toHttp(request).getHeader("X-Requested-With"))) {
    		WebUtils.toHttp(response).setContentType("application/json;charset=UTF-8");
    		OutputStream os = WebUtils.toHttp(response).getOutputStream();
		    if (TAPESTRY_VERSION.startsWith("5.4")) {
			    os.write(("{\"_tapestry\":{\"redirectURL\":\"" + WebUtils.toHttp(request).getContextPath() + loginUrl + "\"}}").getBytes());
		    } else {
			    os.write(("{\"redirectURL\":\"" + WebUtils.toHttp(request).getContextPath() + loginUrl + "\"}").getBytes());
		    }
		    os.close();
    	}
    	else WebUtils.issueRedirect(request, response, loginUrl);
    }

		public boolean isRedirectToSavedUrl() {
			return redirectToSavedUrl;
		}

		public void setRedirectToSavedUrl(boolean redirectToSavedUrl) {
			this.redirectToSavedUrl = redirectToSavedUrl;
		}
		
		protected LoginContextService getLoginContextService() {
			return loginContextService;
		}

}
