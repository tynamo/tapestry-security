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
package org.tynamo.security.shiro.authc;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.shiro.AccessControlFilter;

/**
 * Base class for all Filters that require the current user to be authenticated. This class encapsulates the
 * logic of checking whether a user is already authenticated in the system while subclasses are required to perform
 * specific logic for unauthenticated requests.
 *
 * @since 0.9
 */
public abstract class AuthenticationFilter extends AccessControlFilter {
	public AuthenticationFilter(LoginContextService loginContextService) {
		super(loginContextService);
	}

    /**
     * Determines whether the current subject is authenticated.
     * <p/>
     * The default implementation {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) acquires}
     * the currently executing Subject and then returns
     * {@link org.apache.shiro.subject.Subject#isAuthenticated() subject.isAuthenticated()};
     *
     * @return true if the subject is authenticated; false if the subject is unauthenticated
     */
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        return subject.isAuthenticated();
    }

    /**
     * Redirects to user to the previously attempted URL after a successful login.  This implementation simply calls
     * <code>{@link org.apache.shiro.web.util.WebUtils WebUtils}.{@link WebUtils#redirectToSavedRequest(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String) redirectToSavedRequest}</code>
     * using the {@link #getSuccessUrl() successUrl} as the {@code fallbackUrl} argument to that call.
     *
     * @param request  the incoming request
     * @param response the outgoing response
     * @throws Exception if there is a problem redirecting.
     */
	protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
		String requestUri = getSuccessUrl();
		if (!requestUri.startsWith("/")) requestUri = "/" + requestUri;
		if (isRedirectToSavedUrl()) {
			getLoginContextService().redirectToSavedRequest(requestUri);
			return;
		}
		WebUtils.issueRedirect(request, response, requestUri);
	}
}
