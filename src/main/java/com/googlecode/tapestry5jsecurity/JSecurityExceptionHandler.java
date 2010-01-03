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
package com.googlecode.tapestry5jsecurity;

import javax.servlet.http.HttpServletResponse;

import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.internal.structure.Page;
import org.apache.tapestry5.runtime.Component;
import org.apache.tapestry5.services.ExceptionReporter;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.jsecurity.JSecurityException;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.StringUtils;
import org.jsecurity.web.WebUtils;

import com.googlecode.tapestry5commons.errors.ErrorHandler;
import com.googlecode.tapestry5jsecurity.services.PageService;
import com.googlecode.tapestry5jsecurity.services.SecurityService;

/**
 * Handler for JSecurityException
 * 
 * @author xibyte
 */
public class JSecurityExceptionHandler implements ErrorHandler<JSecurityException> {

	private final PageResponseRenderer renderer;
	private final RequestPageCache pageCache;
	private final SecurityService securityService;
	private final PageService pageService;
	private final RequestGlobals requestGlobals;
	private final Response response;

	public JSecurityExceptionHandler(PageResponseRenderer renderer, RequestPageCache pageCache, 
			SecurityService securityService, PageService pageService, RequestGlobals requestGlobals, Response response) {
		
		this.renderer = renderer;
		this.pageCache = pageCache;
		this.securityService = securityService;
		this.pageService = pageService;
		this.requestGlobals = requestGlobals;
		this.response = response;
	}
	
	public void handle(JSecurityException exception) throws Exception {
		
		if (securityService.isAuthenticated()) {
			
			String unauthorizedPage = pageService.getUnauthorizedPage();
			
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			if (!StringUtils.hasText(unauthorizedPage)) {
				return;
			}
			
			Page page = pageCache.get(unauthorizedPage);
			
			reportExceptionIfPossible(exception, page);
			
			renderer.renderPageResponse(page);
			
		} else {
			response.setStatus(HttpServletResponse.SC_OK);
			Subject subject = securityService.getSubject();
			
			if (subject != null ) {
				Session session = subject.getSession();
				if (session != null) {
					WebUtils.saveRequest(requestGlobals.getHTTPServletRequest());
				}
			}
			
			Page page = pageCache.get(pageService.getLoginPage());
			
			reportExceptionIfPossible(exception, page);
			
			renderer.renderPageResponse(page);
			
		}
	}

	private void reportExceptionIfPossible(JSecurityException exception, Page page) {
		Component rootComponent = page.getRootComponent();
		if (rootComponent instanceof ExceptionReporter) {
			((ExceptionReporter) rootComponent).reportException(exception);
		}
	}


	@Override
	public Class<JSecurityException> getExceptionClass() {
		return JSecurityException.class;
	}


	@Override
	public int getResponseStatusForXHR(JSecurityException th) {
		return HttpServletResponse.SC_UNAUTHORIZED;
	}
}
