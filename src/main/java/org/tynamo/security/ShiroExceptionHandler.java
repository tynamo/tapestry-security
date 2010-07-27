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
package org.tynamo.security;

import org.apache.shiro.ShiroException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.internal.structure.Page;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.runtime.Component;
import org.apache.tapestry5.services.ExceptionReporter;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.tynamo.security.services.PageService;
import org.tynamo.security.services.SecurityService;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler for ShiroException
 *
 */
public class ShiroExceptionHandler
{

	private final PageResponseRenderer renderer;
	private final RequestPageCache pageCache;
	private final SecurityService securityService;
	private final PageService pageService;
	private final RequestGlobals requestGlobals;
	private final Response response;
	private final boolean postTapestry52; 

	public ShiroExceptionHandler(PageResponseRenderer renderer, RequestPageCache pageCache,
	                             SecurityService securityService, PageService pageService,
	                             RequestGlobals requestGlobals, Response response, @Inject @Symbol(SymbolConstants.TAPESTRY_VERSION) String tapestryVersion)
	{

		this.renderer = renderer;
		this.pageCache = pageCache;
		this.securityService = securityService;
		this.pageService = pageService;
		this.requestGlobals = requestGlobals;
		this.response = response;
		tapestryVersion = tapestryVersion.replace(".", "").substring(0, 3);
		int version = Integer.parseInt(tapestryVersion);
		postTapestry52 = version >= 520 ? true : false;
	}


	/**
	 * TODO: Make configurable strategies objects for ShiroException
	 */
	public void handle(ShiroException exception) throws IOException
	{

		if (securityService.isAuthenticated())
		{

			String unauthorizedPage = pageService.getUnauthorizedPage();

			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			if (!StringUtils.hasText(unauthorizedPage))
			{
				return;
			}

			renderPage(exception, unauthorizedPage);

		} else
		{
			Subject subject = securityService.getSubject();

			if (subject != null)
			{
				Session session = subject.getSession();
				if (session != null)
				{
					WebUtils.saveRequest(requestGlobals.getHTTPServletRequest());
				}
			}

			renderPage(exception, pageService.getLoginPage());
		}
	}
	
	private void renderPage(ShiroException exception, String pageName) throws IOException {
		Page page = pageCache.get(pageName);
		if (postTapestry52) requestGlobals.storeActivePageName(pageName);
		reportExceptionIfPossible(exception, page);
		renderer.renderPageResponse(page);
	}

	private void reportExceptionIfPossible(ShiroException exception, Page page)
	{
		Component rootComponent = page.getRootComponent();
		if (rootComponent instanceof ExceptionReporter)
		{
			((ExceptionReporter) rootComponent).reportException(exception);
		}
	}
}
