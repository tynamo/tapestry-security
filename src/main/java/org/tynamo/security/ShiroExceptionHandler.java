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
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.internal.structure.Page;
import org.apache.tapestry5.runtime.Component;
import org.apache.tapestry5.services.ExceptionReporter;
import org.apache.tapestry5.services.PageRenderLinkSource;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.tynamo.security.services.PageService;
import org.tynamo.security.services.SecurityService;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

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
	private final PageRenderLinkSource pageRenderLinkSource;

	public ShiroExceptionHandler(PageResponseRenderer renderer, RequestPageCache pageCache,
	                             SecurityService securityService, PageService pageService,
	                             RequestGlobals requestGlobals, Response response, PageRenderLinkSource pageRenderLinkSource)
	{

		this.renderer = renderer;
		this.pageCache = pageCache;
		this.securityService = securityService;
		this.pageService = pageService;
		this.requestGlobals = requestGlobals;
		this.response = response;
		this.pageRenderLinkSource = pageRenderLinkSource;
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

			Page page = pageCache.get(unauthorizedPage);

			reportExceptionIfPossible(exception, page);

			renderer.renderPageResponse(page);

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

			Page page = pageCache.get(pageService.getLoginPage());

			reportExceptionIfPossible(exception, page);

			WebUtils.issueRedirect(requestGlobals.getHTTPServletRequest(),
					requestGlobals.getHTTPServletResponse(),
					pageRenderLinkSource.createPageRenderLink(pageService.getLoginPage()).toURI(),
					Collections.emptyMap(),
					false,
					true);

		}
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
