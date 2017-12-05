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
package org.tynamo.security.components;

import java.io.IOException;
import java.net.URL;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.tapestry5.BindingConstants;
import org.apache.tapestry5.ComponentResources;
import org.apache.tapestry5.EventConstants;
import org.apache.tapestry5.ValidationException;
import org.apache.tapestry5.annotations.OnEvent;
import org.apache.tapestry5.annotations.Parameter;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.ioc.Messages;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.services.Cookies;
import org.apache.tapestry5.services.PageRenderLinkSource;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityService;

/**
 * Login form component
 *
 */
public class LoginForm
{

	private static final Logger logger = LoggerFactory.getLogger(LoginForm.class);

	private static final String LOGIN_FORM_ID = "tynamoLoginForm";

	@Property
	private String login;

	@Property
	private String password;

	@Property
	private boolean tynamoRememberMe;

	private String loginMessage;

	/** Use ^ for current page the component is contained in, empty for configured success url */
	@Parameter(defaultPrefix = BindingConstants.LITERAL)
	private String successURL;

	@Inject
	private Messages messages;

	@Inject
	private Response response;

	@Inject
	private RequestGlobals requestGlobals;

	@Inject
	private SecurityService securityService;

	@Inject
	private LoginContextService loginContextService;

	@Inject
	private PageRenderLinkSource pageRenderLinkSource;

	@Inject
	private ComponentResources componentResources;

	@Inject
	private Cookies cookies;

	@Inject
	@Symbol(SecuritySymbols.REDIRECT_TO_SAVED_URL)
	private boolean redirectToSavedUrl;

	@OnEvent(value = EventConstants.VALIDATE, component = LOGIN_FORM_ID)
	public void attemptToLogin() throws ValidationException
	{

		Subject currentUser = securityService.getSubject();

		if (currentUser == null)
		{
			throw new IllegalStateException("Subject can't be null");
		}

		UsernamePasswordToken token = new UsernamePasswordToken(login, password);
		token.setRememberMe(tynamoRememberMe);


		try
		{
			currentUser.login(token);
		} catch (UnknownAccountException e)
		{
			loginMessage = messages.get("AccountDoesNotExists");
		} catch (IncorrectCredentialsException e)
		{
			loginMessage = messages.get("WrongPassword");
		} catch (LockedAccountException e)
		{
			loginMessage = messages.get("AccountLocked");
		} catch (AuthenticationException e)
		{
			loginMessage = messages.get("AuthenticationError");
		}

		if (loginMessage != null)
		{
		    throw new ValidationException(loginMessage);
		}
	}

	@OnEvent(value = EventConstants.SUCCESS, component = LOGIN_FORM_ID)
	public Object onSuccessfulLogin() throws IOException
	{
		if (StringUtils.hasText(successURL)) {
			if ("^".equals(successURL))
				return pageRenderLinkSource.createPageRenderLink(componentResources.getPage().getClass());
			return new URL(successURL);
		}

		if (redirectToSavedUrl) {
			String requestUri = loginContextService.getSuccessPage();
			if (!requestUri.startsWith("/") && !requestUri.startsWith("http")) {
			    requestUri = "/" + requestUri;
			}
			loginContextService.redirectToSavedRequest(requestUri);
			return null;
		}
		return loginContextService.getSuccessPage();
	}

	public void setLoginMessage(String loginMessage)
	{
		this.loginMessage = loginMessage;
	}

	public String getLoginMessage()
	{
		if (StringUtils.hasText(loginMessage))
		{
			return loginMessage;
		} else
		{
			return " ";
		}
	}

}
