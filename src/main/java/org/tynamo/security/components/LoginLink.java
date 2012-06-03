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

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityService;

/**
 * If subject is not authenticated rendered link to login page,
 * else link to logout.
 *
 */
public class LoginLink
{

	@Inject
	@Property
	private SecurityService securityService;

	@Inject
	private LoginContextService loginContextService;

	public String onActionFromTynamoLoginLink()
	{
		removeSavedRequest();
		return loginContextService.getLoginPage();
	}

	public void onActionFromTynamoLogoutLink()
	{
		securityService.getSubject().logout();
	}

	private void removeSavedRequest()
	{
		Subject subject = securityService.getSubject();
		if (subject != null)
		{
			subject.getSession().removeAttribute(WebUtils.SAVED_REQUEST_KEY);
		}
	}


}
