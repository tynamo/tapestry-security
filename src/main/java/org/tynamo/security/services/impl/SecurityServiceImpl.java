/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements.  See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the License.  You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.  See the License for the specific language governing permissions and limitations
 * under the License.
 */
package org.tynamo.security.services.impl;

import java.util.concurrent.Callable;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.tynamo.security.services.SecurityService;


/**
 * DOCUMENT ME!
 *
 * @see SecurityService
 */
public class SecurityServiceImpl implements SecurityService
{
	/**
	 * Delimeter that separates role names in tag attribute
	 */
	@SuppressWarnings("unused")
	private static final String ROLE_NAMES_DELIMETER = ",";

	/**
	 * Delimiter used for permissions, i.e. a |
	 */
	private static final String PERMISSIONS_DELIMETER = "\\|";

	/**
	 * Delimited used for roles that allows , or |
	 */
	private static final String PERMISSIONS_OR_ROLES_DELIMETER = "(,|\\|)";

//	public SecurityServiceImpl(@Autobuild TapestryRealmSecurityManager securityManager) {
//		this.securityManager = securityManager;
//	}


	@Override
	public Subject getSubject()
	{
		return SecurityUtils.getSubject();
	}

	@Override
	public boolean isAuthenticated()
	{
		Subject subject = getSubject();

		return (subject != null) && subject.isAuthenticated();
	}

	@Override
	public boolean isNotAuthenticated()
	{
		Subject subject = getSubject();

		return (subject == null) || !subject.isAuthenticated();
	}

	@Override
	public boolean isUser()
	{
		Subject subject = getSubject();

		return (subject != null) && (subject.getPrincipal() != null);
	}

	@Override
	public boolean isGuest()
	{
		Subject subject = getSubject();

		return (subject == null) || (subject.getPrincipal() == null);
	}

	@Override
	public boolean hasAnyRoles(String roles)
	{
		boolean hasAnyRole = false;

		Subject subject = getSubject();

		if (subject != null)
		{

			// Iterate through roles and check to see if the user has one of the roles
			for (String role : roles.split(PERMISSIONS_OR_ROLES_DELIMETER))
			{

				if (subject.hasRole(role.trim()))
				{
					hasAnyRole = true;

					break;
				}
			}
		}

		return hasAnyRole;
	}

	@Override
	public boolean hasAllRoles(String roles)
	{
		boolean hasAllRole = false; // no subject is false

		Subject subject = getSubject();

		if (subject != null)
		{

			hasAllRole = true; // but no roles is true

			// Iterate through roles and check to see if the user has one of the roles
			for (String role : roles.split(PERMISSIONS_OR_ROLES_DELIMETER))
			{

				if (!subject.hasRole(role.trim()))
				{
					hasAllRole = false;

					break;
				}
			}
		}

		return hasAllRole;
	}

	@Override
	public boolean hasAllPermissions(String permissions)
	{
		boolean hasAllPermissions = false; // no subject is false

		Subject subject = getSubject();

		if (subject != null)
		{

			return subject.isPermittedAll(permissions.split(PERMISSIONS_DELIMETER));
		}

		return hasAllPermissions;
	}

	@Override
	public boolean hasAnyPermissions(String permissions)
	{
		boolean hasAnyPermissions = false;

		Subject subject = getSubject();

		if (subject != null)
		{

			// Iterate through roles and check to see if the user has one of the roles
			for (String role : permissions.split(PERMISSIONS_DELIMETER))
			{

				if (subject.isPermitted(role.trim()))
				{
					hasAnyPermissions = true;

					break;
				}
			}
		}

		return hasAnyPermissions;
	}


	@Override
	public boolean hasPermission(String permission)
	{
		Subject subject = getSubject();

		return (subject != null) && subject.isPermitted(permission);
	}

	@Override
	public boolean hasRole(String role)
	{
		Subject subject = getSubject();

		return (subject != null) && subject.hasRole(role);
	}

	@Override
	public boolean isLacksPermission(String permission)
	{
		return !hasPermission(permission);
	}

	@Override
	public boolean isLacksRole(String role)
	{
		return !hasRole(role);
	}

	@Override
	public <T> T invokeWithSecurityDisabled(Callable<T> callable) throws Exception {
		org.apache.shiro.mgt.SecurityManager securityManager = ThreadContext.getSecurityManager();
		ThreadContext.unbindSecurityManager();
		try {
			return callable.call();
		}
		finally {
			if (securityManager == null) ThreadContext.bind(securityManager);
		}
	}
}
