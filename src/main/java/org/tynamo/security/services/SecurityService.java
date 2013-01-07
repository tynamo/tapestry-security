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
package org.tynamo.security.services;

import java.util.concurrent.Callable;

import org.apache.shiro.subject.Subject;

/**
 * General interface for work with shiro api.
 *
 */
public interface SecurityService {

	Subject getSubject();

	/**
	 * Return true only if the current user has executed a <b>successful</b> authentication attempt
	 * <em>during their current session</em>.
	 *
	 * <p>This is more restrictive than the {@link #isUser()}, which only
	 * ensures the current user is known to the system, either via a current login or from Remember Me services,
	 * which only makes the assumption that the current user is who they say they are, and does not guarantee it like
	 * this method does.
	 **/
	boolean isAuthenticated();

	/**
	  * Return true only if the current user has <em>not</em> executed a successful authentication
	 * attempt <em>during their current session</em>.
	 *
	 * <p>The logically opposite tag of this one is the {@link #isAuthenticated()}.
	 */
	boolean isNotAuthenticated();


	/**
	 *
	 * Return true if the current user known to the system, either from a successful login attempt
	 * (not necessarily during the current session) or from 'RememberMe' services.
	 *
	 * <p><b>Note:</b> This is <em>less</em> restrictive than the {@link #isAuthenticated()} since it only assumes
	 * the user is who they say they are, either via a current session login <em>or</em> via Remember Me services, which
	 * makes no guarantee the user is who they say they are.  The {@link #isAuthenticated()} however
	 * guarantees that the current user has logged in <em>during their current session</em>, proving they really are
	 * who they say they are.
	 *
	 * <p>The logically opposite method of this one is the {@link #isGuest()}.
	 */
	boolean isUser();

	/**
	 * Return true if the current user <em>is not</em> known to the system, either because they
	 * haven't logged in yet, or because they have no 'RememberMe' identity.
	 *
	 * <p>The logically opposite method of this one is the {@link #isUser()}.  Please read that class's JavaDoc as it explains
	 * more about the differences between Authenticated/Unauthenticated and User/Guest semantic differences.
	 **/
	boolean isGuest();

	/**
	 * Return true if the current user has any of the roles specified.
	 */
	boolean hasAnyRoles(String roles);

	boolean hasAllRoles(String roles);


	boolean hasPermission(String permission);

	boolean hasAnyPermissions(String permissions);

	boolean hasAllPermissions(String permissions);

	boolean hasRole(String role);

	boolean isLacksPermission(String permission);

	boolean isLacksRole(String role);

	/**
	 * Temporarily disable security before invocation of Callable.
	 *
	 * @param callable A callable that will be invoked with security disabled
	 * @return
	 * @throws Exception
	 */
	<T> T invokeWithSecurityDisabled(Callable<T> callable) throws Exception;
}
