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
package org.googlecode.tapestry5jsecurity.services.impl;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import org.googlecode.tapestry5jsecurity.services.SecurityService;

/**
 * @see SecurityService
 * @author xibyte
 */
public class SecurityServiceImpl implements SecurityService {

    // Delimeter that separates role names in tag attribute
    private static final String ROLE_NAMES_DELIMETER = ",";
	
	@Override
	public Subject getSubject() {
		return SecurityUtils.getSubject();
	}

	@Override
	public boolean isAuthenticated() {
		Subject subject = getSubject();
		return subject != null && subject.isAuthenticated();
	}
	
	@Override
	public boolean isNotAuthenticated() {
		Subject subject = getSubject();
		return subject == null || !subject.isAuthenticated();
	}
	
	@Override
	public boolean isUser() {
		Subject subject = getSubject();
		return subject != null && subject.getPrincipal() != null;
	}

	@Override
	public boolean isGuest() {
		Subject subject = getSubject();
		return subject  == null || subject.getPrincipal() == null;
	}

	@Override
	public boolean hasAnyRoles(String roles) {
        boolean hasAnyRole = false;

        Subject subject = getSubject();

        if (subject != null) {

            // Iterate through roles and check to see if the user has one of the roles
            for (String role : roles.split(ROLE_NAMES_DELIMETER)) {

                if (subject.hasRole(role.trim())) {
                    hasAnyRole = true;
                    break;
                }
            }
        }

        return hasAnyRole;
	}	
	
	@Override
	public boolean hasPermission(String permission) {
		Subject subject = getSubject();
		return subject != null && subject.isPermitted(permission);
	}
	
	@Override
	public boolean hasRole(String role) {
		Subject subject = getSubject();
		return subject != null && subject.hasRole(role);
	}
	
	@Override
	public boolean isLacksPermission(String permission) {
		return !hasPermission(permission);
	}
	
	@Override
	public boolean isLacksRole(String role) {
		return !hasRole(role);
	}

}
