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
package org.tynamo.security.shiro.authz;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.tynamo.security.internal.services.LoginContextService;


/**
 * Filter that allows access based on any of the roles specified by the mapped value.
 * Access is granted if <em>no roles are specified</em> or if the current user has <em>any</em> of the roles.
 * Access is denied if the current user has none of the roles.
 *
 * @since // TODO add correct release version
 */
public class AnyRoleAuthorizationFilter extends AuthorizationFilter {

    public AnyRoleAuthorizationFilter(LoginContextService loginContextService) {
        super(loginContextService);
    }

    /**
     * {@inheritDoc}
     * @param request {@inheritDoc}
     * @param response {@inheritDoc}
     * @param mappedValue a String array containing the roles any of which the current user must have to be granted access
     * @return {@inheritDoc}
     */
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {

        Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;

        if (rolesArray == null || rolesArray.length == 0) {
            //no roles specified, so nothing to check - allow access.
            return true;
        }

        Set<String> roles = CollectionUtils.asSet(rolesArray);

        return roles.stream().anyMatch(t -> subject.hasRole(t));
    }

}

