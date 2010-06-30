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


import java.util.List;

import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;

/**
 * List of {@link org.tynamo.shiro.extension.authz.aop.SecurityInterceptor} for use
 * in security RequestFilter.
 *
 * @see SecurityModule#buildSecurityFilter(org.slf4j.Logger, org.apache.tapestry5.services.ComponentEventLinkEncoder, org.apache.tapestry5.services.ComponentClassResolver, ClassInterceptorsCache)
 */
public interface ClassInterceptorsCache
{

	void put(String className, List<SecurityInterceptor> interceptors);

	void add(String className, SecurityInterceptor interceptor);

	List<SecurityInterceptor> get(String className);

}
