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
package org.tynamo.security.services.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;
import org.tynamo.security.services.ClassInterceptorsCache;

/**
 * @see ClassInterceptorsCache
 */
public class ClassInterceptorsCacheImpl implements ClassInterceptorsCache {

	private final Map<String, List<SecurityInterceptor>> cache = 
		new HashMap<String, List<SecurityInterceptor>>();
	
	@Override
	public void add(String className, SecurityInterceptor interceptor) {
		List<SecurityInterceptor> interceptors = cache.get(className);
		if (interceptors == null) {
			interceptors = new ArrayList<SecurityInterceptor>();
			cache.put(className, interceptors);
		}
		interceptors.add(interceptor);
	}

	@Override
	public List<SecurityInterceptor> get(String className) {
		return cache.get(className);
	}

	@Override
	public void put(String className, List<SecurityInterceptor> interceptors) {
		cache.put(className, interceptors);
	}
}
