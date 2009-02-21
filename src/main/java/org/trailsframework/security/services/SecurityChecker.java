/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007 Robin Helgelin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.trailsframework.security.services;

/**
 * Interface that makes few methods from {@link org.springframework.security.intercept.AbstractSecurityInterceptor}
 * public.
 * 
 * @author Ivan Dubrov
 */
public interface SecurityChecker {
	/**
	 * Check security before calling secured method.
	 * 
	 * @param object
	 *          security object
	 * @return status token
	 */
	// InterceptorStatusToken checkBefore(Object object);
	/**
	 * Check security after calling secured method.
	 * 
	 * @param token
	 *          status token
	 * @param returnedObject
	 *          object returned by the method
	 * @return object to return from the secured method
	 */
	// Object checkAfter(InterceptorStatusToken token, Object returnedObject);
}
