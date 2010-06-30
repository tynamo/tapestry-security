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
package org.tynamo.shiro.extension.authz.aop;

import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;

import java.lang.annotation.Annotation;


/**
 * Generic interceptor for use in different aop implementations.
 * Created based on <b>method</b> annotation.
 * <p/>
 * To create the interceptor based on the class annotation, use
 * {@link org.tynamo.shiro.extension.authz.annotations.utils.AnnotationFactory}
 * for convert class annotation to method annotation.
 *
 */
public class DefaultSecurityInterceptor implements SecurityInterceptor
{

	private final AuthorizingAnnotationHandler handler;
	private final Annotation annotation;


	/**
	 * Used in cases where previously known {@link org.apache.shiro.authz.aop.AuthorizingAnnotationHandler} object.
	 * <p/>
	 * if the handler object is unknown use {@link #DefaultSecurityInterceptor(Annotation)} constructor
	 *
	 * @param handler
	 * @param annotation
	 */
	public DefaultSecurityInterceptor(AuthorizingAnnotationHandler handler, Annotation annotation)
	{
		this.handler = handler;
		this.annotation = annotation;
	}

	/**
	 * Initialize {@link #handler} field use annotation.
	 *
	 * @param annotation annotation for create handler and use during
	 *                   {@link #intercept()} invocation.
	 */
	public DefaultSecurityInterceptor(Annotation annotation)
	{

		this.annotation = annotation;
		AuthorizingAnnotationHandler handler = AopHelper.createHandler(annotation);
		if (handler == null)
		{
			throw new IllegalStateException("No handler for " + annotation + "annotation");
		}
		this.handler = handler;

	}

	/* (non-Javadoc)
		 * @see org.tynamo.shiro.extension.authz.aop.SecurityInterceptor#intercept()
		 */

	public void intercept()
	{
		handler.assertAuthorized(getAnnotation());
	}

	public Annotation getAnnotation()
	{
		return annotation;
	}


}
