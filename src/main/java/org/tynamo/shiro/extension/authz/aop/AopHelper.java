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

import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;
import org.tynamo.shiro.extension.authz.annotations.utils.casters.method.HandlerCreateVisitor;
import org.tynamo.shiro.extension.authz.annotations.utils.casters.method.MethodAnnotationCaster;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;


/**
 * Simple util class, help work with annotations and create interceptors
 * based on annotations.
 *
 */
public class AopHelper
{

	/**
	 * List annotations classes which can be applied (either method or a class).
	 */
	private final static Collection<Class<? extends Annotation>> autorizationAnnotationClasses;

	/**
	 * Initialize annotations lists.
	 */
	static
	{
		autorizationAnnotationClasses = new ArrayList<Class<? extends Annotation>>(5);
		autorizationAnnotationClasses.add(RequiresPermissions.class);
		autorizationAnnotationClasses.add(RequiresRoles.class);
		autorizationAnnotationClasses.add(RequiresUser.class);
		autorizationAnnotationClasses.add(RequiresGuest.class);
		autorizationAnnotationClasses.add(RequiresAuthentication.class);
	}

	/**
	 * Create {@link org.apache.shiro.authz.aop.AuthorizingAnnotationHandler}
	 * for annotation.
	 *
	 * @param annotation
	 * @return
	 */
	public static AuthorizingAnnotationHandler createHandler(Annotation annotation)
	{
		HandlerCreateVisitor visitor = new HandlerCreateVisitor();
		MethodAnnotationCaster.getInstance().accept(visitor, annotation);
		return visitor.getHandler();
	}

	/**
	 * Create list of {@link org.tynamo.shiro.extension.authz.aop.SecurityInterceptor}
	 * instances for method. This method search all method and class annotations and use
	 * annotation data for create interceptors.
	 * <p/>
	 * This method considers only those annotations that have been declared
	 * in the set through parameters of the method and class, regardless of the
	 * inheritance or interface implementations
	 *
	 * @param method
	 * @param clazz
	 * @return
	 */
	public static List<SecurityInterceptor> createSecurityInterceptors(Method method, Class<?> clazz)
	{
		List<SecurityInterceptor> result = new ArrayList<SecurityInterceptor>();

		if (isInterceptOnClassAnnotation(method.getModifiers()))
		{
			for (Class<? extends Annotation> ac :
					getAutorizationAnnotationClasses())
			{
				Annotation annotationOnClass = clazz.getAnnotation(ac);
				if (annotationOnClass != null)
				{
					result.add(new DefaultSecurityInterceptor(annotationOnClass));
				}
			}
		}

		for (Class<? extends Annotation> ac :
				getAutorizationAnnotationClasses())
		{
			Annotation annotation = method.getAnnotation(ac);
			if (annotation != null)
			{
				result.add(new DefaultSecurityInterceptor(annotation));
			}
		}

		return result;
	}

	/**
	 * Create list of {@link org.tynamo.shiro.extension.authz.aop.SecurityInterceptor}
	 * instances for method. This method search all method and class annotations and use
	 * annotation data for create interceptors.
	 * <p/>
	 * In contrast of the {@link #createSecurityInterceptors(Method, Class)}, this method
	 * looking for the annotations in all interfaces, witch implement the targetClass.
	 * <p/>
	 * The following rules
	 * <ul>
	 * <li>If annotation on class presents, will be intercepted all methods in the class,
	 * that satisfy the {@link #isInterceptOnClassAnnotation(Method) rule}.</li>
	 * <li>Annotations on methods are <b>not</b> inherited.</li>
	 * <li>Annotations on classes are <b>not</b> inherited.</li>
	 * <li>The annotations are searched in all interfaces, witch implement the targetClass.</li>
	 * <ul>
	 *
	 * @param method
	 * @param targetClass
	 * @return
	 */
	public static List<SecurityInterceptor> createSecurityInterceptorsSeeingInterfaces(Method method,
	                                                                                   Class<?> targetClass)
	{
		List<SecurityInterceptor> interceptors = new ArrayList<SecurityInterceptor>();

		method = findTargetMethod(method, targetClass);

		interceptors.addAll(createSecurityInterceptors(method, targetClass));

		Set<Class<?>> allInterfaces = new HashSet<Class<?>>();
		getAllInterfaces(allInterfaces, targetClass);

		for (Class<?> intf : allInterfaces)
		{
			try
			{
				Method candidate = intf.getMethod(method.getName(), method.getParameterTypes());
				interceptors.addAll(createSecurityInterceptors(candidate, intf));
			} catch (SecurityException e)
			{
				new RuntimeException(e);
			} catch (NoSuchMethodException e)
			{
				//nothing to do
			}
		}

		return interceptors;
	}

	/**
	 * Find the target method of interface.
	 * <p/>
	 * Ensure this: If a class have an interface, then method parameter from interface and
	 * targetClass implementation.
	 * <p/>
	 */
	public static Method findTargetMethod(Method method, Class<?> targetClass)
	{
		try
		{
			method = targetClass.getDeclaredMethod(method.getName(), method.getParameterTypes());
		} catch (SecurityException e)
		{
			throw new RuntimeException(e);
		} catch (NoSuchMethodException e)
		{
			//That's ok
		}
		return method;
	}

	/**
	 * Recursively finds all the interfaces.
	 *
	 * @param searchInterfaces set of result interfaces
	 * @param clazz
	 */
	private static void getAllInterfaces(Set<Class<?>> searchInterfaces, Class<?> clazz)
	{
		while (clazz != null)
		{
			searchInterfaces.addAll(Arrays.asList(clazz.getInterfaces()));
			for (Class<?> intf : clazz.getInterfaces())
			{
				getAllInterfaces(searchInterfaces, intf);
			}
			clazz = clazz.getSuperclass();
		}
	}

	/**
	 * Rule under which determined the fate of the class contains annotation.
	 * <p/>
	 * All public and protected methods.
	 */
	public static boolean isInterceptOnClassAnnotation(int modifiers)
	{
		return Modifier.isPublic(modifiers)
				|| Modifier.isProtected(modifiers);
	}

	public static Collection<Class<? extends Annotation>> getAutorizationAnnotationClasses()
	{
		return autorizationAnnotationClasses;
	}
}
