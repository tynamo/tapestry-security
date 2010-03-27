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

import org.apache.shiro.ShiroException;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.web.WebSecurityManager;
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.ioc.*;
import org.apache.tapestry5.ioc.annotations.*;
import org.apache.tapestry5.services.*;
import org.slf4j.Logger;
import org.tynamo.security.SecurityComponentRequestFilter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.ShiroAnnotationWorker;
import org.tynamo.security.ShiroExceptionHandler;
import org.tynamo.security.filter.SecurityRequestFilter;
import org.tynamo.security.services.impl.ClassInterceptorsCacheImpl;
import org.tynamo.security.services.impl.PageServiceImpl;
import org.tynamo.security.services.impl.SecurityServiceImpl;
import org.tynamo.shiro.extension.authz.annotations.utils.AnnotationFactory;
import org.tynamo.shiro.extension.authz.aop.AopHelper;
import org.tynamo.shiro.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;

import javax.servlet.ServletException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

/**
 * The main entry point for Security integration. To use in your
 * tapestry application add this module to your application module, using
 * {@link org.apache.tapestry5.ioc.annotations.SubModule SubModule annotation}
 *
 * @author Valentine Yerastov
 */
public class SecurityModule
{

	public static void bind(final ServiceBinder binder)
	{

		binder.bind(WebSecurityManager.class, TapestryRealmSecurityManager.class);
		binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
		binder.bind(SecurityService.class, SecurityServiceImpl.class);
		binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
		binder.bind(ShiroExceptionHandler.class);
		binder.bind(PageService.class, PageServiceImpl.class);
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration)
	{
		configuration.add(SecuritySymbols.LOGIN_URL, "/shiro/login");
		configuration.add(SecuritySymbols.SUCCESS_URL, "/index");
		configuration.add(SecuritySymbols.UNAUTHORIZED_URL, "/shiro/unauthorized");
		configuration.add(SecuritySymbols.DEFAULTSIGNINPAGE, "/defaultSignInPage");
	}


	/**
	 * Create ClassInterceptorsCache through annotations on the class page,
	 * which then will use SecurityFilter.
	 * <p/>
	 */
	public void contributeApplicationInitializer(OrderedConfiguration<ApplicationInitializerFilter> configuration,
	                                             final ComponentClassResolver componentClassResolver,
	                                             final ClassInterceptorsCache classInterceptorsCache)
	{

		configuration.add("SecurityApplicationInitializerFilter", new ApplicationInitializerFilter()
		{
			@Override
			public void initializeApplication(Context context, ApplicationInitializer initializer)
			{

				initializer.initializeApplication(context);

				for (String name : componentClassResolver.getPageNames())
				{
					String className = componentClassResolver.resolvePageNameToClassName(name);
					Class<?> clazz = ClassUtils.forName(className);

					while (clazz != null)
					{
						for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationAllClasses())
						{
							Annotation classAnnotation = clazz.getAnnotation(annotationClass);
							if (classAnnotation != null)
							{
								Annotation annotation = AnnotationFactory.getInstance().createAuthzMethodAnnotation(classAnnotation);
								//Add in the cache which then will be used in RequestFilter
								classInterceptorsCache.add(className, new DefaultSecurityInterceptor(annotation));
							}
						}
						clazz = clazz.getSuperclass();
					}
				}
			}
		});
	}


	public static void contributeComponentRequestHandler(OrderedConfiguration<ComponentRequestFilter> configuration,
	                                                     @Local ComponentRequestFilter filter)
	{
		configuration.add("SecurityFilter", filter, "before:*");
	}

	public static void contributeComponentClassTransformWorker(OrderedConfiguration<ComponentClassTransformWorker> configuration)
	{
		configuration.addInstance(ShiroAnnotationWorker.class.getSimpleName(), ShiroAnnotationWorker.class);
	}

	public static void contributeComponentClassResolver(Configuration<LibraryMapping> configuration)
	{
		configuration.add(new LibraryMapping("shiro", "org.tynamo.security"));
	}

	/**
	 * Secure all service methods, witch marked autorization annotations.
	 * <p/>
	 * <b>Resriction:</b> Annotation can present only on service interface.
	 */
	@Match("*")
	@Order("before:*")
	public static void adviseSecurityAssert(MethodAdviceReceiver receiver)
	{

		Class<?> serviceInterface = receiver.getInterface();

		for (Method method : serviceInterface.getMethods())
		{

			List<SecurityInterceptor> interceptors =
					AopHelper.createSecurityInterceptorsSeeingInterfaces(method, serviceInterface);

			for (final SecurityInterceptor interceptor : interceptors)
			{
				MethodAdvice advice = new MethodAdvice()
				{
					@Override
					public void advise(Invocation invocation)
					{

						interceptor.intercept();
						invocation.proceed();

					}
				};
				receiver.adviseMethod(method, advice);
			}

		}
	}

	/**
	 * Advise current RequestExceptionHandler for we can catch ShiroException exceptions and handle this.
	 *
	 * @see org.tynamo.security.ShiroExceptionHandler
	 */
	public static void adviseRequestExceptionHandler(MethodAdviceReceiver receiver,
	                                                 final PageResponseRenderer renderer,
	                                                 final RequestPageCache pageCache,
	                                                 final Logger logger,
	                                                 final RequestGlobals requestGlobals,
	                                                 final Response response,
	                                                 final SecurityService securityService,
	                                                 final ShiroExceptionHandler handler)
	{

		Method handleMethod;

		try
		{
			Class<?> serviceInterface = receiver.getInterface();
			handleMethod = serviceInterface.getMethod(SecuritySymbols.EXCEPTION_HANDLE_METHOD_NAME, Throwable.class);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't find method  " +
					"RequestExceptionHandler." + SecuritySymbols.EXCEPTION_HANDLE_METHOD_NAME + ". Changed API?", e);
		}

		MethodAdvice advice = new MethodAdvice()
		{
			@Override
			public void advise(Invocation invocation)
			{
				Throwable exception = (Throwable) invocation.getParameter(0);

				ShiroException shiroException = null;

				if (exception.getCause() instanceof ShiroException)
				{
					shiroException = (ShiroException) exception.getCause();
				} else if (exception instanceof ShiroException)
				{
					shiroException = (ShiroException) exception;
				}

				if (shiroException != null)
				{

					try
					{
						handler.handle(shiroException);
					} catch (Exception e)
					{
						logger.error("Error handling SecurityException", e);
						invocation.proceed();
					}

				} else
				{
					invocation.proceed();
				}
			}
		};
		receiver.adviseMethod(handleMethod, advice);
	}

	public static void contributeHttpServletRequestHandler(OrderedConfiguration<HttpServletRequestFilter> configuration,
	                                                       @InjectService("SecurityRequestFilter") HttpServletRequestFilter securityRequestFilter)
	{
		configuration.add("SecurityRequestFilter", securityRequestFilter, "before:*");
	}

	@ServiceId("SecurityRequestFilter")
	public static HttpServletRequestFilter buildHttpServletRequestFilter(final ApplicationGlobals globals,
						 Logger logger,
						 WebSecurityManager securityManager,
						 @Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
						 @Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
						 @Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl) throws ServletException
	{
		return new SecurityRequestFilter(securityManager, logger, loginUrl, unauthorizedUrl, successUrl, globals.getServletContext());
	}

}
