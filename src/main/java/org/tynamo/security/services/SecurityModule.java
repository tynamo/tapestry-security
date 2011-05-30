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

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Properties;

import org.apache.shiro.ShiroException;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.filter.PathMatchingFilterPatternMatcherChanger;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.Invocation;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.MethodAdvice;
import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.InjectService;
import org.apache.tapestry5.ioc.annotations.Local;
import org.apache.tapestry5.ioc.annotations.Match;
import org.apache.tapestry5.ioc.annotations.Order;
import org.apache.tapestry5.services.ApplicationInitializer;
import org.apache.tapestry5.services.ApplicationInitializerFilter;
import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.Context;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.slf4j.Logger;
import org.tynamo.security.SecurityComponentRequestFilter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.ShiroAnnotationWorker;
import org.tynamo.security.ShiroExceptionHandler;
import org.tynamo.security.filter.SecurityRequestFilter;
import org.tynamo.security.services.impl.ClassInterceptorsCacheImpl;
import org.tynamo.security.services.impl.PageServiceImpl;
import org.tynamo.security.services.impl.SecurityConfiguration;
import org.tynamo.security.services.impl.SecurityFilterChainFactoryImpl;
import org.tynamo.security.services.impl.SecurityServiceImpl;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.shiro.extension.authz.aop.AopHelper;
import org.tynamo.shiro.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;

/**
 * The main entry point for Security integration.
 *
 */
public class SecurityModule
{

	private static final String EXCEPTION_HANDLE_METHOD_NAME = "handleRequestException";
	private static final String PATH_PREFIX = "security";
	private static String version = "unversioned";

	static
	{
		Properties moduleProperties = new Properties();
		try
		{
			moduleProperties.load(SecurityModule.class.getResourceAsStream("module.properties"));
			version = moduleProperties.getProperty("module.version");
		} catch (IOException e)
		{
			// ignore
		}
	}

	public static void bind(final ServiceBinder binder)
	{

		binder.bind(WebSecurityManager.class, TapestryRealmSecurityManager.class);
		binder.bind(HttpServletRequestFilter.class, SecurityConfiguration.class).withId("SecurityConfiguration");
		binder.bind(HttpServletRequestFilter.class, SecurityRequestFilter.class).withId("SecurityRequestFilter");
		binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
		binder.bind(SecurityService.class, SecurityServiceImpl.class);
		binder.bind(SecurityFilterChainFactory.class, SecurityFilterChainFactoryImpl.class);
		binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
		binder.bind(ShiroExceptionHandler.class);
		binder.bind(PageService.class, PageServiceImpl.class);
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration)
	{
		configuration.add(SecuritySymbols.LOGIN_URL, "/" + PATH_PREFIX + "/login");
		configuration.add(SecuritySymbols.SUCCESS_URL, "/index");
		configuration.add(SecuritySymbols.UNAUTHORIZED_URL, "/" + PATH_PREFIX + "/unauthorized");
		configuration.add(SecuritySymbols.DEFAULTSIGNINPAGE, "/defaultSignInPage");
		configuration.add(SecuritySymbols.CONFIG_PATH, "classpath:shiro.ini");
		configuration.add(SecuritySymbols.SHOULD_LOAD_INI_FROM_CONFIG_PATH, "false");
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
						for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationClasses())
						{
							Annotation classAnnotation = clazz.getAnnotation(annotationClass);
							if (classAnnotation != null)
							{
								//Add in the cache which then will be used in RequestFilter
								classInterceptorsCache.add(className, new DefaultSecurityInterceptor(classAnnotation));
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
		configuration.add(new LibraryMapping(PATH_PREFIX, "org.tynamo.security"));
	}

	public static void contributeClasspathAssetAliasManager(MappedConfiguration<String, String> configuration)
	{
		configuration.add(PATH_PREFIX + "-" + version, "org/tynamo/security");
	}

	/**
	 * Secure all service methods that are marked with authorization annotations.
	 * <p/>
	 * <b>Restriction:</b> Only service interfaces can be annotated.
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
						// Only (try to) intercept if subject is bound.
						// This is useful in case background or initializing operations
						// call service operations that are secure
						if (ThreadContext.getSubject() != null) interceptor.intercept();
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
			handleMethod = serviceInterface.getMethod(EXCEPTION_HANDLE_METHOD_NAME, Throwable.class);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't find method  " +
					"RequestExceptionHandler." + EXCEPTION_HANDLE_METHOD_NAME + ". Changed API?", e);
		}

		MethodAdvice advice = new MethodAdvice()
		{
			@Override
			public void advise(Invocation invocation)
			{
				Throwable exception = (Throwable) invocation.getParameter(0);

				ShiroException shiroException = null;

				// TODO Maybe we should just loop through the chain as done in exceptionpage module
				// Depending on where the error was thrown, there could be several levels of wrappers..
				// For exceptions in component operations, it's OperationException -> ComponentEventException -> ShiroException
				if (exception.getCause() instanceof ShiroException) shiroException = (ShiroException) exception.getCause();
				else if (exception.getCause() !=null && exception.getCause().getCause() instanceof ShiroException) shiroException = (ShiroException) exception.getCause().getCause();
				else if (exception instanceof ShiroException) shiroException = (ShiroException) exception;

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
			@InjectService("SecurityConfiguration") HttpServletRequestFilter securityConfiguration) {
		configuration.add("SecurityConfiguration", securityConfiguration, "before:*");
	}
	
	private static String defaultSignInPage = "/security/login";
	
	public static AnonymousFilter buildAnonymousFilter() throws Exception {
		String name = "anon";
		AnonymousFilter filter = new AnonymousFilter();
		filter.setName(name);
		return filter;
	}

	public static UserFilter buildUserFilter() throws Exception {
		String name = "user";
		UserFilter filter = new UserFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		PathMatchingFilterPatternMatcherChanger.setLowercasingPathMatcher((PathMatchingFilter)filter);
		return filter;
	}

	public static FormAuthenticationFilter buildFormAuthenticationFilter() throws Exception {
		String name = "authc";
		FormAuthenticationFilter filter = new FormAuthenticationFilter();
		filter.setName(name);
		return filter;
	}

	public static BasicHttpAuthenticationFilter buildBasicHttpAuthenticationFilter() throws Exception {
		String name = "authcBasic";
		BasicHttpAuthenticationFilter filter = new BasicHttpAuthenticationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		PathMatchingFilterPatternMatcherChanger.setLowercasingPathMatcher((PathMatchingFilter)filter);
		return filter;
	}

	public static RolesAuthorizationFilter buildRolesAuthorizationFilter() throws Exception {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		PathMatchingFilterPatternMatcherChanger.setLowercasingPathMatcher((PathMatchingFilter)filter);
		return filter;
	}

	public static PermissionsAuthorizationFilter buildPermissionsAuthorizationFilter() throws Exception {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		PathMatchingFilterPatternMatcherChanger.setLowercasingPathMatcher((PathMatchingFilter)filter);
		return filter;
	}

}
