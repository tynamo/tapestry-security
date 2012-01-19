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

import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.ShiroException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.util.WebUtils;
import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.internal.structure.Page;
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
import org.apache.tapestry5.ioc.annotations.SubModule;
import org.apache.tapestry5.services.ApplicationInitializer;
import org.apache.tapestry5.services.ApplicationInitializerFilter;
import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.Context;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.PageRenderLinkSource;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.tynamo.common.ModuleProperties;
import org.tynamo.exceptionpage.ExceptionHandlerAssistant;
import org.tynamo.exceptionpage.services.ExceptionPageModule;
import org.tynamo.security.SecurityComponentRequestFilter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.ShiroAnnotationWorker;
import org.tynamo.security.services.impl.ClassInterceptorsCacheImpl;
import org.tynamo.security.services.impl.PageServiceImpl;
import org.tynamo.security.services.impl.SecurityConfiguration;
import org.tynamo.security.services.impl.SecurityFilterChainFactoryImpl;
import org.tynamo.security.services.impl.SecurityServiceImpl;
import org.tynamo.shiro.extension.authz.aop.AopHelper;
import org.tynamo.shiro.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;

/**
 * The main entry point for Security integration.
 *
 */
@SubModule(ExceptionPageModule.class)
public class SecurityModule
{

	private static final String EXCEPTION_HANDLE_METHOD_NAME = "handleRequestException";
	private static final String PATH_PREFIX = "security";
	private static final String version = ModuleProperties.getVersion(SecurityModule.class);

	public static void bind(final ServiceBinder binder)
	{

		binder.bind(WebSecurityManager.class, TapestryRealmSecurityManager.class);
		binder.bind(HttpServletRequestFilter.class, SecurityConfiguration.class).withId("SecurityConfiguration");
		binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
		binder.bind(SecurityService.class, SecurityServiceImpl.class);
		binder.bind(SecurityFilterChainFactory.class, SecurityFilterChainFactoryImpl.class);
		binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
//		binder.bind(ShiroExceptionHandler.class);
		binder.bind(PageService.class, PageServiceImpl.class);
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration)
	{
		configuration.add(SecuritySymbols.LOGIN_URL, "/" + PATH_PREFIX + "/login");
		configuration.add(SecuritySymbols.SUCCESS_URL, "/index");
		configuration.add(SecuritySymbols.UNAUTHORIZED_URL, "/" + PATH_PREFIX + "/unauthorized");
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
	
	public void contributeExceptionHandler(MappedConfiguration<Class, Object> configuration,
		final PageResponseRenderer renderer, final RequestPageCache pageCache, final SecurityService securityService,
		final PageService pageService, final RequestGlobals requestGlobals, final Response response,
		final PageRenderLinkSource pageRenderLinkSource) {
		final ExceptionHandlerAssistant assistant = new ExceptionHandlerAssistant() {
			@Override
			public Object handleRequestException(Throwable exception, List<Object> exceptionContext) throws IOException {
				if (securityService.isAuthenticated()) {
					String unauthorizedPage = pageService.getUnauthorizedPage();
					response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					if (!StringUtils.hasText(unauthorizedPage)) return null;

					Page page = pageCache.get(unauthorizedPage);
					renderer.renderPageResponse(page);
					return null;
				}
				Subject subject = securityService.getSubject();
				if (subject != null) {
					Session session = subject.getSession();
					if (session != null) WebUtils.saveRequest(requestGlobals.getHTTPServletRequest());
				}

				return pageService.getLoginPage();
			}
		};
		configuration.add(ShiroException.class, assistant);
	}

	public static void contributeHttpServletRequestHandler(OrderedConfiguration<HttpServletRequestFilter> configuration,
			@InjectService("SecurityConfiguration") HttpServletRequestFilter securityConfiguration) {
		configuration.add("SecurityConfiguration", securityConfiguration, "after:StoreIntoGlobals");
	}
}
