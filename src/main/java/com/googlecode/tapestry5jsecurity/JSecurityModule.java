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
package com.googlecode.tapestry5jsecurity;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

import org.apache.tapestry5.internal.services.PageResponseRenderer;
import org.apache.tapestry5.internal.services.RequestPageCache;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.Invocation;
import org.apache.tapestry5.ioc.MethodAdvice;
import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.Local;
import org.apache.tapestry5.ioc.annotations.Match;
import org.apache.tapestry5.ioc.annotations.Order;
import org.apache.tapestry5.ioc.annotations.SubModule;
import org.apache.tapestry5.services.ApplicationGlobals;
import org.apache.tapestry5.services.ApplicationInitializer;
import org.apache.tapestry5.services.ApplicationInitializerFilter;
import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.Context;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Response;
import org.jsecurity.util.ClassUtils;
import org.slf4j.Logger;

import com.googlecode.jsecurity.extension.authz.annotations.utils.AnnotationFactory;
import com.googlecode.jsecurity.extension.authz.aop.AopHelper;
import com.googlecode.jsecurity.extension.authz.aop.DefaultSecurityInterceptor;
import com.googlecode.jsecurity.extension.authz.aop.SecurityInterceptor;
import com.googlecode.tapestry5commons.TapestryCommonsModule;
import com.googlecode.tapestry5commons.errors.ErrorHandler;
import com.googlecode.tapestry5jsecurity.services.ClassInterceptorsCache;
import com.googlecode.tapestry5jsecurity.services.PageService;
import com.googlecode.tapestry5jsecurity.services.SecurityService;
import com.googlecode.tapestry5jsecurity.services.impl.ClassInterceptorsCacheImpl;
import com.googlecode.tapestry5jsecurity.services.impl.PageServiceImpl;
import com.googlecode.tapestry5jsecurity.services.impl.SecurityServiceImpl;

/**
 * The main entry point JSecurity integration. To use in your 
 * tapestry application add this module to your application module, using  
 * {@link org.apache.tapestry5.ioc.annotations.SubModule SubModule annotation}
 * 
 * @author Valentine Yerastov
 */
@SubModule(TapestryCommonsModule.class)
public class JSecurityModule {
	
	public static final String LOGIN_URL_PROPERTY_NAME = "loginUrl";
	public static final String SUCCESS_URL_PROPERTY_NAME = "successUrl";
	public static final String UNAUTHORIZED_URL_PROPERTY_NAME = "unauthorizedUrl";

	public static final String LOGIN_URL_DEFAULT_VALUE = "/jsec/login";
	public static final String SUCCESS_DEFAULT_VALUE = "/index";
	public static final String UNAUTHORIZED_DEFAULT_VALUE = "/jsec/unauthorized";

    public static void bind(ServiceBinder binder){
        binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
        binder.bind(SecurityService.class, SecurityServiceImpl.class);
        binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
    }
	
	public static PageService buildPageService(ApplicationGlobals applicationGlobals) {
		PageServiceImpl pageService = new PageServiceImpl(applicationGlobals);
		return pageService;
	}
	
	
	/**
	 * Create ClassInterceptorsCache through annotations on the class page, 
	 * which then will use SecurityFilter.
	 * <p>
	 * <b>RU:</b> 
	 * Создаем ClassInterceptorsCache на основе аннотаций на классе страницы, 
	 * который потом будет использовать SecurityFilter. 
	 */
	public void contributeApplicationInitializer(OrderedConfiguration<ApplicationInitializerFilter> configuration,
			final ComponentClassResolver componentClassResolver,
			final ClassInterceptorsCache classInterceptorsCache) {
		
		configuration.add("JSecurityApplicationInitializerFilter", new ApplicationInitializerFilter() {
				
			@Override
			public void initializeApplication(Context context,
					ApplicationInitializer initializer) {
				
                initializer.initializeApplication(context);
                
                //TODO: Лучшим местом для создания обновления кэша будет JSecurityAnnotationWorker
                for (String name : componentClassResolver.getPageNames()) {
                	String className = componentClassResolver.resolvePageNameToClassName(name);
                	Class<?> clazz = ClassUtils.forName(className);
                	//Смотрим аннотации у классов предков и у себя
                	while (clazz != null) {
	            		for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationAllClasses()) {
	            			Annotation classAnnotation = clazz.getAnnotation(annotationClass);
	            			if (classAnnotation != null) {
	            				Annotation annotation = AnnotationFactory.getInstance().createAuthzMethodAnnotation(classAnnotation);
	            				//Add in the cache which then will be used in RequestFilter
	            				//Добавляем в кэш который потом будет использоваться в RequestFilter
	            				classInterceptorsCache.add(className, new DefaultSecurityInterceptor(annotation));
	            			}
	            		}
	            		clazz = clazz.getSuperclass();
                	}
                }
			}
		});
	}

	
	public static void contributeComponentRequestHandler(
			OrderedConfiguration<ComponentRequestFilter> configuration,
			@Local ComponentRequestFilter filter) {
		
			configuration.add("JSecurityFilter", filter, "before:*");

	}
	
	
	public static void contributeComponentClassTransformWorker(
			OrderedConfiguration<ComponentClassTransformWorker> configuration) {

		configuration.addInstance(JSecurityAnnotationWorker.class
				.getSimpleName(), JSecurityAnnotationWorker.class);
	}

	public static void contributeComponentClassResolver(
			Configuration<LibraryMapping> configuration) {
		configuration.add(new LibraryMapping("jsec", JSecurityModule.class.getPackage().getName()));
	}

	/**
	 * Secure all service methods, witch marked autorization annotations.
	 * <p>
	 * <b>Resriction:</b> Annotation can present only on service interface.
	 */
	@Match("*")
	@Order("before:*")
	public static void adviseJSecurityAssert(MethodAdviceReceiver receiver) {

		Class<?> serviceInterface = receiver.getInterface();

		for (Method method : serviceInterface.getMethods()) {

			List<SecurityInterceptor> interceptors =
				AopHelper.createSecurityInterceptorsSeeingInterfaces(method, serviceInterface);

			for (final SecurityInterceptor interceptor : interceptors) {
				MethodAdvice advice = new MethodAdvice() {
					@Override
					public void advise(Invocation invocation) {

						interceptor.intercept();
						invocation.proceed();

					}
				};
				receiver.adviseMethod(method, advice);
			}
			
		}
	}

	public static JSecurityExceptionHandler buildJSecurityExceptionHandler(
			final PageResponseRenderer renderer, 
			final RequestPageCache pageCache, 
			final Logger logger, 
			final RequestGlobals requestGlobals,
			final Response response,
			final SecurityService securityService,
			final PageService pageService) {

		return new JSecurityExceptionHandler(renderer, pageCache,
				securityService, pageService, requestGlobals, response);
		
	}
	
	public static void contributeErrorHandlerSource(OrderedConfiguration<ErrorHandler<?>> configuration, 
			JSecurityExceptionHandler handler) {

		configuration.add(JSecurityExceptionHandler.class.getSimpleName(), handler, "before:*");
	}

}
