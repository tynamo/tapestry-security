package org.tynamo.security.services;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

import org.apache.shiro.ShiroException;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.Contribute;
import org.apache.tapestry5.ioc.annotations.InjectService;
import org.apache.tapestry5.ioc.annotations.Local;
import org.apache.tapestry5.ioc.annotations.Marker;
import org.apache.tapestry5.ioc.annotations.Match;
import org.apache.tapestry5.ioc.annotations.Order;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.services.ApplicationInitializer;
import org.apache.tapestry5.services.ApplicationInitializerFilter;
import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.Context;
import org.apache.tapestry5.services.Core;
import org.apache.tapestry5.services.Environment;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.transform.ComponentClassTransformWorker2;
import org.tynamo.common.ModuleProperties;
import org.tynamo.security.Security;
import org.tynamo.security.SecurityComponentRequestFilter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.ShiroAnnotationWorker;
import org.tynamo.security.internal.ModularRealmAuthenticator;
import org.tynamo.security.internal.SecurityExceptionHandlerAssistant;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.internal.services.impl.LoginContextServiceImpl;
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
@Marker(Security.class)
public class SecurityModule
{

	private static final String EXCEPTION_HANDLE_METHOD_NAME = "handleRequestException";
	private static final String PATH_PREFIX = "security";
	private static final String version = ModuleProperties.getVersion(SecurityModule.class);

	public static void bind(final ServiceBinder binder)
	{

		binder.bind(WebSecurityManager.class, TapestryRealmSecurityManager.class);
		// TYNAMO-155 It's not enough to identify ModularRealmAuthenticator by it's Authenticator interface only
		// because Shiro tests if the object is an instanceof LogoutAware to call logout handlers
		binder.bind(ModularRealmAuthenticator.class);
		binder.bind(SubjectFactory.class, DefaultWebSubjectFactory.class);
		binder.bind(RememberMeManager.class, CookieRememberMeManager.class);
		binder.bind(HttpServletRequestFilter.class, SecurityConfiguration.class).withId("SecurityConfiguration");
		binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
		binder.bind(SecurityService.class, SecurityServiceImpl.class);
		binder.bind(SecurityFilterChainFactory.class, SecurityFilterChainFactoryImpl.class);
		binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
//		binder.bind(ShiroExceptionHandler.class);
		binder.bind(LoginContextService.class, LoginContextServiceImpl.class);
		binder.bind(PageService.class, PageServiceImpl.class);
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration)
	{
		configuration.add(SecuritySymbols.LOGIN_URL, "/" + PATH_PREFIX + "/login");
		configuration.add(SecuritySymbols.SUCCESS_URL, "/index");
		configuration.add(SecuritySymbols.UNAUTHORIZED_URL, "/" + PATH_PREFIX + "/unauthorized");
		configuration.add(SecuritySymbols.REDIRECT_TO_SAVED_URL, "true");
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

	@Contribute(ComponentClassTransformWorker2.class)
	public static void addTransformWorkers(OrderedConfiguration<ComponentClassTransformWorker2> configuration)
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
	public static void adviseSecurityAssert(MethodAdviceReceiver receiver,
			final @Core Environment environment)
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
					public void advise(MethodInvocation invocation)
					{
						// Only (try to) intercept if subject is bound.
						// This is useful in case background or initializing operations
						// call service operations that are secure
						if (ThreadContext.getSubject() != null)
						{
							environment.push(MethodInvocation.class, invocation);
							try
							{
								interceptor.intercept();
							}
							finally
							{
								environment.pop(MethodInvocation.class);
							}
						}
						invocation.proceed();

					}
				};
				receiver.adviseMethod(method, advice);
			}

		}
	}

	@SuppressWarnings("rawtypes")
	public void contributeRequestExceptionHandler(MappedConfiguration<Class, Object> configuration) {
		configuration.add(ShiroException.class, SecurityExceptionHandlerAssistant.class);
	}

	public static void contributeHttpServletRequestHandler(OrderedConfiguration<HttpServletRequestFilter> configuration,
			@InjectService("SecurityConfiguration") HttpServletRequestFilter securityConfiguration) {
		configuration.add("SecurityConfiguration", securityConfiguration, "after:StoreIntoGlobals");
	}
}
