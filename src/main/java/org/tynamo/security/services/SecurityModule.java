package org.tynamo.security.services;

import java.io.UnsupportedEncodingException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.lang.io.Serializer;
import org.apache.shiro.lang.util.ClassUtils;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.commons.Configuration;
import org.apache.tapestry5.commons.MappedConfiguration;
import org.apache.tapestry5.commons.OrderedConfiguration;
import org.apache.tapestry5.http.services.ApplicationInitializer;
import org.apache.tapestry5.http.services.ApplicationInitializerFilter;
import org.apache.tapestry5.http.services.Context;
import org.apache.tapestry5.http.services.HttpServletRequestFilter;
import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.Contribute;
import org.apache.tapestry5.ioc.annotations.InjectService;
import org.apache.tapestry5.ioc.annotations.Local;
import org.apache.tapestry5.ioc.annotations.Match;
import org.apache.tapestry5.ioc.annotations.Order;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.services.BindingFactory;
import org.apache.tapestry5.services.BindingSource;
import org.apache.tapestry5.services.ComponentClassResolver;
import org.apache.tapestry5.services.ComponentRequestFilter;
import org.apache.tapestry5.services.Core;
import org.apache.tapestry5.services.Environment;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.transform.ComponentClassTransformWorker2;
import org.slf4j.Logger;
import org.tynamo.security.Security;
import org.tynamo.security.SecurityComponentRequestFilter;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.ShiroAnnotationWorker;
import org.tynamo.security.internal.ModularRealmAuthenticator;
import org.tynamo.security.internal.SecurityExceptionHandlerAssistant;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.internal.services.impl.LoginContextServiceImpl;
import org.tynamo.security.internal.services.impl.PermissionBindingFactory;
import org.tynamo.security.services.impl.ClassInterceptorsCacheImpl;
import org.tynamo.security.services.impl.SecurityConfiguration;
import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.services.impl.SecurityFilterChainFactoryImpl;
import org.tynamo.security.services.impl.SecurityFilterChainHubImpl;
import org.tynamo.security.services.impl.SecurityServiceImpl;
import org.tynamo.security.shiro.SimplePrincipalSerializer;
import org.tynamo.shiro.extension.authz.aop.AopHelper;
import org.tynamo.shiro.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;


/**
 * The main entry point for Security integration.
 */
@Security
public class SecurityModule {
	private static final String PATH_PREFIX = "security";

	public static void bind(final ServiceBinder binder) {
		binder.bind(WebSecurityManager.class, TapestryRealmSecurityManager.class);
		// TYNAMO-155 It's not enough to identify ModularRealmAuthenticator by it's Authenticator interface only
		// because Shiro tests if the object is an instanceof LogoutAware to call logout handlers
		binder.bind(ModularRealmAuthenticator.class);
		binder.bind(SubjectFactory.class, DefaultWebSubjectFactory.class);
		binder.bind(HttpServletRequestFilter.class, SecurityConfiguration.class).withId("SecurityConfiguration").withMarker(Security.class);
		binder.bind(ClassInterceptorsCache.class, ClassInterceptorsCacheImpl.class);
		binder.bind(SecurityService.class, SecurityServiceImpl.class);
		binder.bind(SecurityFilterChainFactory.class, SecurityFilterChainFactoryImpl.class);
		binder.bind(ComponentRequestFilter.class, SecurityComponentRequestFilter.class);
		binder.bind(SecurityFilterChainHub.class, SecurityFilterChainHubImpl.class);
//		binder.bind(ShiroExceptionHandler.class);
		binder.bind(LoginContextService.class, LoginContextServiceImpl.class);
		binder.bind(Serializer.class, SimplePrincipalSerializer.class);
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	public static RememberMeManager buildRememberMeManager(Serializer serializer, Logger logger,
														   @Symbol(SymbolConstants.HMAC_PASSPHRASE) String hmacPassphrase,
														   @Symbol(SecuritySymbols.REMEMBERME_CIPHERKERY) String rememberMeCipherKey) throws UnsupportedEncodingException {
		CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
		// the default Shiro serializer produces obnoxiously long cookies
		rememberMeManager.setSerializer(serializer);

		// assume properly configured cipher is of the right width (divisable by 16)
		byte[] cipherKey = Base64.getDecoder().decode(rememberMeCipherKey);
		if (cipherKey.length <= 0) {
			if (hmacPassphrase.isEmpty()) {
				logger
						.error("Neither symbol '"
									   + SecuritySymbols.REMEMBERME_CIPHERKERY
									   + "' nor  '"
									   + SymbolConstants.HMAC_PASSPHRASE
									   + "' is set. Using a random value as the cipher key for encrypting rememberMe information. Cookies will be invalidated when the JVM is restarted");
				return rememberMeManager;
			}

			logger.warn("Symbol '" + SecuritySymbols.REMEMBERME_CIPHERKERY + "' is not set, using '"
								+ SymbolConstants.HMAC_PASSPHRASE
								+ "' as the cipher. Beware that changing the value will invalidate rememberMe cookies");
			if (hmacPassphrase.length() < 16)
				hmacPassphrase = hmacPassphrase + ("================".substring(hmacPassphrase.length()));
			cipherKey = hmacPassphrase.getBytes("UTF-8");
			if (cipherKey.length > 16) cipherKey = Arrays.copyOf(cipherKey, 16);
		}
		rememberMeManager.setCipherKey(cipherKey);
		return rememberMeManager;
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration) {
		configuration.add(SecuritySymbols.LOGIN_URL, "/" + PATH_PREFIX + "/login");
		configuration.add(SecuritySymbols.SUCCESS_URL, "/" + "${" + SymbolConstants.START_PAGE_NAME + "}");
		configuration.add(SecuritySymbols.UNAUTHORIZED_URL, "/" + PATH_PREFIX + "/unauthorized");
		configuration.add(SecuritySymbols.REDIRECT_TO_SAVED_URL, "true");
		configuration.add(SecuritySymbols.REMEMBERME_CIPHERKERY, "");
	}


	/**
	 * Create ClassInterceptorsCache through annotations on the class page,
	 * which then will use SecurityFilter.
	 * <p>
	 */
	public void contributeApplicationInitializer(OrderedConfiguration<ApplicationInitializerFilter> configuration,
												 final ComponentClassResolver componentClassResolver,
												 final ClassInterceptorsCache classInterceptorsCache) {

		configuration.add("SecurityApplicationInitializerFilter", new ApplicationInitializerFilter() {
			@Override
			public void initializeApplication(Context context, ApplicationInitializer initializer) {

				initializer.initializeApplication(context);

				for (String name : componentClassResolver.getPageNames()) {
					String className = componentClassResolver.resolvePageNameToClassName(name);
					Class<?> clazz = ClassUtils.forName(className);

					while (clazz != null) {
						for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationClasses()) {
							Annotation classAnnotation = clazz.getAnnotation(annotationClass);
							if (classAnnotation != null) {
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
														 @Local ComponentRequestFilter filter) {
		configuration.add("SecurityFilter", filter, "before:*");
	}

	@SuppressWarnings("rawtypes")
	@Contribute(Serializer.class)
	public static void addSafePrincipalTypes(Configuration<Class> configuration) {
		configuration.add(Long.class);
		configuration.add(String.class);
		configuration.add(Integer.class);
		configuration.add(Number.class);
	}

	@Contribute(ComponentClassTransformWorker2.class)
	public static void addTransformWorkers(OrderedConfiguration<ComponentClassTransformWorker2> configuration) {
		configuration.addInstance(ShiroAnnotationWorker.class.getSimpleName(), ShiroAnnotationWorker.class);
	}


	public static void contributeComponentClassResolver(Configuration<LibraryMapping> configuration) {
		configuration.add(new LibraryMapping(PATH_PREFIX, "org.tynamo.security"));
	}

	/**
	 * Secure all service methods that are marked with authorization annotations.
	 * <p>
	 * <b>Restriction:</b> Only service interfaces can be annotated.
	 */
	@Match("*")
	@Order("before:*")
	public static void adviseSecurityAssert(MethodAdviceReceiver receiver,
											final @Core Environment environment) {
		Class<?> serviceInterface = receiver.getInterface();

		for (Method method : serviceInterface.getMethods()) {

			List<SecurityInterceptor> interceptors =
					AopHelper.createSecurityInterceptorsSeeingInterfaces(method, serviceInterface);

			for (final SecurityInterceptor interceptor : interceptors) {
				MethodAdvice advice = new MethodAdvice() {
					@Override
					public void advise(MethodInvocation invocation) {
						// Only (try to) intercept if subject is bound.
						// This is useful in case background or initializing operations
						// call service operations that are secure
						if (ThreadContext.getSubject() != null) {
							environment.push(MethodInvocation.class, invocation);
							try {
								interceptor.intercept();
							}
							finally {
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
		configuration.add("SecurityConfiguration", securityConfiguration, "after:StoreIntoGlobals", "before:IgnoredPaths");
	}

	@Contribute(HttpServletRequestFilter.class)
	@Security
	public static void defaultSecurity(OrderedConfiguration<SecurityFilterChain> configuration,
									   SecurityFilterChainFactory factory) {
		configuration.add("ModulesCompressed", factory.createChain("/modules.gz/**").add(factory.anon()).build());
		configuration.add("Modules", factory.createChain("/modules/**").add(factory.anon()).build());
		configuration.add("Assets", factory.createChain("/assets/**").add(factory.anon()).build());
	}

	@Contribute(BindingSource.class)
	public static void addPermissionBinding(final MappedConfiguration<String, BindingFactory> configuration) {
	    configuration.addInstance("permission", PermissionBindingFactory.class);
	}
}
