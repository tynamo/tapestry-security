/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007, 2008 Robin Helgelin
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

import java.io.IOException;
import java.util.Properties;

import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.InjectService;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.web.config.WebConfiguration;
import org.jsecurity.web.filter.authc.AnonymousFilter;
import org.jsecurity.web.filter.authc.BasicHttpAuthenticationFilter;
import org.jsecurity.web.filter.authc.FormAuthenticationFilter;
import org.jsecurity.web.filter.authc.UserFilter;
import org.jsecurity.web.filter.authz.PermissionsAuthorizationFilter;
import org.jsecurity.web.filter.authz.RolesAuthorizationFilter;
import org.jsecurity.web.servlet.JSecurityFilter;

public class SecurityModule {
	private static String version = "unversioned";
	static {
		Properties moduleProperties = new Properties();
		try {
			moduleProperties.load(SecurityModule.class.getResourceAsStream("module.properties"));
			version = moduleProperties.getProperty("module.version");
		} catch (IOException e) {
			// ignore
		}
	}

	// TODO we should a custom implementation of jsecurityfilter that accepts configurations, such as defaultSigninPage
	private static String defaultSignInPage = "/signin";

	public static void bind(final ServiceBinder binder) {
		binder.bind(SecurityConfiguration.class, SecurityConfigurationImpl.class);
		/*
				binder.bind(LogoutService.class, LogoutServiceImpl.class).withMarker(SpringSecurityServices.class);
				binder.bind(AuthenticationTrustResolver.class, AuthenticationTrustResolverImpl.class).withMarker(SpringSecurityServices.class);
				binder.bind(PasswordEncoder.class, PlaintextPasswordEncoder.class).withMarker(SpringSecurityServices.class);
				*/
	}

	public static void contributeFactoryDefaults(final MappedConfiguration<String, String> configuration) {
		configuration.add("spring-security.check.url", "/j_spring_security_check");
		configuration.add("spring-security.failure.url", "/loginfailed");
		configuration.add("spring-security.target.url", "/");
		configuration.add("spring-security.afterlogout.url", "/");
		configuration.add("spring-security.accessDenied.url", "");
		configuration.add("spring-security.force.ssl.login", "false");
		configuration.add("spring-security.rememberme.key", "REMEMBERMEKEY");
		configuration.add("spring-security.loginform.url", "/loginpage");
		configuration.add("spring-security.anonymous.key", "spring_anonymous");
		configuration.add("spring-security.anonymous.attribute", "anonymous,ROLE_ANONYMOUS");
		configuration.add("spring-security.password.salt", "DEADBEEF");
	}

	/*
	public static void contributeComponentClassTransformWorker(OrderedConfiguration<ComponentClassTransformWorker> configuration, SecurityChecker securityChecker) {
		configuration.add("SpringSecurity", new SpringSecurityWorker(securityChecker));
	}
	*/

	public static void contributeHttpServletRequestHandler(OrderedConfiguration<HttpServletRequestFilter> configuration,
			@InjectService("JSecurityFilter") HttpServletRequestFilter jsecurityFilter) {
		configuration.add("jsecurityFilter", jsecurityFilter, "before:*");
	}

	public static HttpServletRequestFilter buildJSecurityFilter(SecurityConfiguration securityConfiguration) throws Exception {
		// Need to sub-class JSecurityFilter to set the configuration rather than it creating a default one on the fly
		// compare to overridden onFilterConfigSet() implementation
		JSecurityFilter filter = new JSecurityFilter() {
			@Override
			protected void onFilterConfigSet() throws Exception {
				WebConfiguration config = getConfiguration();
				applyFilterConfig(config);
				setConfiguration(config);

				// Retrieve and store a reference to the security manager
				SecurityManager sm = ensureSecurityManager(config);
				setSecurityManager(sm);
			}

			@Override
			public void setConfiguration(WebConfiguration configuration) {
				super.setConfiguration(configuration);
				setSecurityManager(ensureSecurityManager(configuration));
			}

		};
		filter.setConfiguration(securityConfiguration);
		// FIXME add configuration here
		/*
		filter.setContextClass(SecurityContextImpl.class);
		filter.setAllowSessionCreation(true);
		filter.setForceEagerSessionCreation(false);
		filter.afterPropertiesSet();
		*/
		return new HttpServletRequestFilterWrapper(filter);
	}

	/*
	public static void contributeLogoutService(final OrderedConfiguration<LogoutHandler> cfg,
			@InjectService("RememberMeLogoutHandler") final LogoutHandler rememberMeLogoutHandler) {
		cfg.add("securityContextLogoutHandler", new SecurityContextLogoutHandler());
		cfg.add("rememberMeLogoutHandler", rememberMeLogoutHandler);
	}
	*/

	/*
	public static void contributeRequestHandler(final OrderedConfiguration<RequestFilter> configuration, final RequestGlobals globals,
			@InjectService("SpringSecurityExceptionFilter") final SpringSecurityExceptionTranslationFilter springSecurityExceptionFilter) {

		configuration.add("SpringSecurityExceptionFilter", new RequestFilterWrapper(globals, springSecurityExceptionFilter), "after:ErrorFilter");
	}
	*/

	public static void contributeComponentClassResolver(Configuration<LibraryMapping> configuration) {
		configuration.add(new LibraryMapping("security", "org.trailsframework.security"));
	}

	public static void contributeClasspathAssetAliasManager(MappedConfiguration<String, String> configuration) {
		configuration.add("jsecurity/" + version, "org/trailsframework/security");
	}

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
		return filter;
	}

	public static RolesAuthorizationFilter buildRolesAuthorizationFilter() throws Exception {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}

	public static PermissionsAuthorizationFilter buildPermissionsAuthorizationFilter() throws Exception {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}

}
