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
import org.apache.tapestry5.ioc.annotations.Order;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;

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

	private static String defaultSignInPage = "/signin";

	public static void bind(final ServiceBinder binder) {
		binder.bind(RealmSecurityManager.class, WebRealmSecurityManagerImpl.class);
		binder.bind(HttpServletRequestFilter.class, SecurityConfiguration.class).withId("SecurityConfiguration");
		binder.bind(SecurityFilterChainFactory.class, SecurityFilterChainFactoryImpl.class);
		binder.bind(HttpServletRequestDecorator.class, HttpServletRequestDecoratorImpl.class);
	}

	public static void contributeHttpServletRequestHandler(OrderedConfiguration<HttpServletRequestFilter> configuration,
			@InjectService("SecurityConfiguration") HttpServletRequestFilter securityConfiguration) {
		configuration.add("SecurityConfiguration", securityConfiguration, "before:*");
	}

	public static void contributeComponentClassResolver(Configuration<LibraryMapping> configuration) {
		configuration.add(new LibraryMapping("security", "org.trailsframework.security"));
	}

	public static void contributeClasspathAssetAliasManager(MappedConfiguration<String, String> configuration) {
		configuration.add("security/" + version, "org/trailsframework/security");
	}

	@Order("before:*")
	public static <T> T decorateHttpServletRequest(Class<T> serviceInterface, T delegate, HttpServletRequestDecorator decorator) {
		return decorator.build(serviceInterface, delegate);
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
