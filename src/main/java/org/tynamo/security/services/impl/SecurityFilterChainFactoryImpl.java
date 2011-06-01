package org.tynamo.security.services.impl;

import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.slf4j.Logger;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.shiro.AccessControlFilter;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;

public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {
	private PipelineBuilder builder;

	private Logger logger;
	
	public SecurityFilterChainFactoryImpl(PipelineBuilder builder, Logger logger,
      @Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
      @Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
      @Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl
	) {
		this.builder = builder;
		this.logger = logger;
		AccessControlFilter.LOGIN_URL = loginUrl;
		AccessControlFilter.SUCCESS_URL = successUrl;
		AccessControlFilter.UNAUTHORIZED_URL = unauthorizedUrl;
	}

	public SecurityFilterChain.Builder createChain(String path) {
		return new SecurityFilterChain.Builder(logger, builder, path);
	}

	@SuppressWarnings("unchecked")
	public String getLogicalUrl(Class pageClass) {
		// TODO should add package, or maybe use Tapestry util operation for it?
		return "/" + pageClass.getSimpleName().toLowerCase();
	}
	
	public AnonymousFilter anon() {
		String name = "anon";
		AnonymousFilter filter = new AnonymousFilter();
		filter.setName(name);
		return filter;
	}

	public UserFilter user() {
		String name = "user";
		UserFilter filter = new UserFilter();
		filter.setName(name);
		return filter;
	}

	public FormAuthenticationFilter authc() {
		String name = "authc";
		FormAuthenticationFilter filter = new FormAuthenticationFilter();
		filter.setName(name);
		return filter;
	}

	public BasicHttpAuthenticationFilter basic() {
		String name = "authcBasic";
		BasicHttpAuthenticationFilter filter = new BasicHttpAuthenticationFilter();
		filter.setName(name);
		return filter;
	}

	public RolesAuthorizationFilter roles() {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
		filter.setName(name);
		return filter;
	}
	
	
	public PermissionsAuthorizationFilter perms() {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
		filter.setName(name);
		return filter;
	}
	
	

}
