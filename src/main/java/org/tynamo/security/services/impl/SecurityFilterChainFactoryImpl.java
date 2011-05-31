package org.tynamo.security.services.impl;

import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.slf4j.Logger;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;

public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {
	private PipelineBuilder builder;

	private Logger logger;
	
	@Deprecated
	private String defaultSignInPage = "/security/login";

	public SecurityFilterChainFactoryImpl(PipelineBuilder builder, Logger logger) {
		this.builder = builder;
		this.logger = logger;
	}

	public SecurityFilterChain.Builder createChain(String path) {
		return new SecurityFilterChain.Builder(logger, builder, path);
	}

	@SuppressWarnings("unchecked")
	public String getLogicalUrl(Class pageClass) {
		// TODO should add package, or maybe use Tapestry util operation for it?
		return "/" + pageClass.getSimpleName().toLowerCase();
	}
	
	@Override
	public void setDefaultSignInPage(String defaultSignInPage) {
		this.defaultSignInPage = defaultSignInPage;
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
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}

	public FormAuthenticationFilter authc() {
		String name = "authc";
		FormAuthenticationFilter filter = new FormAuthenticationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);		
		return filter;
	}

	public BasicHttpAuthenticationFilter basic() {
		String name = "authcBasic";
		BasicHttpAuthenticationFilter filter = new BasicHttpAuthenticationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}

	public RolesAuthorizationFilter roles() {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}
	
	
	public PermissionsAuthorizationFilter perms() {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter();
		filter.setName(name);
		filter.setLoginUrl(defaultSignInPage);
		return filter;
	}
	
	

}
