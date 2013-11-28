package org.tynamo.security.services.impl;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.util.RegExPatternMatcher;
import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.ioc.annotations.EagerLoad;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.slf4j.Logger;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.shiro.AccessControlFilter;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.NotFoundFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.PortFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;
import org.tynamo.security.shiro.authz.SslFilter;

// Eager load since this service initializes the global filter defaults
@EagerLoad
public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {

	private final Logger logger;

	private final PipelineBuilder builder;

	private final LoginContextService loginContextService;

	private final AntPathMatcher antPathMatcher = new AntPathMatcher();
	private final RegExPatternMatcher regExPatternMatcher= new RegExPatternMatcher();

	public SecurityFilterChainFactoryImpl(Logger logger, PipelineBuilder builder, LoginContextService loginContextService,
      @Inject @Symbol(SymbolConstants.TAPESTRY_VERSION) String tapestryVersion,
      @Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
      @Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
      @Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl
	) {
		this.builder = builder;
		this.logger = logger;
		this.loginContextService = loginContextService;
		AccessControlFilter.TAPESTRY_VERSION = tapestryVersion;
		AccessControlFilter.LOGIN_URL = loginUrl;
		AccessControlFilter.SUCCESS_URL = successUrl;
		AccessControlFilter.UNAUTHORIZED_URL = unauthorizedUrl;
	}

	public SecurityFilterChain.Builder createChain(String path) {
		return new SecurityFilterChain.Builder(logger, builder, path, antPathMatcher);
	}

	public SecurityFilterChain.Builder createChain(String pattern, PatternMatcher patternMatcher) {
		return new SecurityFilterChain.Builder(logger, builder, pattern, patternMatcher);
	}

	public SecurityFilterChain.Builder createChainWithAntPath(String path) {
		return new SecurityFilterChain.Builder(logger, builder, path, antPathMatcher);
	}

	public SecurityFilterChain.Builder createChainWithRegEx(String pattern) {
		return new SecurityFilterChain.Builder(logger, builder, pattern, regExPatternMatcher);
	}

	public AnonymousFilter anon() {
		String name = "anon";
		AnonymousFilter filter = new AnonymousFilter(loginContextService);
		filter.setName(name);
		return filter;
	}
	
	public NotFoundFilter notfound() {
		return new NotFoundFilter();
	}
	

	public UserFilter user() {
		String name = "user";
		UserFilter filter = new UserFilter(loginContextService);
		filter.setName(name);
		return filter;
	}

	public FormAuthenticationFilter authc() {
		String name = "authc";
		FormAuthenticationFilter filter = new FormAuthenticationFilter(loginContextService);
		filter.setName(name);
		return filter;
	}

	public BasicHttpAuthenticationFilter basic() {
		String name = "authcBasic";
		BasicHttpAuthenticationFilter filter = new BasicHttpAuthenticationFilter(loginContextService);
		filter.setName(name);
		return filter;
	}

	public RolesAuthorizationFilter roles() {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter(loginContextService);
		filter.setName(name);
		return filter;
	}
	
	
	public PermissionsAuthorizationFilter perms() {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter(loginContextService);
		filter.setName(name);
		return filter;
	}

	@Override
	public SslFilter ssl() {
		SslFilter filter = new SslFilter(loginContextService);
		filter.setName("ssl");
		return filter;
	}

	@Override
	public PortFilter port() {
		PortFilter filter = new PortFilter(loginContextService);
		filter.setName("port");
		return filter;
	}

}
