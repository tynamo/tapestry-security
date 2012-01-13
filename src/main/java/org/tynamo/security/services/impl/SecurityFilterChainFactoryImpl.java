package org.tynamo.security.services.impl;

import org.apache.tapestry5.internal.services.LinkSource;
import org.apache.tapestry5.ioc.annotations.EagerLoad;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.slf4j.Logger;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.services.PageService;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.shiro.AccessControlFilter;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.PortFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;
import org.tynamo.security.shiro.authz.SslFilter;

// Eager load since this service initializes the global filter defaults
@EagerLoad
public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {
	private final PipelineBuilder builder;

	private final Logger logger;
	
	private final LinkSource linkSource;
	private final PageService pageService;
	
	public SecurityFilterChainFactoryImpl(Logger logger, PipelineBuilder builder, LinkSource linkSource, PageService pageService,
      @Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
      @Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
      @Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl
	) {
		this.builder = builder;
		this.logger = logger;
		this.linkSource = linkSource;
		this.pageService = pageService;
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
		AnonymousFilter filter = new AnonymousFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}

	public UserFilter user() {
		String name = "user";
		UserFilter filter = new UserFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}

	public FormAuthenticationFilter authc() {
		String name = "authc";
		FormAuthenticationFilter filter = new FormAuthenticationFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}

	public BasicHttpAuthenticationFilter basic() {
		String name = "authcBasic";
		BasicHttpAuthenticationFilter filter = new BasicHttpAuthenticationFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}

	public RolesAuthorizationFilter roles() {
		String name = "roles";
		RolesAuthorizationFilter filter = new RolesAuthorizationFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}
	
	
	public PermissionsAuthorizationFilter perms() {
		String name = "perms";
		PermissionsAuthorizationFilter filter = new PermissionsAuthorizationFilter(linkSource, pageService);
		filter.setName(name);
		return filter;
	}

	@Override
	public SslFilter ssl() {
		SslFilter filter = new SslFilter(linkSource, pageService);
		filter.setName("ssl");
		return filter;
	}

	@Override
	public PortFilter port() {
		PortFilter filter = new PortFilter(linkSource, pageService);
		filter.setName("port");
		return filter;
	}

}
