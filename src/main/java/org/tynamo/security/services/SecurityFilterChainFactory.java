package org.tynamo.security.services;

import org.apache.shiro.util.PatternMatcher;
import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.NotFoundFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.PortFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;
import org.tynamo.security.shiro.authz.SslFilter;

public interface SecurityFilterChainFactory {

	public SecurityFilterChain.Builder createChain(String path);

	public SecurityFilterChain.Builder createChain(String path, PatternMatcher patternMatcher);

	/**
	 * @deprecated Introduced in 0.4.5 but never really used, since we decided to keep {@link #createChain(String)} for backwards compatibility.
	 * To be removed in 0.5.0
	 */
	@Deprecated
	public SecurityFilterChain.Builder createChainWithAntPath(String path);

	public SecurityFilterChain.Builder createChainWithRegEx(String path);

	public AnonymousFilter anon();

	public NotFoundFilter notfound();

	public UserFilter user();

	public FormAuthenticationFilter authc();

	public BasicHttpAuthenticationFilter basic();

	public RolesAuthorizationFilter roles();

	public PermissionsAuthorizationFilter perms();

	public SslFilter ssl();

	public PortFilter port();
}
