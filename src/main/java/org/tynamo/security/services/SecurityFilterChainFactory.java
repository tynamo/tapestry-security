package org.tynamo.security.services;

import org.apache.shiro.util.PatternMatcher;
import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.*;

public interface SecurityFilterChainFactory {

	/**
	 * @deprecated in 0.4.5 Use {@link #createChainWithAntPath(String)} or one of the other createChain methods instead.
	 */
	@Deprecated
	public SecurityFilterChain.Builder createChain(String path);

	public SecurityFilterChain.Builder createChain(String path, PatternMatcher patternMatcher);

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
