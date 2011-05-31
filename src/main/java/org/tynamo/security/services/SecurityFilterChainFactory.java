package org.tynamo.security.services;

import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.shiro.authc.AnonymousFilter;
import org.tynamo.security.shiro.authc.BasicHttpAuthenticationFilter;
import org.tynamo.security.shiro.authc.FormAuthenticationFilter;
import org.tynamo.security.shiro.authc.UserFilter;
import org.tynamo.security.shiro.authz.PermissionsAuthorizationFilter;
import org.tynamo.security.shiro.authz.RolesAuthorizationFilter;

public interface SecurityFilterChainFactory {
	public SecurityFilterChain.Builder createChain(String path);

	public String getLogicalUrl(Class pageClass);
	
	public void setDefaultSignInPage(String defaultSignInPage);
	
	public AnonymousFilter anon();

	public UserFilter user();

	public FormAuthenticationFilter authc();

	public BasicHttpAuthenticationFilter basic();
	
	public RolesAuthorizationFilter roles();
	
	public PermissionsAuthorizationFilter perms();
}
