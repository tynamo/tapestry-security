package org.tynamo.security.services;

import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.tynamo.security.services.impl.SecurityFilterChain;

public interface SecurityFilterChainFactory {
	public SecurityFilterChain.Builder createChain(String path);

	public String getLogicalUrl(Class pageClass);
	
	public Class<AnonymousFilter> anon();
}
