package org.trailsframework.security.services;

public interface SecurityFilterChainFactory {
	public SecurityFilterChain createChain(String path, final SecurityFilterConfiguration filterConfiguration);

	@SuppressWarnings("unchecked")
	public String getLogicalUrl(Class pageClass);
}
