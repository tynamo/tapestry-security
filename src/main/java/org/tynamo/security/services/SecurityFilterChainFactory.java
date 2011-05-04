package org.tynamo.security.services;

import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.services.impl.SecurityFilterConfiguration;

public interface SecurityFilterChainFactory {
	public SecurityFilterChain createChain(String path, final SecurityFilterConfiguration filterConfiguration);

	public String getLogicalUrl(Class pageClass);
}
