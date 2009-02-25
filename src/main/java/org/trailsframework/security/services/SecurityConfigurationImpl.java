package org.trailsframework.security.services;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.tapestry5.ioc.annotations.EagerLoad;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.jsecurity.web.config.IniWebConfiguration;

@EagerLoad
public class SecurityConfigurationImpl extends IniWebConfiguration implements SecurityConfiguration {
	private static final long serialVersionUID = -2719356039757635700L;

	protected Map<String, SecurityFilterChain> chainMap = new LinkedHashMap<String, SecurityFilterChain>();

	public SecurityConfigurationImpl(final Collection<SecurityFilterChain> chains, SecurityRealm securityRealm) {
		for (SecurityFilterChain chain : chains) {
			chainMap.put(chain.getPath(), chain);
		}
		DefaultWebSecurityManager sm = new DefaultWebSecurityManager();
		sm.setRealms(securityRealm);
		setSecurityManager(sm);
	}

	@Override
	protected FilterChain getChain(String chainUrl, FilterChain originalChain) {
		SecurityFilterChain chain = chainMap.get(chainUrl);
		/*
		if (chain != null && !chain.isEmpty()) {
			return createChain(chain.getFilters(), originalChain);
		}
		*/
		return null;
	}

	@Override
	public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
		if (chainMap.isEmpty()) return null;

		String requestURI = getPathWithinApplication(request);

		for (String path : chainMap.keySet()) {

			// If the path does match, then pass on to the subclass implementation for specific checks:
			if (pathMatches(path, requestURI)) {
				/*
				if (log.isTraceEnabled()) {
					log.trace("Matched path [" + path + "] for requestURI [" + requestURI + "].  " + "Utilizing corresponding filter chain...");
				}
				*/
				return getChain(path, originalChain);
			}
		}

		return null;
	}

}
