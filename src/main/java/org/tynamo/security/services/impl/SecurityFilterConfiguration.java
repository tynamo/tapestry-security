package org.tynamo.security.services.impl;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

public class SecurityFilterConfiguration {
	private Map<Filter, String> filterConfiguration = new LinkedHashMap<Filter, String>();

	public SecurityFilterConfiguration add(Filter filter) {
		return add(filter, null);
	}

	public SecurityFilterConfiguration add(Filter filter, String configuration) {
		filterConfiguration.put(filter, configuration);
		return this;
	}

	public Map<Filter, String> getMap() {
		return filterConfiguration;
	}

}
