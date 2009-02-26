package org.trailsframework.security.services;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.jsecurity.web.filter.PathMatchingFilter;
import org.slf4j.Logger;

public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {
	private PipelineBuilder builder;

	private Logger logger;

	public SecurityFilterChainFactoryImpl(PipelineBuilder builder, Logger logger) {
		this.builder = builder;
		this.logger = logger;
	}

	public SecurityFilterChain createChain(String path, final SecurityFilterConfiguration filterConfiguration) {
		List<HttpServletRequestFilter> configuration = new ArrayList<HttpServletRequestFilter>(filterConfiguration.getMap().size());
		for (Filter filter : filterConfiguration.getMap().keySet()) {
			if (filter instanceof PathMatchingFilter) ((PathMatchingFilter) filter).processPathConfig(path, filterConfiguration.getMap().get(filter));
			configuration.add(new HttpServletRequestFilterWrapper(filter));
		}
		return new SecurityFilterChain(path, builder.build(logger, HttpServletRequestHandler.class, HttpServletRequestFilter.class, configuration));

	}

	@SuppressWarnings("unchecked")
	public String getLogicalUrl(Class pageClass) {
		// TODO should add package, or maybe use Tapestry util operation for it?
		return "/" + pageClass.getSimpleName().toLowerCase();
	}

}
