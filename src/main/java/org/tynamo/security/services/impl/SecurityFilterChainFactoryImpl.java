package org.tynamo.security.services.impl;

import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.tapestry5.ioc.services.PipelineBuilder;
import org.slf4j.Logger;
import org.tynamo.security.services.SecurityFilterChainFactory;

public class SecurityFilterChainFactoryImpl implements SecurityFilterChainFactory {
	private PipelineBuilder builder;

	private Logger logger;

	public SecurityFilterChainFactoryImpl(PipelineBuilder builder, Logger logger) {
		this.builder = builder;
		this.logger = logger;
	}

	public SecurityFilterChain.Builder createChain(String path) {
		return new SecurityFilterChain.Builder(logger, builder, path);
	}

	@SuppressWarnings("unchecked")
	public String getLogicalUrl(Class pageClass) {
		// TODO should add package, or maybe use Tapestry util operation for it?
		return "/" + pageClass.getSimpleName().toLowerCase();
	}
	
	public Class<AnonymousFilter> anon() {return AnonymousFilter.class;}
	

}
