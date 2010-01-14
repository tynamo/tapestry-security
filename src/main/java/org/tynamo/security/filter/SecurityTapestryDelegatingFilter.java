package org.tynamo.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.tapestry5.TapestryFilter;
import org.apache.tapestry5.ioc.Registry;

import org.tynamo.security.services.PageService;


public class SecurityTapestryDelegatingFilter implements Filter
{

	private final TapestryFilter tapestryFilter;
	private final SecurityTapestryFilter securityFilter;


	public SecurityTapestryDelegatingFilter()
	{
		tapestryFilter = new TapestryFilter();
		securityFilter = new SecurityTapestryFilter();
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException
	{
		tapestryFilter.init(filterConfig);
		securityFilter.init(filterConfig);

		//Поскольку сейчас TapestryFilter инициализируется перед SecurityTapestryFilter
		//TapestryFilter ничего не знает о конфигурации url страниц(login, success...) и
		//сконфигурирован по умолчанию. Поэтому нужно его переконфигурировать 
		reloadPageConfiguration(filterConfig.getServletContext());

	}

	private void reloadPageConfiguration(ServletContext servletContext) throws ServletException
	{
		Registry registry =
				(Registry) servletContext.getAttribute(TapestryFilter.REGISTRY_CONTEXT_NAME);

		if (registry == null)
		{
			throw new ServletException("Registry not found in ServletContext. Tapestry was not initialize.");
		}

		PageService pageService = registry.getService(PageService.class);
		pageService.loadPagesFromServletContext();

	}

	@Override
	public void destroy()
	{
		tapestryFilter.destroy();
		securityFilter.destroy();
	}

	@Override
	public void doFilter(final ServletRequest request, final ServletResponse response,
	                     final FilterChain mainChain) throws IOException, ServletException
	{
		securityFilter.doFilter(request, response, new FilterChain()
		{
			@Override
			public void doFilter(ServletRequest arg0, ServletResponse chain)
					throws IOException, ServletException
			{
				tapestryFilter.doFilter(request, response, mainChain);
			}
		});
	}

}
