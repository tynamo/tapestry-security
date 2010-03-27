package org.tynamo.security.filter;

import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.WebSecurityManager;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.IniShiroFilter;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.slf4j.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

public class SecurityRequestFilter extends IniShiroFilter implements HttpServletRequestFilter
{

	private IniShiroFilter shiroFilter;
	private Logger logger;

	private String loginUrl;
	private String unauthorizedUrl;
	private String successUrl;

	public SecurityRequestFilter(WebSecurityManager securityManager, Logger logger,
	                             String loginUrl, String unauthorizedUrl, String successUrl,
	                             final ServletContext servletContext) throws ServletException
	{
		this.logger = logger;
		this.loginUrl = loginUrl;
		this.unauthorizedUrl = unauthorizedUrl;
		this.successUrl = successUrl;

		shiroFilter = new IniShiroFilter();
		shiroFilter.setConfigPath("classpath:shiro.ini");
		shiroFilter.init(new FilterConfig()
		{

			@Override
			public String getFilterName()
			{
				return "ShiroFilter";
			}

			@Override
			public ServletContext getServletContext()
			{
				return servletContext;
			}

			@Override
			public String getInitParameter(String name)
			{
				return null;  //To change body of implemented methods use File | Settings | File Templates.
			}

			@Override
			public Enumeration getInitParameterNames()
			{
				return new Enumeration()
				{

					@Override
					public boolean hasMoreElements()
					{
						return false;
					}

					@Override
					public Object nextElement()
					{
						return null;  //To change body of implemented methods use File | Settings | File Templates.
					}
				};
			}
		}
		);

		shiroFilter.setSecurityManager(securityManager);

		PathMatchingFilterChainResolver resolver = (PathMatchingFilterChainResolver) shiroFilter.getFilterChainResolver();

		Map<String, Filter> defaultFilters = resolver.getFilterChainManager().getFilters();
		//apply global settings if necessary:
		for (Filter filter : defaultFilters.values())
		{
			applyGlobalPropertiesIfNecessary(filter);
		}
	}

	@Override
	public boolean service(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
	                       final HttpServletRequestHandler handler) throws IOException
	{
		// Assume request handled if filter chain is NOT executed
		final boolean[] res = new boolean[]{true};
		try
		{
			shiroFilter.doFilter(httpServletRequest, httpServletResponse, new FilterChain()
			{
				public void doFilter(final ServletRequest request,
				                     final ServletResponse response) throws IOException, ServletException
				{
					res[0] = handler.service((HttpServletRequest) request, (HttpServletResponse) response);
				}
			});
		} catch (ServletException e)
		{
			IOException ex = new IOException(e.getMessage());
			ex.initCause(e);
			throw ex;
		}
		return res[0];
	}

	private void applyLoginUrlIfNecessary(Filter filter)
	{
		if (StringUtils.hasText(loginUrl) && (filter instanceof AccessControlFilter))
		{
			AccessControlFilter acFilter = (AccessControlFilter) filter;
			//only apply the login url if they haven't explicitly configured one already:
			String existingLoginUrl = acFilter.getLoginUrl();
			if (AccessControlFilter.DEFAULT_LOGIN_URL.equals(existingLoginUrl))
			{
				acFilter.setLoginUrl(loginUrl);
			}
		}
	}

	private void applySuccessUrlIfNecessary(Filter filter)
	{
		if (StringUtils.hasText(successUrl) && (filter instanceof AuthenticationFilter))
		{
			AuthenticationFilter authcFilter = (AuthenticationFilter) filter;
			//only apply the successUrl if they haven't explicitly configured one already:
			String existingSuccessUrl = authcFilter.getSuccessUrl();
			if (AuthenticationFilter.DEFAULT_SUCCESS_URL.equals(existingSuccessUrl))
			{
				authcFilter.setSuccessUrl(successUrl);
			}
		}
	}

	private void applyUnauthorizedUrlIfNecessary(Filter filter)
	{
		if (StringUtils.hasText(unauthorizedUrl) && (filter instanceof AuthorizationFilter))
		{
			AuthorizationFilter authzFilter = (AuthorizationFilter) filter;
			//only apply the unauthorizedUrl if they haven't explicitly configured one already:
			String existingUnauthorizedUrl = authzFilter.getUnauthorizedUrl();
			if (existingUnauthorizedUrl == null)
			{
				authzFilter.setUnauthorizedUrl(unauthorizedUrl);
			}
		}
	}

	private void applyGlobalPropertiesIfNecessary(Filter filter)
	{
		applyLoginUrlIfNecessary(filter);
		applySuccessUrlIfNecessary(filter);
		applyUnauthorizedUrlIfNecessary(filter);
	}
}
