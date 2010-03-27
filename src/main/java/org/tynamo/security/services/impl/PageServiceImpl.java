package org.tynamo.security.services.impl;

import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.tynamo.security.SecuritySymbols;
import org.tynamo.security.services.PageService;

public class PageServiceImpl implements PageService
{

	private String loginPage;
	private String successPage;
	private String unauthorizedPage;

	public PageServiceImpl(
			@Inject @Symbol(SecuritySymbols.SUCCESS_URL) String successUrl,
			@Inject @Symbol(SecuritySymbols.LOGIN_URL) String loginUrl,
			@Inject @Symbol(SecuritySymbols.UNAUTHORIZED_URL) String unauthorizedUrl)
	{

		this.loginPage = urlToPage(loginUrl);
		this.successPage = urlToPage(successUrl);
		this.unauthorizedPage = urlToPage(unauthorizedUrl);
	}

	@Override
	public String getLoginPage()
	{
		return loginPage;
	}

	@Override
	public String getSuccessPage()
	{
		return successPage;
	}

	@Override
	public String getUnauthorizedPage()
	{
		return unauthorizedPage;
	}

	private static String urlToPage(String url)
	{
		if (url.charAt(0) == '/')
		{
			url = url.substring(1);
		}
		return url;
	}

}
