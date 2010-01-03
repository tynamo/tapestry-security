package org.tynamo.security.services.impl;

import org.apache.tapestry5.services.ApplicationGlobals;

import org.tynamo.security.JSecurityModule;
import org.tynamo.security.filter.JSecurityTapestryFilter;
import org.tynamo.security.services.PageService;

public class PageServiceImpl implements PageService {
	
	private String loginPage;
	private String successPage;
	private String unauthorizedPage;
	private final  ApplicationGlobals applicationGlobals;

	public PageServiceImpl(ApplicationGlobals applicationGlobals) {
		this.applicationGlobals = applicationGlobals;  
		loadPagesFromServletContext();
	}
	
	@Override
	public void loadPagesFromServletContext() {
		
    	String loginUrl = (String) applicationGlobals.getServletContext().getAttribute(
    			JSecurityTapestryFilter.getContextKey(JSecurityModule.LOGIN_URL_PROPERTY_NAME));
    	
    	String successUrl = (String) applicationGlobals.getServletContext().getAttribute(
    			JSecurityTapestryFilter.getContextKey(JSecurityModule.SUCCESS_URL_PROPERTY_NAME));
    	
    	String unauthorizedUrl = (String) applicationGlobals.getServletContext().getAttribute(
    			JSecurityTapestryFilter.getContextKey(JSecurityModule.UNAUTHORIZED_URL_PROPERTY_NAME));

    	setLoginPage(urlToPage(loginUrl==null ? 
    			JSecurityModule.LOGIN_URL_DEFAULT_VALUE : loginUrl));
		
    	setSuccessPage(urlToPage(successUrl==null ? 
    			JSecurityModule.SUCCESS_DEFAULT_VALUE:  successUrl));
		
    	setUnauthorizedPage(urlToPage(unauthorizedUrl==null ? 
    			JSecurityModule.UNAUTHORIZED_DEFAULT_VALUE : unauthorizedUrl));
	}
	
	@Override
	public String getLoginPage() {
		return loginPage;
	}

	@Override
	public void setLoginPage(String loginPage) {
		this.loginPage = loginPage;
	}

	@Override
	public String getSuccessPage() {
		return successPage;
	}

	@Override
	public void setSuccessPage(String successPage) {
		this.successPage = successPage;
	}

	@Override
	public void setUnauthorizedPage(String unauthorizedPage) {
		this.unauthorizedPage = unauthorizedPage;
	}

	@Override
	public String getUnauthorizedPage() {
		return unauthorizedPage;
	}

    private static String urlToPage(String url) {
    	if (url.charAt(0) == '/') {
    		url = url.substring(1);
    	}
		return url;
	}
	
}
