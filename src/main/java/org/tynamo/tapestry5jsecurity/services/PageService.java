package org.tynamo.tapestry5jsecurity.services;

public interface PageService {
	
	String getLoginPage();

	void setLoginPage(String loginPage);

	String getSuccessPage();

	void setSuccessPage(String successPage);

	String getUnauthorizedPage();
	
	void setUnauthorizedPage(String unauthorizedPage);

	void loadPagesFromServletContext();
	
}
