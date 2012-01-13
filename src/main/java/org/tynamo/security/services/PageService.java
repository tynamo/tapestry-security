package org.tynamo.security.services;

// Deprecated without replacement for now. I don't like the name, I don't like pages are configured as strings (kaosko 2011-1-13) 
@Deprecated
public interface PageService
{

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

}
