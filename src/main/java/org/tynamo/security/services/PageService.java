package org.tynamo.security.services;


// Deprecated with an intention of renaming this service and making it internal 
// I don't like the name of the service, not convinced this is needed externally to the module (kaosko 2012-01-15) 
@Deprecated
public interface PageService
{

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

	
  public String getLocalelessPathWithinApplication();
  
	public String getLocaleFromPath(String path);
}
