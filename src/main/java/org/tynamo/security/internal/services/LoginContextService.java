package org.tynamo.security.internal.services;

import java.io.IOException;

public interface LoginContextService
{

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

  public String getLocalelessPathWithinApplication();
  
	public String getLocaleFromPath(String path);
	
  public void saveRequest();
  
  public void redirectToSavedRequest(String fallbackUrl) throws IOException;
}
