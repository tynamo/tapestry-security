package org.tynamo.security.services;

import java.io.IOException;

// To be removed in 0.6. Replaced with internal LoginContextService
@Deprecated
public interface PageService
{

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

  public String getLocalelessPathWithinApplication();

	public String getLocaleFromPath(String path);

  public void saveRequest();

  public void redirectToSavedRequest(String fallbackUrl) throws IOException;
}
