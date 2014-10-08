package org.tynamo.security.internal.services;

import java.io.IOException;

public interface LoginContextService {

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

	String getLocalelessPathWithinApplication();

	String getLocaleFromPath(String path);

	void saveRequest();

	@Deprecated
	// to be removed in 0.7
	void saveRequest(String contextPath);

	void redirectToSavedRequest(String fallbackUrl) throws IOException;

}
