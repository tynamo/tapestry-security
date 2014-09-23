package org.tynamo.security.internal.services;

import java.io.IOException;

public interface LoginContextService {

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

	String getLocalelessPathWithinApplication();

	String getLocaleFromPath(String path);

	void saveRequest();

	void saveRequest(String contextPath);

	void redirectToSavedRequest(String fallbackUrl) throws IOException;

}
