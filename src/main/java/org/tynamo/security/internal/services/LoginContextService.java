package org.tynamo.security.internal.services;

import java.io.IOException;

public interface LoginContextService {

	@Deprecated
	// to be removed in 0.7
	String getLoginPage();

	@Deprecated
	// to be removed in 0.7
	String getSuccessPage();

	@Deprecated
	// to be removed in 0.7
	String getUnauthorizedPage();

	String getLoginURL();

	String getSuccessURL();

	String getUnauthorizedURL();

	String getLocalelessPathWithinApplication();

	String getLocaleFromPath(String path);

	void saveRequest();

	void removeSavedRequest();

	@Deprecated
	// to be removed in 0.7
	void saveRequest(String contextPath);

	void redirectToSavedRequest(String fallbackUrl) throws IOException;

}
