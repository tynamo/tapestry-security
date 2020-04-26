package org.tynamo.security.internal.services;

import java.io.IOException;

public interface LoginContextService {

	String getLoginPage();

	String getSuccessPage();

	String getUnauthorizedPage();

	@Deprecated
	// to be removed in 0.9
	String getLoginURL();

	@Deprecated
	// to be removed in 0.9
	String getSuccessURL();

	@Deprecated
	// to be removed in 0.9
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
