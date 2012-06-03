package org.tynamo.security.services.impl;

import java.io.IOException;

import org.tynamo.security.internal.services.LoginContextService;
import org.tynamo.security.services.PageService;

public class PageServiceImpl implements PageService {
	private LoginContextService loginContextService;

	public PageServiceImpl(LoginContextService loginContextService) {
		this.loginContextService = loginContextService;
	}

	@Override
	public String getLoginPage() {
		return loginContextService.getLoginPage();
	}

	@Override
	public String getSuccessPage() {
		return loginContextService.getSuccessPage();
	}

	@Override
	public String getUnauthorizedPage() {
		return loginContextService.getUnauthorizedPage();
	}

	@Override
	public String getLocalelessPathWithinApplication() {
		return loginContextService.getLocalelessPathWithinApplication();
	}

	@Override
	public String getLocaleFromPath(String path) {
		return loginContextService.getLocaleFromPath(path);
	}
	
	@Override
  public void saveRequest() {
		loginContextService.saveRequest();
  }
	
	@Override
  public void redirectToSavedRequest(String fallbackUrl) throws IOException {
		loginContextService.redirectToSavedRequest(fallbackUrl);
  }
	
}
