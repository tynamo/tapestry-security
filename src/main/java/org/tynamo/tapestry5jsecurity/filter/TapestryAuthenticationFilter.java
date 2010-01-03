package org.tynamo.tapestry5jsecurity.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.web.filter.authc.AuthenticationFilter;

public class TapestryAuthenticationFilter extends AuthenticationFilter {

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        if (isLoginRequest(request, response) || isLoginSubmitRequest(request, response)) {
            return true;
        } else {
            saveRequestAndRedirectToLogin(request, response);
            return false;
        }
    }

	protected boolean isLoginSubmitRequest(ServletRequest request,
			ServletResponse response) {
		
		String requestURI = getPathWithinApplication(request);
		
		return pathsMatch(getLoginUrl(), eraseSubmit(requestURI));
	}

	protected String eraseSubmit(String url) {
		if (url == null) {
			return url;
		}
		return url.replaceFirst("[\\.\\;\\?\\&][^\\/]*$", "");
	}
	
	public static void main(String[] args) {
		System.out.println(new TapestryAuthenticationFilter().eraseSubmit("/ligun/do.action;jsessionid=23231" ));
	}
}
