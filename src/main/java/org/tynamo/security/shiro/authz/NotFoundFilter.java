package org.tynamo.security.shiro.authz;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class NotFoundFilter implements Filter {
	@Override
	public void init(FilterConfig filerConfig) {
	}

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
		ServletException {
		
		if (!(response instanceof HttpServletResponse)) chain.doFilter(request, response);
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		// TODO is there some reason to allow customizing the message
		httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND );
	}
}
