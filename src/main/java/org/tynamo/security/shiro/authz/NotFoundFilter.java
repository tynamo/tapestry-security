package org.tynamo.security.shiro.authz;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

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
