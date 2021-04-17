package org.tynamo.security.testapp.services;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tapestry5.http.services.HttpServletRequestFilter;
import org.apache.tapestry5.http.services.HttpServletRequestHandler;
import org.apache.tapestry5.ioc.annotations.UsesMappedConfiguration;
@UsesMappedConfiguration(key = String.class, value = String.class)
public class AFilter implements HttpServletRequestFilter {
  @Override
  public boolean service(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final HttpServletRequestHandler httpServletRequestHandler) throws IOException {
    return httpServletRequestHandler.service(httpServletRequest, httpServletResponse);
  }

  public AFilter(Map<String, String> config) {
  }
}
