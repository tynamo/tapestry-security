package org.tynamo.security.testapp.services;

import org.apache.tapestry5.commons.OrderedConfiguration;
import org.apache.tapestry5.http.services.HttpServletRequestFilter;
import org.apache.tapestry5.ioc.ServiceBinder;

public class FalseContributionModule {

  public static void bind(ServiceBinder binder){
    binder.bind(AFilter.class, AFilter.class);
  }
  public static void contributeHttpServletRequestHandler(
          OrderedConfiguration<HttpServletRequestFilter> configuration, AFilter aFilter)
  {
    configuration.add("aFilter",aFilter);
  }
}
