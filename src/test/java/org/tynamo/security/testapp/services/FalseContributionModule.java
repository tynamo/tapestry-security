package org.tynamo.security.testapp.services;

import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.services.HttpServletRequestFilter;

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
