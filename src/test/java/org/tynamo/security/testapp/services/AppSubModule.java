package org.tynamo.security.testapp.services;

import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.tynamo.security.FilterChainDefinition;

public class AppSubModule
{

	public static void contributeSecurityRequestFilter(OrderedConfiguration<FilterChainDefinition> configuration)
	{
		configuration.add("contributed", new FilterChainDefinition("/contributed/**", "roles[user]"));
	}

}
