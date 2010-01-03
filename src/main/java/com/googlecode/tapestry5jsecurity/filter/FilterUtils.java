/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.googlecode.tapestry5jsecurity.filter;

import java.beans.PropertyDescriptor;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.commons.beanutils.PropertyUtils;
import org.jsecurity.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.tapestry5jsecurity.JSecurityModule;

/**
 * Simple util class to manipulate jsecurity filters.  
 * 
 * @author Valentine Yerastov
 */
public class FilterUtils {

	private static final Logger logger = LoggerFactory
	.getLogger(FilterUtils.class);
	
	/**
	 * Override defults filter configuration 
	 */
	public static void overrideDefaults(Filter filter) {
    	if (filter instanceof AccessControlFilter) {
        	/**
        	 * Override defaults urls
        	 */
        	overrideDefaultPropertyValue(filter, JSecurityModule.LOGIN_URL_PROPERTY_NAME, 
        			JSecurityModule.LOGIN_URL_DEFAULT_VALUE);
        	
        	overrideDefaultPropertyValue(filter, JSecurityModule.SUCCESS_URL_PROPERTY_NAME, 
        			JSecurityModule.SUCCESS_DEFAULT_VALUE);
        	
        	overrideDefaultPropertyValue(filter, JSecurityModule.UNAUTHORIZED_URL_PROPERTY_NAME, 
        			JSecurityModule.UNAUTHORIZED_DEFAULT_VALUE);
    	}
	}
	
	private static void overrideDefaultPropertyValue(Filter filter, String propertyName,
			String propertyDefaultValue) {
		try {
			PropertyDescriptor pd = PropertyUtils.getPropertyDescriptor(filter, propertyName);
			if (pd != null && pd.getWriteMethod() != null) {
				pd.getWriteMethod().invoke(filter, propertyDefaultValue);
			} else {
				logger.debug("No find property {} for bean {}", "", "");
			}
		} catch (Exception e) {
			logger.debug("No find property {} for bean {}", "", "");
		}
	}
	
	/**
	 * Override default authc filter fom {@link org.jsecurity.web.filter.authc.FormAuthenticationFilter} to 
	 * {@link org.jsecurity.web.filter.authc.PassThruAuthenticationFilter}.
	 * <p>
	 * This is necessary in order to handle the authentication process manually.
	 * 
	 *  @see com.googlecode.tapestry5jsecurity.JSecurityExceptionHandler
	 */
	public static Map<String, Filter> overrideAuthenticationFilter(Map<String, Filter> filters) {
		String name = "authc";
		TapestryAuthenticationFilter filter = new TapestryAuthenticationFilter();
        filter.setName(name);
        filters.put(name, filter);
        return filters;
	}

}
