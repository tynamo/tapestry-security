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
package org.tynamo.tapestry5jsecurity.filter;

import java.io.StringReader;
import java.util.Map;

import org.apache.shiro.io.IniResource;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.config.IniWebConfiguration;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.tynamo.tapestry5jsecurity.JSecurityModule;

/**
 * Filter extending JSecurityFilter and provide  {@link TapestryIniWebConfiguration}.
 * <p>
 * Also configure login form, success, unauthorized pages urls. 
 * 
 * @see TapestryIniWebConfiguration
 * @author xibyte
 */
public class JSecurityTapestryFilter extends ShiroFilter {

	private static final Logger logger = LoggerFactory.getLogger(JSecurityTapestryFilter.class);
	
	private static final String KEY_PREFIX = JSecurityTapestryFilter.class.getSimpleName()+":";
	
    private static final String GLOBAL_PROPERTY_PREFIX = "jsecurity";

    public JSecurityTapestryFilter() {
    	this.configClassName = TapestryIniWebConfiguration.class.getName();
	}
    
    public static String getContextKey(String property) {
    	return KEY_PREFIX+property;
    }
    
	/**
	 * See all configurations alternatives:
	 * <ul>
	 * <li>Embedded config in web.xml</li>
	 * <li>Configuration file</li>
	 * </ul>
	 * find and save urls for login form, success, unauthorized pages to servlet context.
	 * <p>
	 * This use tapestry for handling exception, redirect after logout etc...  
	 *  
	 * @see org.apache.shiro.web.servlet.JSecurityFilter#onFilterConfigSet()
	 */
	@Override
	protected void onFilterConfigSet() throws Exception {
		super.onFilterConfigSet();
			
		if (StringUtils.hasText(config)) {
			IniResource embededToWebXMLIniResource = new IniResource(new StringReader(config));
			savePropertiesToContext(embededToWebXMLIniResource);
		} 
		
		if (StringUtils.hasText(configUrl)) {
			IniResource fileIniResource = new IniResource(configUrl);
			savePropertiesToContext(fileIniResource);
		}
			
	}
	
	private void savePropertiesToContext(IniResource iniResource) {
		Map<String, String> filters = iniResource.getSections().get(IniWebConfiguration.FILTERS);
		
		savePropertyToContext(filters, JSecurityModule.LOGIN_URL_PROPERTY_NAME);
		savePropertyToContext(filters, JSecurityModule.SUCCESS_URL_PROPERTY_NAME);
		savePropertyToContext(filters, JSecurityModule.UNAUTHORIZED_URL_PROPERTY_NAME);
	}

	private void savePropertyToContext(Map<String, String> filters, String property) {
		String value = null;
		if (filters != null) {
			value = filters.get(GLOBAL_PROPERTY_PREFIX+"."+property);
		}
		
		if (StringUtils.hasText(value)) {
			getServletContext().setAttribute(getContextKey(property), value);
		} else {
			logger.info("Property {} not defined in ini config.", property);
		}
	}
	

}
