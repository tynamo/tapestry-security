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
package org.tynamo.security.filter;

import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.config.IniWebConfiguration;
import org.apache.tapestry5.TapestryFilter;
import org.apache.tapestry5.ioc.Registry;
import org.tynamo.security.realm.RealmCollection;

import javax.servlet.Filter;
import java.util.Map;

/**
 * Override default filter configuration, for simple work with tapestry.
 *
 * @author xibyte
 * @see FilterUtils
 */
@SuppressWarnings("serial")
public class TapestryIniWebConfiguration extends IniWebConfiguration
{

	@Override
	protected void initFilter(Filter filter)
	{
		FilterUtils.overrideDefaults(filter);
		super.initFilter(filter);
	}

//    protected Map<String, Filter> createDefaultFilters() {
//    	return FilterUtils.overrideAuthenticationFilter(super.createDefaultFilters());
//    }

	/**
	 * Try find SecurityManager or Realm or RealmCollection in tapestry registry.
	 */
	@Override
	protected SecurityManager createSecurityManager(Map<String, Map<String, String>> sections)
	{
		Registry registry = (Registry) getFilterConfig().getServletContext()
				.getAttribute(TapestryFilter.REGISTRY_CONTEXT_NAME);


		if (registry == null)
		{
			//Can't get Registry
			//(for example: The case when Tapestry filter initialize after
			//Security filter).
			return super.createSecurityManager(sections);
		}

		SecurityManager securityManager =
				findServiceInTapestryRegistry(registry, SecurityManager.class);

		if (securityManager == null)
		{
			securityManager = super.createSecurityManager(sections);

			if (securityManager instanceof RealmSecurityManager)
			{
				RealmSecurityManager realmSm = (RealmSecurityManager) securityManager;

				Realm realm = findServiceInTapestryRegistry(registry, Realm.class);
				if (realm != null)
				{
					realmSm.setRealm(realm);
				} else
				{
					RealmCollection realmCollection = findServiceInTapestryRegistry(registry, RealmCollection.class);
					if (realmCollection != null)
					{
						realmSm.setRealms(realmCollection);
					}
				}
			}
		}

		return securityManager;
	}

	private <T> T findServiceInTapestryRegistry(Registry registry, Class<T> clazz)
	{
		try
		{
			return registry.getService(clazz);
		} catch (RuntimeException e)
		{
			//If service not exists, registsry throw exception.
			return null;
		}
	}
}
