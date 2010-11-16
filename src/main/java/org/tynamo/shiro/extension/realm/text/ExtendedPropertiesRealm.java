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
package org.tynamo.shiro.extension.realm.text;

import org.apache.shiro.authc.*;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.text.PropertiesRealm;

/**
 * Fixes some bugs with {@link org.apache.shiro.realm.text.PropertiesRealm}
 *
 */
public class ExtendedPropertiesRealm extends PropertiesRealm
{

	boolean created;

	public ExtendedPropertiesRealm(String resourcePath)
	{
		super();
		setResourcePath(resourcePath);
		onInit();
	}

	/**
	 * Eliminates the error generating NullPointerException,
	 * when trying to register for non-existent account.
	 * <p/>
	 *
	 * @see org.apache.shiro.realm.SimpleAccountRealm#doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
	{

		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		if (!accountExists(upToken.getUsername()))
		{
			throw new UnknownAccountException("Unknown account" + upToken.getUsername());
		}

		return super.doGetAuthenticationInfo(token);
	}

	@Override
	public void setCacheManager(CacheManager authzInfoCacheManager)
	{
		if (created && getCacheManager() != null)
		{
			return;
		}
		super.setCacheManager(authzInfoCacheManager);
	}


	/**
	 * Remove initialization after installing cacheManager.
	 * This created problems of premature initialization,
	 * when not specified the name of realm, respectively,
	 * are generated nekkorektnye account with the name of the default realm,
	 * which then changed to the name specified in the config.
	 *
	 * @see org.apache.shiro.realm.AuthorizingRealm#afterCacheManagerSet()
	 */
	@Override
	protected void afterCacheManagerSet()
	{
		if (created)
		{
			super.afterCacheManagerSet();
		} else
		{
			setAuthorizationCache(null);
		}
	}
}
