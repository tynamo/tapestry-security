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
	 * <p/>
	 * <b>RU:</b>
	 * Ð£Ð±Ð¸Ñ€Ð°ÐµÐ¼ Ð¸Ð½Ð¸Ñ†Ð¸Ð°Ð»Ð¸Ð·Ð°Ñ†Ð¸ÑŽ Ð¿Ð¾Ñ�Ð»Ðµ ÑƒÑ�Ñ‚Ð°Ð½Ð¾Ð²ÐºÐ¸ cacheManager.
	 * Ñ�Ñ‚Ð¾ Ñ�Ð¾Ð·Ð´Ð°Ð²Ð°Ð»Ð¾ Ð¿Ñ€Ð¾Ð±Ð»ÐµÐ¼Ð¼Ñƒ Ð¿Ñ€ÐµÐ¶Ð´ÐµÐ²Ñ€ÐµÐ¼ÐµÐ½Ð½Ð¾Ð¹ Ð¸Ð½Ð¸Ñ†Ð¸Ð°Ð»Ð¸Ð·Ð°Ñ†Ð¸Ð¸,
	 * ÐºÐ¾Ð³Ð´Ð° ÐµÑ‰Ðµ Ð½Ðµ Ð·Ð°Ð´Ð°Ð½Ð¾ Ð¸Ð¼Ñ� realm, Ñ�Ð¾Ð¾Ñ‚Ð²ÐµÑ‚Ñ�Ñ‚Ð²ÐµÐ½Ð½Ð¾ Ñ�Ñ‚Ð¾ Ð¿Ð¾Ñ€Ð¾Ð¶Ð´Ð°Ð»Ð¾
	 * Ð½ÐµÐºÐºÐ¾Ñ€ÐµÐºÑ‚Ð½Ñ‹Ðµ Ð°ÐºÐºÐ°ÑƒÐ½Ñ‚Ñ‹ Ñ� Ð¸Ð¼ÐµÐ½ÐµÐ¼ realm Ð¿Ð¾ ÑƒÐ¼Ð¾Ð»Ñ‡Ð°Ð½Ð¸Ðµ, ÐºÐ¾Ñ‚Ð¾Ñ€Ð¾Ðµ Ð¿Ð¾Ñ‚Ð¾Ð¼ Ð¼ÐµÐ½Ñ�Ð»Ð¾Ñ�ÑŒ
	 * Ð½Ð° Ð¸Ð¼Ñ� Ð·Ð°Ð´Ð°Ð½Ð½Ð¾Ðµ Ð² ÐºÐ¾Ð½Ñ„Ð¸Ð³Ðµ.
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
