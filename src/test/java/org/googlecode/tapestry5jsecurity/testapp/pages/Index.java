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
package org.googlecode.tapestry5jsecurity.testapp.pages;

import org.apache.tapestry5.PersistenceConstants;
import org.apache.tapestry5.annotations.Persist;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.shiro.authz.annotation.RequiresAuthentication;

import org.googlecode.tapestry5jsecurity.services.SecurityService;
import org.googlecode.tapestry5jsecurity.testapp.services.AlphaService;
import org.googlecode.tapestry5jsecurity.testapp.services.BettaService;
import org.googlecode.tapestry5jsecurity.testapp.services.impl.Invoker;

public class Index {

	@Persist(PersistenceConstants.FLASH)
	private String result;
	
	@Inject
	private AlphaService alphaService;
	
	@Inject
	private BettaService bettaService;

	@Inject
	private SecurityService securityService;
	
	public String getStatus() {
		return securityService.isAuthenticated() ? "Authenticated" : "Not Authenticated";
	}
	
	@RequiresAuthentication
	public void onActionFromComponentMethodInterceptor() {
		result = Invoker.invoke(getClass());
	}
	
	public void onActionFromBettaServiceInvoke() {
        result = bettaService.invoke();
	}
	
	public void onActionFromAlphaServiceInvoke() {
		result = alphaService.invoke();
	}
	
	
	public void onActionFromAlphaServiceRequiresAuthentication() {
		result = alphaService.invokeRequiresAuthentication();
	}
	
	public void onActionFromAlphaServiceRequiresUser() {
		result = alphaService.invokeRequiresUser();
	}
	
	public void onActionFromAlphaServiceRequiresGuest() {
		result = alphaService.invokeRequiresGuest();
	}
	
	public void onActionFromAlphaServiceRequiresRolesUser() {
		result = alphaService.invokeRequiresRolesUser();
	}
	
	public void onActionFromAlphaServiceRequiresRolesManager() {
		result = alphaService.invokeRequiresRolesManager();
	}
	
	public void onActionFromAlphaServiceRequiresPermissionsNewsView() {
		result = alphaService.invokeRequiresPermissionsNewsView();
	}
	
	public void onActionFromAlphaServiceRequiresPermissionsNewsEdit() {
		result = alphaService.invokeRequiresPermissionsNewsEdit();
	}
	
	public void setResult(String result) {
		this.result = result;
	}

	public String getResult() {
		return result;
	}
	
}
