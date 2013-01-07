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
package org.tynamo.security.testapp.pages;

import java.util.concurrent.Callable;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.tapestry5.PersistenceConstants;
import org.apache.tapestry5.annotations.InjectComponent;
import org.apache.tapestry5.annotations.Persist;
import org.apache.tapestry5.corelib.components.Zone;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;
import org.tynamo.security.testapp.services.AlphaService;
import org.tynamo.security.testapp.services.BetaService;
import org.tynamo.security.testapp.services.ilac.GammaService;
import org.tynamo.security.testapp.services.impl.Invoker;

public class Index {

	@Persist(PersistenceConstants.FLASH)
	private String result;

	@Inject
	private AlphaService alphaService;

	@Inject
	private BetaService betaService;

	@Inject
	private GammaService gammaService;

	@Inject
	private SecurityService securityService;

	public String getStatus() {
		return securityService.isAuthenticated() ? "Authenticated" : "Not Authenticated";
	}

	@RequiresAuthentication
	public void onActionFromComponentMethodInterceptor() {
		result = Invoker.invoke(getClass());
	}

	@InjectComponent
	private Zone targetZone;

	@RequiresAuthentication
	public Object onActionFromComponentMethodInterceptorWithAjax() {
		result = Invoker.invoke(getClass());
		return targetZone.getBody();
	}

	@RequiresPermissions("ilac:action2")
	public void onComponentMethodInterceptorRequiresPermissionsILAC(String param)
	{
		result = Invoker.invoke(getClass());
	}

	public void onActionFromBetaServiceInvoke() {
        result = betaService.invoke();
	}

	public void onActionFromAlphaServiceInvoke() {
		result = alphaService.invoke();
	}

	public void onActionFromAlphaServiceInvokeWithSecurityDisabled() throws Exception {
		result = securityService.invokeWithSecurityDisabled(new Callable<String>() {
			@Override
			public String call() throws Exception {
				return alphaService.invoke();
			}
		});
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

	public void onActionFromGammaServiceRequiresPermissionsILACSuccessWithArgument() {
		result = gammaService.invokeRequiresPermissionsILACSuccessIfArgumentAllows("allow");
	}

	public void onActionFromGammaServiceRequiresPermissionsILACUnauthorizedWithArgument() {
		result = gammaService.invokeRequiresPermissionsILACSuccessIfArgumentAllows("deny");
	}

	public void onActionFromGammaServiceRequiresPermissionsILACSuccessWithoutArguments() {
		result = gammaService.invokeRequiresPermissionsILACSuccessWithoutArguments();
	}

	public void setResult(String result) {
		this.result = result;
	}

	public String getResult() {
		return result;
	}

}
