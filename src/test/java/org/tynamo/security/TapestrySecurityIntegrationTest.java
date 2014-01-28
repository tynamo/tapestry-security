package org.tynamo.security;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;

import org.apache.tapestry5.json.JSONObject;
import org.eclipse.jetty.webapp.WebAppContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeGroups;
import org.testng.annotations.Test;
import org.tynamo.security.testapp.services.impl.Invoker;
import org.tynamo.test.AbstractContainerTest;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

public class TapestrySecurityIntegrationTest extends AbstractContainerTest
{

	private static final String STATUS_NOT_AUTH = "STATUS[Not Authenticated]";
	private static final String STATUS_AUTH = "STATUS[Authenticated]";
	private HtmlPage page;

	// masks the inherited field because that one is final (in model-test 0.1.0)
	private static String APP_HOST_PORT;
	private static String APP_CONTEXT;
	protected static String BASEURI;

	@Override
	@BeforeClass
	public void configureWebClient()
	{
		APP_HOST_PORT = "http://localhost:" + port;
		APP_CONTEXT = "/test/";
		BASEURI = APP_HOST_PORT + APP_CONTEXT;
		webClient.setThrowExceptionOnFailingStatusCode(false);
	}

	@Override
	public WebAppContext buildContext()
	{
		WebAppContext context = new WebAppContext("src/test/webapp", "/test");
		/*
		 * Sets the classloading model for the context to avoid an strange "ClassNotFoundException: org.slf4j.Logger"
		 */
		context.setParentLoaderPriority(true);
		return context;
	}


	@BeforeGroups(groups = "notLoggedIn")
	public void checkLoggedIn() throws Exception
	{
		openBase();

		if (STATUS_AUTH.equals(getText("status")))
		{
			clickOnBasePage("tynamoLogout");
		}
	}

	//------------------------------------------------------
	// Not logged in
	//------------------------------------------------------


	//----------------------------------------
	// Testing interceptors works deny
	//----------------------------------------
	@Test(groups = {"notLoggedIn"})
	public void testInterceptServiceMethodDeny() throws Exception
	{
		clickOnBasePage("alphaServiceInvoke");
		assertLoginPage();
	}

	public void testInterceptServiceMethodWithSecurityDisabled() throws Exception
	{
		clickOnBasePage("alphaServiceInvokeWithSecurityDisabled");
		assertSuccessInvoke();
	}

	@Test(groups = {"notLoggedIn"})
	public void testInterceptServiceClassDeny() throws Exception
	{
		clickOnBasePage("betaServiceInvoke");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testInterceptComponentMethodDeny() throws Exception
	{
		clickOnBasePage("componentMethodInterceptor");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testInterceptComponentMethodWithAjaxDeny() throws Exception
	{
		clickOnBasePage("componentMethodInterceptorWithAjax");
		// this executes window.location.replace so we have to wait for it. is there an event we could listen instead?
		webClient.waitForBackgroundJavaScript(500);
		page = (HtmlPage) webClient.getCurrentWindow().getEnclosedPage();
		assertLoginPage();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testComponentMethodInterceptorRequiresPermissionsILACSuccess() throws Exception
	{
		clickOnBasePage("componentMethodInterceptorRequiresPermissionsILACSuccess");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testComponentMethodInterceptorRequiresPermissionsILACUnauthorized() throws Exception
	{
		clickOnBasePage("componentMethodInterceptorRequiresPermissionsILACUnauthorized");
		assertUnauthorizedPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testInterceptComponentClassDeny() throws Exception
	{
		clickOnBasePage("about");
		assertLoginPage();
	}
	//----------------------------------------


	//----------------------------------------
	// Testing annotation types handlers
	//----------------------------------------
	@Test(groups = {"notLoggedIn"})
	public void testRequiresAuthenticationDeny() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresAuthentication");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testRequiresUserDeny() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresUser");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testRequiresGuestAccess() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresGuest");
		assertSuccessInvoke();
	}

	@Test(groups = {"notLoggedIn"})
	public void testRequiresRole() throws Exception
	{
		clickOnBasePage("tynamoLoginLink");
		type("tynamoLogin", "student");
		type("tynamoPassword", "student");
		click("tynamoEnter");
		clickOnBasePage("annotated");
		assertUnauthorizedPage();
		clickOnBasePage("tynamoLogoutLink");
	}

	//----------------------------------------


	//----------------------------------------
	// Testing filters works
	//----------------------------------------
	@Test(groups = {"notLoggedIn"})
	public void testAnonFilterAccess() throws Exception
	{
		clickOnBasePage("authcSignup");
		assertSuccessInvoke();

		clickOnBasePage("userSignup");
		assertSuccessInvoke();
	}

	@Test(groups = {"notLoggedIn"})
	public void testUserFilterDeny() throws Exception
	{
		clickOnBasePage("userCabinet");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testUserFilterWithAjaxDeny() throws Exception
	{
		clickOnBasePage("tynamoLoginLink");
		loginAction();
		clickOnBasePage("contributed");
		// now go log out in a different "window"
		HtmlPage indexPage = webClient.getPage(BASEURI);
		indexPage.getHtmlElementById("tynamoLogoutLink").click();

                // Clicking on this link should make an ajax request, but HTMLUnit doesn't like it and sends a non-ajax request
		HtmlElement ajaxLink = (HtmlElement) page.getElementById("ajaxLink");
                URL ajaxUrl = new URL(APP_HOST_PORT + ajaxLink.getAttribute("href"));
                WebRequest ajaxRequest = new WebRequest(ajaxUrl);
                ajaxRequest.setAdditionalHeader("X-Requested-With", "XMLHttpRequest");

                Page jsonLoginResponse  = webClient.getPage(ajaxRequest);
                String ajaxLoginResp = jsonLoginResponse.getWebResponse().getContentAsString();
                JSONObject jsonResp = new JSONObject(ajaxLoginResp);
                String ajaxRedirectUrl = jsonResp.getJSONObject("_tapestry").getString("redirectURL");
                assertTrue(ajaxRedirectUrl.contains(APP_CONTEXT), "The ajax redirect response '" + ajaxRedirectUrl + "' did not contain app context '" + APP_CONTEXT+"'");
                page = webClient.getPage(APP_HOST_PORT+ajaxRedirectUrl);
                assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testLocalizedUserFilterDeny() throws Exception
	{
		// this test can fail either if acl rules don't correctly handle path matching with the requested locale,
		// or that resulting login page is not correctly localized anymore (requested locale is lost)
		openPage("fi_FI/authc/cabinet");
		assertLoginPage();
		page.getElementById("tynamoEnter").asText().contains("Kirjaudu sisään");
	}

	@Test(groups = {"notLoggedIn"})
	public void testNotFoundRule() throws Exception
	{
		openPage("hidden/something");
		assertEquals(404, page.getWebResponse().getStatusCode());
	}

	@Test(groups = {"notLoggedIn"})
	public void testNoContextPathHandling() throws Exception
	{
		// without security, should actually give you the index page since there's no 'user' page
		openPage("user");
		assertLoginPage();
		openPage("user#test");
		assertLoginPage();
		openPage("user?test");
		assertLoginPage();
		openPage("user/");
		assertLoginPage();
	}



	@Test(groups = {"notLoggedIn"})
	public void testAuthcFilterDeny() throws Exception
	{
		clickOnBasePage("authcCabinet");
		assertLoginPage();
		// test case insensitive access
		openPage("authC/cabinet");
		assertLoginPage();
	}

	@Test(groups = {"notLoggedIn"})
	public void testContributedFilterChainDefinitionNotLoggedIn() throws Exception
	{
		clickOnBasePage("contributed");
		assertLoginPage();
	}

	//----------------------------------------


	//----------------------------------------
	// Testing components works
	//----------------------------------------
	@Test(groups = {"notLoggedIn"})
	public void testAuthenticatedComponentNotLoggedIn() throws Exception
	{
		openBase();
		if (isElementPresent("AuthenticatedComponent"))
		{
			throw new AssertionError("Authenticated component can't be present");
		}
	}

	@Test(groups = {"notLoggedIn"})
	public void testNotAuthenticatedComponentNotLoggedIn() throws Exception
	{
		openBase();
		assertText("NotAuthenticatedComponent", "NotAuthenticatedComponent - RENDERED");
	}

	@Test(groups = {"notLoggedIn"})
	public void testUserComponentNotLoggedIn() throws Exception
	{
		openBase();
		if (isElementPresent("UserComponent"))
		{
			throw new AssertionError("User component can't be present");
		}
	}

	@Test(groups = {"notLoggedIn"})
	public void testGuestComponentNotLoggedIn() throws Exception
	{
		openBase();
		assertText("GuestComponent", "GuestComponent - RENDERED");
	}
	//----------------------------------------


	@Test(dependsOnGroups = {"notLoggedIn"})
	public void testLoginClick() throws Exception
	{
		clickOnBasePage("tynamoLoginLink");
		assertLoginPage();
	}

	@Test(dependsOnMethods = "testLoginClick")
	public void testLogin() throws Exception
	{
		loginAction();
		openBase();
		assertAuthenticated();
	}


	//------------------------------------------------------
	// Logged In
	//------------------------------------------------------


	//----------------------------------------
	// Testing interceptors works access
	//----------------------------------------
	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testInterceptServiceMethodAccess() throws Exception
	{
		clickOnBasePage("alphaServiceInvoke");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testInterceptServiceClassAccess() throws Exception
	{
		clickOnBasePage("betaServiceInvoke");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testInterceptComponentMethodAccess() throws Exception
	{
		clickOnBasePage("componentMethodInterceptor");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testInterceptComponentClassAccess() throws Exception
	{
		clickOnBasePage("about");
		assertSuccessInvoke();
	}
	//----------------------------------------


	//----------------------------------------
	// Testing annotation types handlers
	//----------------------------------------
	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresAuthenticationAccess() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresAuthentication");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresUserAccess() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresUser");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresGuestDeny() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresGuest");
		assertUnauthorizedPage();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresRoleAccess() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresRolesUser");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresRoleDeny() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresRolesManager");
		assertUnauthorizedPage();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresPermissionAccess() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresPermissionsNewsView");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresPermissionDeny() throws Exception
	{
		clickOnBasePage("alphaServiceRequiresPermissionsNewsEdit");
		assertUnauthorizedPage();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresPermissionILACSuccessWithoutArguments() throws Exception
	{
		clickOnBasePage("gammaServiceRequiresPermissionsILACSuccessWithoutArguments");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresPermissionILACSuccessWithArgument() throws Exception
	{
		clickOnBasePage("gammaServiceRequiresPermissionsILACSuccessWithArgument");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRequiresPermissionILACUnauthorizedWithArgument() throws Exception
	{
		clickOnBasePage("gammaServiceRequiresPermissionsILACUnauthorizedWithArgument");
		assertUnauthorizedPage();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testPermsRequiresPermissionsILACViewOnPageClass() throws Exception
	{
		clickOnBasePage("permILACView");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testPermsRequiresPermissionsILACEditOnPageClass() throws Exception
	{
		clickOnBasePage("permILACEdit");
		assertUnauthorizedPage();
	}

	//----------------------------------------


	//----------------------------------------
	// Testing filters works
	//----------------------------------------
	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testUserFilterAccess() throws Exception
	{
		clickOnBasePage("userCabinet");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testAuthcFilterAccess() throws Exception
	{
		clickOnBasePage("authcCabinet");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRolesFilterDeny() throws Exception
	{
		clickOnBasePage("rolesManager");
//		assertUnauthorizedPage();
		// FIXME What determines which one gets returned?
		assertUnauthorizedPage401();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testRolesFilterAccess() throws Exception
	{
		clickOnBasePage("rolesUser");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testPermsFilterDeny() throws Exception
	{
		clickOnBasePage("permEdit");
		// assertUnauthorizedPage();
		// FIXME What determines which one gets returned?
		assertUnauthorizedPage401();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testPermsFilterAccess() throws Exception
	{
		clickOnBasePage("permView");
		assertSuccessInvoke();
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testContributedFilterChainDefinition() throws Exception
	{
		clickOnBasePage("contributed");
		assertEquals("contribution success", page.getTitleText());
	}

	//----------------------------------------


	//----------------------------------------
	// Testing components works
	//----------------------------------------
	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testAuthenticatedComponentLoggedIn() throws Exception
	{
		openBase();
		assertText("AuthenticatedComponent", "AuthenticatedComponent - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testNotAuthenticatedComponentLoggedIn() throws Exception
	{
		openBase();
		if (isElementPresent("NotAuthenticatedComponent"))
		{
			throw new AssertionError("NotAuthenticated component can't be present");
		}
		// assertTrue(isElementPresent("NotAuthenticatedComponentElse"));
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testUserComponentLoggedIn() throws Exception
	{
		openBase();
		assertText("UserComponent", "UserComponent - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testGuestComponentLoggedIn() throws Exception
	{
		openBase();
		if (isElementPresent("GuestComponent"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyRolesComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasAnyRolesComponentSuccess", "HasAnyRolesComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyRolesComponentSuccessAlternateDivisor() throws Exception
	{
		openBase();
		assertText("HasAnyRolesComponentSuccessAlternateDivisor", "HasAnyRolesComponentSuccessAlternateDivisor - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyRolesComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasAnyRolesComponentFailed"))
		{
			throw new AssertionError("HasAnyRoles component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyRoleComponentFailedAlternateDivisor() throws Exception
	{
		openBase();
		if (isElementPresent("HasAnyRolesComponentFailedAlternateDivisor"))
		{
			throw new AssertionError("HasAnyRole component can't be present");
		}
	}


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllRolesComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasAllRolesComponentSuccess", "HasAllRolesComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllRolesComponentSuccessAlternateDivisor() throws Exception
	{
		openBase();
		assertText("HasAllRolesComponentSuccessAlternateDivisor", "HasAllRolesComponentSuccessAlternateDivisor - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllRolesComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasAllRolesComponentFailed"))
		{
			throw new AssertionError("HasAllRoles component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllRolesComponentFailedAlternateDivisor() throws Exception
	{
		openBase();
		if (isElementPresent("HasAllRolesComponentFailedAlternateDivisor"))
		{
			throw new AssertionError("HasAllRoles component can't be present");
		}
	}


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasPermissionComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasPermissionComponentSuccess", "HasPermissionComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasPermissionComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasPermissionComponentFailed"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyPermissionsComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasAnyPermissionsComponentSuccess", "HasAnyPermissionsComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAnyPermissionsComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasAnyPermissionsComponentFailed"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllPermissionsComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasAllPermissionsComponentSuccess", "HasAllPermissionsComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasAllPermissionsComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasAllPermissionsComponentFailed"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasRoleComponentSuccess() throws Exception
	{
		openBase();
		assertText("HasRoleComponentSuccess", "HasRoleComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testHasRoleComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("HasRoleComponentFailed"))
		{
			throw new AssertionError("Role component can't be present");
		}
	}

	// new granted tests

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyPermissionsComponentSuccess() throws Exception
	{
		openBase();
		assertText("IfGrantedAnyPermissionsComponentSuccess", "IfGrantedAnyPermissionsComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyPermissionsComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAnyPermissionsComponentFailed"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllPermissionsComponentSuccess() throws Exception
	{
		openBase();
		assertText("IfGrantedAllPermissionsComponentSuccess", "IfGrantedAllPermissionsComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllPermissionsComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAllPermissionsComponentFailed"))
		{
			throw new AssertionError("Guest component can't be present");
		}
	}


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyRolesComponentSuccess() throws Exception
	{
		openBase();
		assertText("IfGrantedAnyRolesComponentSuccess", "IfGrantedAnyRolesComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyRolesComponentSuccessAlternateDivisor() throws Exception
	{
		openBase();
		assertText("IfGrantedAnyRolesComponentSuccessAlternateDivisor", "IfGrantedAnyRolesComponentSuccessAlternateDivisor - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyRolesComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAnyRolesComponentFailed"))
		{
			throw new AssertionError("IfGrantedAnyRoles component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAnyRoleComponentFailedAlternateDivisor() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAnyRolesComponentFailedAlternateDivisor"))
		{
			throw new AssertionError("IfGrantedAnyRole component can't be present");
		}
	}


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllRolesComponentSuccess() throws Exception
	{
		openBase();
		assertText("IfGrantedAllRolesComponentSuccess", "IfGrantedAllRolesComponentSuccess - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllRolesComponentSuccessAlternateDivisor() throws Exception
	{
		openBase();
		assertText("IfGrantedAllRolesComponentSuccessAlternateDivisor", "IfGrantedAllRolesComponentSuccessAlternateDivisor - RENDERED");
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllRolesComponentFailed() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAllRolesComponentFailed"))
		{
			throw new AssertionError("IfGrantedAllRoles component can't be present");
		}
	}

	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testIfGrantedAllRolesComponentFailedAlternateDivisor() throws Exception
	{
		openBase();
		if (isElementPresent("IfGrantedAllRolesComponentFailedAlternateDivisor"))
		{
			throw new AssertionError("IfGrantedAllRoles component can't be present");
		}
	}

	//----------------------------------------


	@Test(dependsOnGroups = {"loggedIn"})
	public void testLogout() throws Exception
	{
		clickOnBasePage("tynamoLogoutLink");
		assertNotAuthenticated();
	}

	@Test(dependsOnMethods = {"testLogout"})
	public void testSaveRequestAnnotationHandler() throws Exception
	{
		clickOnBasePage("about");
		assertLoginPage();
		loginAction();
		assertTrue(getLocation().startsWith(BASEURI + "about"), "Request wasn't redirected to the remembered url");
	}

	public void testSaveRequestWithFallbackUri() throws Exception
	{
		clickOnBasePage("tynamoLogoutLink");
		CookieManager cookieManager = webClient.getCookieManager();
		cookieManager.clearCookies();
		boolean original = cookieManager.isCookiesEnabled();
		cookieManager.setCookiesEnabled(false);
		clickOnBasePage("about");
		assertLoginPage();
		loginAction();
		assertTrue(getLocation().startsWith(BASEURI + "index"), "Request wasn't redirected to the default success url");
		cookieManager.setCookiesEnabled(original);
	}


// the following test *does not* work because of deficiency in htmlunit itself. The request parameters however are saved
// see	http://old.nabble.com/Problem-with-WebRequestSettings.getRequestParameters%28%29-td20167941.html
// htmlunit's current implementation only returns what's added with setRequestParameters()
//	@Test(dependsOnMethods = {"testLogout"})
//	public void testSaveRequestWithParameters() throws Exception
//	{
//		openPage("about?test=now");
//		assertLoginPage();
//		loginAction();
//		assertTrue(getLocation().startsWith(BASEURI + "about"), "Request wasn't redirected to the remebered url");
//		List<NameValuePair> valuePairs = page.getWebResponse().getRequestSettings().getRequestParameters();
//		assertTrue(valuePairs.contains(new NameValuePair("test", "now")), "Request parameters weren't remebered");
//	}

	public void testSaveRequestFilter() throws Exception
	{
		clickOnBasePage("tynamoLogoutLink");
		clickOnBasePage("authcCabinet");
		assertLoginPage();
		loginAction();
		assertTrue(getLocation().startsWith(BASEURI + "authc/cabinet"), "Request wasn't redirected to the remebered url");
	}

	@Test
	public void testPort8180Filter() throws Exception
	{
		openBase();
		clickOnBasePage("port8180");
		assertSuccessInvoke();
	}

//	@Test
	public void testPort9090Filter() throws Exception
	{
		openBase();
		try {
			clickOnBasePage("port9090");
			fail("ConnectException expected");
		} catch (RuntimeException e) {
			assertEquals(e.getCause().getClass(), ConnectException.class);
			assertEquals(e.getCause().getMessage(), "Connection refused");
		}
	}

//	@Test
	public void testSslFilter() throws Exception
	{
		openBase();
		try {
			clickOnBasePage("ssl");
			fail("ConnectException expected");
		} catch (RuntimeException e) {
			assertEquals(e.getCause().getClass(), ConnectException.class);
			assertEquals(e.getCause().getMessage(), "Connection refused");
		}
	}


	protected void assertLoginPage()
	{
		assertNotNull(page.getElementById("tynamoLogin"), "Page doesn't contain login field. Not a login page.");
		assertEquals("password", getAttribute("tynamoPassword", "type"),
				"Page doesn't contain password field. Not a login page.");
		assertEquals("checkbox", getAttribute("tynamoRememberMe", "type"),
				"Page doesn't contain rememberMe field. Not a login page.");

		assertNotNull(page.getElementById("tynamoEnter"), "Page doesn't contain login form submit button. Not a login page.");
	}

// -----------------------


	@Test(groups = {"loggedIn"}, dependsOnMethods = {"testLogin"})
	public void testServletDecoration() throws Exception
	{
		clickOnBasePage("contributed");
		assertText("remoteUser", "psycho");
		assertText("userPrincipal", "psycho");
		assertText("userInRoleUser", "true");
		assertText("userInRoleManager", "false");
	}

	private String getAttribute(String id, String attr)
	{
		return page.getElementById(id).getAttribute(attr);
	}

	protected void assertUnauthorizedPage()
	{
		assertEquals(getTitle(), "Unauthorized", "Not Unauthorized page");
	}

	protected void assertUnauthorizedPage401()
	{
		assertEquals(getTitle(), "Error 401 Unauthorized", "Not Unauthorized page");
	}

	protected void openPage(String url) throws Exception
	{
		page = webClient.getPage(BASEURI + url);
	}

	protected void openBase() throws Exception
	{
		openPage("");
	}

	protected void clickOnBasePage(String url) throws Exception
	{
		openBase();
		page = page.getHtmlElementById(url).click();
	}

	protected void assertSuccessInvoke()
	{
		assertTrue(getText("result").contains(Invoker.SUCCESS_SUFFIX), "Method invocation unsuccessfully");
	}


	protected void assertAuthenticated()
	{
		assertEquals(getText("status"), STATUS_AUTH);
	}

	protected void assertNotAuthenticated()
	{
		assertEquals(getText("status"), STATUS_NOT_AUTH);
	}

	protected void loginAction() throws IOException
	{
		type("tynamoLogin", "psycho");
		type("tynamoPassword", "psycho");
		click("tynamoEnter");
	}

	private void type(String id, String value)
	{
		page.getForms().get(0).<HtmlInput>getInputByName(id).setValueAttribute(value);
	}

	private void click(String id) throws IOException
	{
		page = clickButton(page, id);
	}

	private String getText(String id)
	{
		return page.getElementById(id).asText();
	}


	private void assertText(String id, String text)
	{
		assertEquals(page.getElementById(id).asText(), text);
	}

	private boolean isElementPresent(String id)
	{
		return page.getElementById(id) != null;
	}


	private String getTitle()
	{
		return page.getTitleText();
	}

	private String getLocation()
	{
		return page.getWebResponse().getWebRequest().getUrl().toString();
	}

}
