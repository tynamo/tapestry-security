package org.tynamo.security.testapp.pages;

import org.apache.tapestry5.annotations.PageActivationContext;
import org.apache.tapestry5.annotations.Property;
import org.tynamo.security.pages.Login;

public class LoginWithContext extends Login {
	@PageActivationContext
	@Property
	private String successURL;

}
