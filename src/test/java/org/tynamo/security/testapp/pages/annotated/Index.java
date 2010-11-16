package org.tynamo.security.testapp.pages.annotated;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.tynamo.security.testapp.pages.AccessiblePage;

@RequiresRoles("user")
public class Index extends AccessiblePage {

}
