package org.tynamo.security.components;

import org.apache.tapestry5.Block;
import org.apache.tapestry5.annotations.Parameter;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.services.SecurityService;


/**
 * @see SecurityService#hasAnyPermissions(String)
 */
public class IfGranted
{

	//~ Instance fields ----------------------------------------------------------------------------

	/**
	 * Security service for doing our lookups
	 */
	@Inject
	private SecurityService securityService;

	/**
	 * Must have all of these permissions, separated by a |
	 */
	@Parameter(
			required = false,
			defaultPrefix = "literal"
	)
	private String allPermissions;

	/**
	 * Can have any of these permissions, separated by |
	 */
	@Parameter(
			required = false,
			defaultPrefix = "literal"
	)
	private String anyPermissions;

	/**
	 * Must have all of these roles, separated by , or |
	 */
	@Parameter(
			required = false,
			defaultPrefix = "literal"
	)
	private String allRoles;

	/**
	 * Can hav any of these roles, separated by , or |
	 */
	@Parameter(
			required = false,
			defaultPrefix = "literal"
	)
	private String anyRoles;

	/**
	 * Optional parameter to invert the test. If true, then the body is rendered when the test
	 * parameter is false (not true).
	 */
	@Parameter
	private boolean negate;

	/**
	 * An alternate {@link Block} to render if the test parameter is false. The default, null, means
	 * render nothing in that situation.
	 */
	@Parameter(name = "else")
	private Block elseBlock;

	/**
	 * DOCUMENT ME!
	 */
	private boolean test; // result of our security check.

	//~ Methods ------------------------------------------------------------------------------------

	/**
	 * True is the default. return true if all non-null expressions are satisfied.
	 *
	 * @return DOCUMENT ME!
	 */
	private boolean doCheck()
	{
		boolean check = true;

		if ((null != allPermissions) && !allPermissions.isEmpty())
		{

			if (!securityService.hasAllPermissions(allPermissions))
			{
				return false;
			}
		}

		if ((null != anyPermissions) && !anyPermissions.isEmpty())
		{

			if (!securityService.hasAnyPermissions(anyPermissions))
			{
				return false;
			}
		}

		if ((null != allRoles) && !allRoles.isEmpty())
		{

			if (!securityService.hasAllRoles(allRoles))
			{
				return false;
			}
		}

		if ((null != anyRoles) && !anyRoles.isEmpty())
		{

			if (!securityService.hasAnyRoles(anyRoles))
			{
				return false;
			}
		}

		return check;
	}

	/**
	 * DOCUMENT ME!
	 */
	void setupRender()
	{
		test = doCheck();
	}

	/**
	 * Returns null if the test method returns true, which allows normal rendering (of the body). If
	 * the test parameter is false, returns the else parameter (this may also be null).
	 *
	 * @return DOCUMENT ME!
	 */
	Object beginRender()
	{
		return (test != negate) ? null : elseBlock;
	}

	/**
	 * If the test method returns true, then the body is rendered, otherwise not. The component does
	 * not have a template or do any other rendering besides its body.
	 *
	 * @return DOCUMENT ME!
	 */
	boolean beforeRenderBody()
	{
		return test != negate;
	}
} // end class IfGranted
