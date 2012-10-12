package org.tynamo.security.testapp.services.ilac;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.services.Environment;

public final class TestModule
{
	public static void bind(ServiceBinder binder)
	{
		binder.bind(GammaService.class, GammaServiceImpl.class);
	}
	
	public static void contributeWebSecurityManager(Configuration<Realm> configuration, 
			final Environment environment)
	{
		AuthorizingRealm realm = new AuthorizingRealm() {
			
			@SuppressWarnings("unchecked")
			@Override
			public boolean isPermitted(PrincipalCollection principals, Permission permission)
			{
				if (!(permission instanceof WildcardPermission))
				{
					return false;
				}
				
				List<Set<String>> parts = null;
				
				Method method = null;
				
				try {
					method = permission.getClass().getDeclaredMethod("getParts");
					method.setAccessible(true);
					parts = (List<Set<String>>) method.invoke(permission);
					if (!parts.get(0).contains("ilac"))
					{
						return false;
					}
				}
				catch (Exception e)
				{
					throw new RuntimeException(e);
				}
				finally
				{
					if (method != null)
					{
						method.setAccessible(false);
					}
				}
				
				MethodInvocation methodInvocation = environment.peek(MethodInvocation.class);
				
				if (parts.get(1).contains("view"))
				{
					//	allow 'ilac:view' for this test domain
					
					if (methodInvocation != null)
					{
						throw new RuntimeException("Method invocation should be null since permission check was not originated from advised service");
					}
					
					return true;
				}
				
				if (methodInvocation == null)
				{
					return false;
				}
				
				if (methodInvocation.getMethod().getParameterTypes().length == 0)
				{
					//	For this test domain allow invocations of all methods without arguments
					return true;
				}
				
				Object param0 = methodInvocation.getParameter(0);
				
				return param0 != null && param0.equals("allow");
			}
			
			protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
					throws AuthenticationException
			{
				//	Not necessary for this test domain
				return null;
			}
			
			protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
			{
				//	Not necessary for this test domain
				return null;
			}
		};
		
		configuration.add(realm);
	}

}