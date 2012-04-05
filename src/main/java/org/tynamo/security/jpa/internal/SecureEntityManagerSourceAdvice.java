package org.tynamo.security.jpa.internal;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.Symbol;
import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.tynamo.security.jpa.JpaSecuritySymbols;
import org.tynamo.security.services.SecurityService;

public class SecureEntityManagerSourceAdvice implements MethodAdvice {
	private final SecurityService securityService;
	private final PropertyAccess propertyAccess;
	private final HttpServletRequest request;
	private String realmName;
	private Class principalType;

	public SecureEntityManagerSourceAdvice(SecurityService securityService, PropertyAccess propertyAccess,
		HttpServletRequest request, @Inject @Symbol(JpaSecuritySymbols.ASSOCIATED_REALM) String realmName,
		@Inject @Symbol(JpaSecuritySymbols.ASSOCIATED_PRINCIPALTYPE) String principalType) throws ClassNotFoundException {
		this.securityService = securityService;
		this.propertyAccess = propertyAccess;
		this.request = request;
		this.realmName = realmName;
		this.principalType = principalType.isEmpty() ? null : Class.forName(principalType);
	}

	@Override
	public void advise(MethodInvocation invocation) {
		invocation.proceed();
		EntityManager entityManager = (EntityManager) invocation.getReturnValue();
		if (entityManager == null) return;
		invocation.setReturnValue(new SecureEntityManager(securityService, propertyAccess, request, entityManager,
			realmName, principalType));
	}

}
