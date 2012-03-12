package org.tynamo.security.jpa.internal;

import javax.persistence.EntityManager;
import javax.persistence.metamodel.Attribute;
import javax.persistence.metamodel.EntityType;
import javax.persistence.metamodel.Metamodel;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.Type;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.tynamo.security.jpa.EntitySecurityException;
import org.tynamo.security.jpa.annotations.Operation;
import org.tynamo.security.jpa.annotations.RequiresRole;
import org.tynamo.security.services.SecurityService;

public class SecurePersistAdvice implements MethodAdvice {
	private final SecurityService securityService;
	private final HttpServletRequest request;
	private final PropertyAccess propertyAccess;

	public SecurePersistAdvice(final SecurityService securityService, final HttpServletRequest request,
		final PropertyAccess propertyAccess) {
		this.securityService = securityService;
		this.request = request;
		this.propertyAccess = propertyAccess;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void advise(MethodInvocation invocation) {
		Class aClass = (Class) invocation.getParameter(0);
		RequiresRole requiresRole = (RequiresRole) aClass.getAnnotation(RequiresRole.class);
		String requiredRoleValue = RequiresAnnotationUtil.getRequiredRole(aClass, Operation.INSERT);

		if (requiredRoleValue != null && request.isUserInRole(requiredRoleValue)) {
			invocation.proceed();
			return;
		}

		String requiredAssociationValue = RequiresAnnotationUtil.getRequiredAssociation(aClass, Operation.INSERT);

		if (requiredAssociationValue == null) {
			// proceed as normal if there's neither RequiresRole nor RequiresAssociation, throw an exception if role didn't match
			if (requiredRoleValue != null) invocation.proceed();
			else throw new EntitySecurityException(
				"Currently executing subject is not permitted to persist entities of type " + aClass.getSimpleName());
		}
		EntityManager entityManager = (EntityManager) invocation.getInstance();

		// FIXME handle empty value, i.e. association to "self"
		Object associatedObject = propertyAccess.get(invocation.getParameter(0), requiredAssociationValue);

		Metamodel metamodel = entityManager.getMetamodel();
		EntityType entityType = metamodel.entity(aClass);
		Attribute association = entityType.getAttribute(requiredAssociationValue);
		entityType = metamodel.entity(association.getJavaType());
		Type idType = entityType.getIdType();
		SingularAttribute idAttr = entityType.getId(idType.getJavaType());
		if (!propertyAccess.get(associatedObject, idAttr.getName()).equals(
			securityService.getSubject().getPrincipals().getPrimaryPrincipal())) { throw new EntitySecurityException(
			"Currently executing subject is not permitted to persist entities of type " + aClass.getSimpleName()
				+ " because the required association didn't exist"); }
		invocation.proceed();
	}
}
