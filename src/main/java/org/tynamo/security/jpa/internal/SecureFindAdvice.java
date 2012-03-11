package org.tynamo.security.jpa.internal;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Join;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import javax.persistence.metamodel.Attribute;
import javax.persistence.metamodel.EntityType;
import javax.persistence.metamodel.Metamodel;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.Type;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.tynamo.security.jpa.annotations.Operation;
import org.tynamo.security.jpa.annotations.RequiresAssociation;
import org.tynamo.security.jpa.annotations.RequiresRole;
import org.tynamo.security.services.SecurityService;

public class SecureFindAdvice implements MethodAdvice {
	private SecurityService securityService;
	private HttpServletRequest request;

	public SecureFindAdvice(final SecurityService securityService, HttpServletRequest request) {
		this.securityService = securityService;
		this.request = request;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void advise(MethodInvocation invocation) {
		Class aClass = (Class) invocation.getParameter(0);
		RequiresRole requiresRole = (RequiresRole) aClass.getAnnotation(RequiresRole.class);
		boolean securedRoleAction = false;
		if (requiresRole != null) for (Operation action : requiresRole.operations()) {
			if (Operation.ANY.equals(action) || Operation.READ.equals(action)) securedRoleAction = true;
			break;
		}
		if (securedRoleAction && request.isUserInRole(requiresRole.value())) {
			invocation.proceed();
			return;
		}

		RequiresAssociation requiresAssociation = (RequiresAssociation) aClass.getAnnotation(RequiresAssociation.class);
		boolean securedAssociationAction = false;
		if (requiresAssociation != null) for (Operation action : requiresAssociation.operations()) {
			if (Operation.ANY.equals(action) || Operation.READ.equals(action)) securedAssociationAction = true;
			break;
		}

		if (!securedAssociationAction) {
			// proceed as normal if there's neither RequiresRole nor RequiresAssociation, directly return null if role didn't match
			if (!securedRoleAction) invocation.proceed();
			else invocation.setReturnValue(null);
			return;
		}
		EntityManager entityManager = (EntityManager) invocation.getInstance();
		// FIXME handle empty value, i.e. association to "self"
		String restrictionValue = requiresAssociation.value();
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<Object> criteriaQuery = builder.createQuery();
		Root<?> from = criteriaQuery.from(aClass);
		CriteriaQuery<Object> select = criteriaQuery.select(from);
		Metamodel metamodel = entityManager.getMetamodel();

		EntityType entityType = metamodel.entity(aClass);
		Type idType;
		SingularAttribute idAttr;

		Object entityId = invocation.getParameter(1);
		Predicate predicate1 = null;
		if (entityId != null) {
			idType = entityType.getIdType();
			idAttr = entityType.getId(idType.getJavaType());
			predicate1 = builder.equal(from.get(idAttr.getName()), invocation.getParameter(1));
		}
		Attribute association = entityType.getAttribute(restrictionValue);
		// TODO handle if !association.isAssociation()
		entityType = metamodel.entity(association.getJavaType());
		idType = entityType.getIdType();
		idAttr = entityType.getId(idType.getJavaType());

		Join<Object, Object> join = from.join(restrictionValue);
		// TODO handle subject == null
		// TODO allow configuring the principal for it rather than using primary
		Predicate predicate2 = builder.equal(join.get(idAttr.getName()), securityService.getSubject().getPrincipals()
			.getPrimaryPrincipal());
		criteriaQuery.where(predicate1 == null ? predicate2 : builder.and(predicate1, predicate2));
		invocation.setReturnValue(entityManager.createQuery(criteriaQuery).getSingleResult());
	}
}
