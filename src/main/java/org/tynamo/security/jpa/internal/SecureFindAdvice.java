package org.tynamo.security.jpa.internal;

import java.util.List;

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

import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.tynamo.security.jpa.annotations.RequiresAssociation;
import org.tynamo.security.services.SecurityService;

public class SecureFindAdvice implements MethodAdvice {
	private SecurityService securityService;

	public SecureFindAdvice(final SecurityService securityService) {
		this.securityService = securityService;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void advise(MethodInvocation invocation) {
		Class aClass = (Class) invocation.getParameter(0);
		RequiresAssociation requiresAssociation = (RequiresAssociation) aClass.getAnnotation(RequiresAssociation.class);
		if (requiresAssociation == null) {
			invocation.proceed();
			return;
		}
		EntityManager entityManager = (EntityManager) invocation.getInstance();
		String restrictionValue = requiresAssociation.value();
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<Object> criteriaQuery = builder.createQuery();
		Root<?> from = criteriaQuery.from(aClass);
		CriteriaQuery<Object> select = criteriaQuery.select(from);
		Metamodel metamodel = entityManager.getMetamodel();
		EntityType entityType = metamodel.entity(aClass);
		Type idType = entityType.getIdType();
		SingularAttribute idAttr = entityType.getId(idType.getJavaType());

		Predicate predicate1 = builder.equal(from.get(idAttr.getName()), invocation.getParameter(1));

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
		criteriaQuery.where(builder.and(predicate1, predicate2));
		List list = entityManager.createQuery(criteriaQuery).getResultList();
		invocation.setReturnValue(list.size() == 0 ? null : list.get(0));

	}
}
