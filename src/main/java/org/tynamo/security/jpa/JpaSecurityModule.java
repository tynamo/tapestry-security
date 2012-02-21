package org.tynamo.security.jpa;

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
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

import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.annotations.Advise;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.tynamo.security.jpa.annotations.RequiresAssociation;

public class JpaSecurityModule {
	private static final MethodAdvice secureFindAdvice = new MethodAdvice() {
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

			// The following value should be the configured principal from subject
			Join<Object, Object> join = from.join(restrictionValue);
			Predicate predicate2 = builder.equal(join.get(idAttr.getName()), 0L);
			criteriaQuery.where(builder.and(predicate1, predicate2));
			List list = entityManager.createQuery(criteriaQuery).getResultList();
			invocation.setReturnValue(list.size() == 0 ? null : list.get(0));

		}

	};

	@Advise(serviceInterface = EntityManager.class)
	public static void secureFindOperations(MethodAdviceReceiver receiver) {
		for (final Method m : receiver.getInterface().getMethods()) {
			if (m.getName().startsWith("find")) receiver.adviseMethod(m, secureFindAdvice);
		}

	}

	/**
	 * Fetches the value of the given SingularAttribute on the given entity.
	 * 
	 * @see http://stackoverflow.com/questions/7077464/how-to-get-singularattribute-mapped-value-of-a-persistent-object
	 */
	@SuppressWarnings("unchecked")
	public static <EntityType, FieldType> FieldType getValue(EntityType entity,
		SingularAttribute<EntityType, FieldType> field) {
		try {
			Member member = field.getJavaMember();
			if (member instanceof Method) {
				// this should be a getter method:
				return (FieldType) ((Method) member).invoke(entity);
			} else if (member instanceof Field) {
				return (FieldType) ((Field) member).get(entity);
			} else {
				throw new IllegalArgumentException("Unexpected java member type. Expecting method or field, found: " + member);
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
