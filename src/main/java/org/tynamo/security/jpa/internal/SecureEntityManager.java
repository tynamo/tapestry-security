package org.tynamo.security.jpa.internal;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.FlushModeType;
import javax.persistence.GeneratedValue;
import javax.persistence.LockModeType;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
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

import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.tynamo.security.jpa.EntitySecurityException;
import org.tynamo.security.jpa.annotations.Operation;
import org.tynamo.security.jpa.annotations.RequiresAssociation;
import org.tynamo.security.services.SecurityService;

public class SecureEntityManager implements EntityManager {
	private final EntityManager delegate;
	private final SecurityService securityService;
	private final HttpServletRequest request;
	private final PropertyAccess propertyAccess;

	public SecureEntityManager(final SecurityService securityService, final PropertyAccess propertyAccess,
		final HttpServletRequest request, final EntityManager delegate) {
		this.securityService = securityService;
		this.propertyAccess = propertyAccess;
		this.request = request;
		this.delegate = delegate;
	}

	public void clear() {
		delegate.clear();
	}

	public void close() {
		delegate.close();
	}

	public boolean contains(Object arg0) {
		return delegate.contains(arg0);
	}

	public <T> TypedQuery<T> createNamedQuery(String arg0, Class<T> arg1) {
		return delegate.createNamedQuery(arg0, arg1);
	}

	public Query createNamedQuery(String arg0) {
		return delegate.createNamedQuery(arg0);
	}

	public Query createNativeQuery(String arg0, Class arg1) {
		return delegate.createNativeQuery(arg0, arg1);
	}

	public Query createNativeQuery(String arg0, String arg1) {
		return delegate.createNativeQuery(arg0, arg1);
	}

	public Query createNativeQuery(String arg0) {
		return delegate.createNativeQuery(arg0);
	}

	public <T> TypedQuery<T> createQuery(CriteriaQuery<T> arg0) {
		return delegate.createQuery(arg0);
	}

	public <T> TypedQuery<T> createQuery(String arg0, Class<T> arg1) {
		return delegate.createQuery(arg0, arg1);
	}

	public Query createQuery(String arg0) {
		return delegate.createQuery(arg0);
	}

	public void detach(Object arg0) {
		delegate.detach(arg0);
	}

	public <T> T find(Class<T> entityClass, Object primaryKey, LockModeType lockMode, Map<String, Object> properties) {
		return secureFind(entityClass, primaryKey, lockMode, properties);
	}

	public <T> T find(Class<T> entityClass, Object primaryKey, LockModeType lockMode) {
		return secureFind(entityClass, primaryKey, lockMode, null);
	}

	public <T> T find(Class<T> entityClass, Object primaryKey, Map<String, Object> properties) {
		return secureFind(entityClass, primaryKey, null, properties);
	}

	public <T> T find(Class<T> entityClass, Object primaryKey) {
		return secureFind(entityClass, primaryKey, null, null);
	}

	public void flush() {
		delegate.flush();
	}

	public CriteriaBuilder getCriteriaBuilder() {
		return delegate.getCriteriaBuilder();
	}

	public Object getDelegate() {
		return delegate.getDelegate();
	}

	public EntityManagerFactory getEntityManagerFactory() {
		return delegate.getEntityManagerFactory();
	}

	public FlushModeType getFlushMode() {
		return delegate.getFlushMode();
	}

	public LockModeType getLockMode(Object arg0) {
		return delegate.getLockMode(arg0);
	}

	public Metamodel getMetamodel() {
		return delegate.getMetamodel();
	}

	public Map<String, Object> getProperties() {
		return delegate.getProperties();
	}

	public <T> T getReference(Class<T> arg0, Object arg1) {
		return delegate.getReference(arg0, arg1);
	}

	public EntityTransaction getTransaction() {
		return delegate.getTransaction();
	}

	public boolean isOpen() {
		return delegate.isOpen();
	}

	public void joinTransaction() {
		delegate.joinTransaction();
	}

	public void lock(Object arg0, LockModeType arg1, Map<String, Object> arg2) {
		delegate.lock(arg0, arg1, arg2);
	}

	public void lock(Object arg0, LockModeType arg1) {
		delegate.lock(arg0, arg1);
	}

	public <T> T merge(T entity) {
		checkWritePermissions(entity, Operation.UPDATE);
		return delegate.merge(entity);
	}

	public void persist(Object entity) {
		checkWritePermissions(entity, Operation.INSERT);
		delegate.persist(entity);
	}

	public void refresh(Object arg0, LockModeType arg1, Map<String, Object> arg2) {
		delegate.refresh(arg0, arg1, arg2);
	}

	public void refresh(Object arg0, LockModeType arg1) {
		delegate.refresh(arg0, arg1);
	}

	public void refresh(Object arg0, Map<String, Object> arg1) {
		delegate.refresh(arg0, arg1);
	}

	public void refresh(Object arg0) {
		delegate.refresh(arg0);
	}

	public void remove(Object entity) {
		checkWritePermissions(entity, Operation.DELETE);
		delegate.remove(entity);
	}

	public void setFlushMode(FlushModeType arg0) {
		delegate.setFlushMode(arg0);
	}

	public void setProperty(String arg0, Object arg1) {
		delegate.setProperty(arg0, arg1);
	}

	public <T> T unwrap(Class<T> arg0) {
		return delegate.unwrap(arg0);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private <T> T secureFind(Class<T> entityClass, Object entityId, LockModeType lockMode, Map<String, Object> properties) {
		if (!securityService.getSubject().isAuthenticated()) return null;

		String requiredRoleValue = RequiresAnnotationUtil.getRequiredRole(entityClass, Operation.READ);

		if (requiredRoleValue != null && request.isUserInRole(requiredRoleValue))
			return delegate.find(entityClass, entityId, lockMode, properties);

		String requiredAssociationValue = RequiresAnnotationUtil.getRequiredAssociation(entityClass, Operation.READ);

		if (requiredAssociationValue == null) {
			// proceed as normal if there's neither RequiresRole nor RequiresAssociation, directly return null if role didn't match
			if (requiredRoleValue != null) return null;
			if (entityId != null) return delegate.find(entityClass, entityId, lockMode, properties);
			// even if assocation is not required for read, we can still use it to find the entity
			RequiresAssociation annotation = entityClass.getAnnotation(RequiresAssociation.class);
			if (annotation == null) return null;
			requiredAssociationValue = annotation.value();
		}

		CriteriaBuilder builder = delegate.getCriteriaBuilder();
		CriteriaQuery<Object> criteriaQuery = builder.createQuery();
		Root<?> from = criteriaQuery.from(entityClass);
		CriteriaQuery<Object> select = criteriaQuery.select(from);
		Metamodel metamodel = delegate.getMetamodel();

		EntityType entityType = metamodel.entity(entityClass);
		Type idType;
		SingularAttribute idAttr;
		Predicate predicate2 = null;

		// empty string indicates association to "self"
		if (requiredAssociationValue.isEmpty()) entityId = securityService.getSubject().getPrincipals()
			.getPrimaryPrincipal();
		else {
			Attribute association = entityType.getAttribute(requiredAssociationValue);
			// TODO handle if !association.isAssociation()
			entityType = metamodel.entity(association.getJavaType());
			idType = entityType.getIdType();
			idAttr = entityType.getId(idType.getJavaType());

			Join<Object, Object> join = from.join(requiredAssociationValue);
			// TODO handle subject == null
			// TODO allow configuring the principal for it rather than using primary
			predicate2 = builder.equal(join.get(idAttr.getName()), securityService.getSubject().getPrincipals()
				.getPrimaryPrincipal());
		}

		Predicate predicate1 = null;
		if (entityId != null) {
			idType = entityType.getIdType();
			idAttr = entityType.getId(idType.getJavaType());
			predicate1 = builder.equal(from.get(idAttr.getName()), entityId);
		}
		criteriaQuery.where(predicate1 == null ? predicate2 : predicate2 == null ? predicate1 : builder.and(predicate1,
			predicate2));
		return (T) delegate.createQuery(criteriaQuery).getSingleResult();
	}

	private Annotation getAnnotation(Member member, Class annotationType) {
		return member instanceof Field ? ((Field) member).getAnnotation(annotationType)
			: member instanceof Method ? ((Method) member).getAnnotation(annotationType) : null;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void checkWritePermissions(final Object entity, final Operation writeOperation) {
		String requiredRoleValue = RequiresAnnotationUtil.getRequiredRole(entity.getClass(), writeOperation);

		if (requiredRoleValue != null && request.isUserInRole(requiredRoleValue)) return;

		String requiredAssociationValue = RequiresAnnotationUtil.getRequiredAssociation(entity.getClass(), writeOperation);

		if (requiredAssociationValue == null) {
			// proceed as normal if there's neither RequiresRole nor RequiresAssociation, throw an exception if role didn't match
			if (requiredRoleValue == null) return;
			else throw new EntitySecurityException("Currently executing subject is not permitted to " + writeOperation
				+ " entities of type " + entity.getClass().getSimpleName());
		}

		Metamodel metamodel = delegate.getMetamodel();
		EntityType entityType = metamodel.entity(entity.getClass());
		// empty association value indicates association to "self"
		Object associatedObject;
		if (requiredAssociationValue.isEmpty()) associatedObject = entity;
		else {
			Attribute association = entityType.getAttribute(requiredAssociationValue);
			entityType = metamodel.entity(association.getJavaType());
			associatedObject = propertyAccess.get(entity, requiredAssociationValue);
		}

		Type idType = entityType.getIdType();
		SingularAttribute idAttr = entityType.getId(idType.getJavaType());

		// handle INSERT operation to "self" with a generated id as a special allowed case
		if (associatedObject == entity && getAnnotation(idAttr.getJavaMember(), GeneratedValue.class) != null
			&& Operation.INSERT.equals(writeOperation)) return;
		else if (!propertyAccess.get(associatedObject, idAttr.getName()).equals(
			securityService.getSubject().getPrincipals().getPrimaryPrincipal())) { throw new EntitySecurityException(
			"Currently executing subject is not permitted to " + writeOperation + " entities of type "
				+ entity.getClass().getSimpleName() + " because the required association didn't exist"); }
	}
}
