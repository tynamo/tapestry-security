package org.tynamo.security.jpa.internal;

import java.util.Map;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.internal.jpa.EntityManagerSourceImpl;
import org.apache.tapestry5.ioc.Resource;
import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.apache.tapestry5.jpa.PersistenceUnitConfigurer;
import org.slf4j.Logger;
import org.tynamo.security.services.SecurityService;

@Deprecated
public class SecureEntityManagerSource extends EntityManagerSourceImpl {
	private final SecurityService securityService;
	private final PropertyAccess propertyAccess;
	private final HttpServletRequest request;

	public SecureEntityManagerSource(SecurityService securityService, PropertyAccess propertyAccess,
		HttpServletRequest request, Logger logger, Resource persistenceDescriptor,
		PersistenceUnitConfigurer packageNamePersistenceUnitConfigurer, Map<String, PersistenceUnitConfigurer> configuration) {
		super(logger, persistenceDescriptor, packageNamePersistenceUnitConfigurer, configuration);
		this.securityService = securityService;
		this.propertyAccess = propertyAccess;
		this.request = request;
	}

	@Override
	public EntityManager create(String persistenceUnitName) {
		EntityManager entityManager = super.create(persistenceUnitName);
		return entityManager == null ? null : new SecureEntityManager(securityService, propertyAccess, request,
			entityManager, "", null);
	}
}
