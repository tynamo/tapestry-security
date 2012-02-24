package org.tynamo.security.jpa.services;

import java.util.List;

import javax.persistence.EntityManager;

public interface AssociatedEntities {
	List<?> findAll(EntityManager em, Class<?> entityClass);

}
