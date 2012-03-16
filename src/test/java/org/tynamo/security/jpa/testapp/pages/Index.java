package org.tynamo.security.jpa.testapp.pages;

import javax.persistence.EntityManager;

import org.apache.tapestry5.ioc.annotations.Inject;
import org.tynamo.security.jpa.testapp.entities.SimpleEntity;

public class Index {
	@Inject
	private EntityManager entityManager;

	public void onActivate() {
		entityManager.find(SimpleEntity.class, 1L);
	}
}
