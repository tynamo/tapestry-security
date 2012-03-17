package org.tynamo.security.jpa.testapp.pages;

import javax.persistence.EntityManager;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.tapestry5.annotations.InjectComponent;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.corelib.components.Zone;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.jpa.annotations.CommitAfter;
import org.tynamo.security.jpa.testapp.entities.AdminOnly;
import org.tynamo.security.jpa.testapp.entities.MyData;
import org.tynamo.security.services.SecurityService;

public class Index {
	@Inject
	private EntityManager entityManager;

	@Property
	private MyData myData;

	void onActivate() {
		myData = entityManager.find(MyData.class, null);
	}

	@CommitAfter
	Object onActionFromUpdateMyData() {
		myData.setValue(String.valueOf(System.currentTimeMillis()));
		entityManager.persist(myData);
		return myDataZone.getBody();
	}

	@Inject
	private SecurityService securityService;

	@InjectComponent
	Zone myDataZone;

	void onActionFromSignInAsUser() {
		securityService.getSubject().login(new UsernamePasswordToken("user", "user"));
	}

	@CommitAfter
	void onActionFromInsertAdminOnly() {
		AdminOnly adminOnly = new AdminOnly();
		entityManager.persist(adminOnly);
	}
}
