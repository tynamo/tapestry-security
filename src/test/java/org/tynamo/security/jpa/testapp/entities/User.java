package org.tynamo.security.jpa.testapp.entities;

import javax.persistence.Entity;
import javax.persistence.Id;

import org.tynamo.security.jpa.annotations.RequiresAssociation;

@RequiresAssociation("owner")
@Entity
public class User {

	@Id
	private String id;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

}
