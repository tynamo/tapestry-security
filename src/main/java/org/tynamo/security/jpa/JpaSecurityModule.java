package org.tynamo.security.jpa;

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;

import javax.persistence.EntityManager;
import javax.persistence.metamodel.SingularAttribute;

import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.annotations.Advise;
import org.tynamo.security.jpa.internal.SecureFindAdvice;
import org.tynamo.security.services.SecurityService;

public class JpaSecurityModule {
	@Advise(serviceInterface = EntityManager.class)
	public static void secureFindOperations(MethodAdviceReceiver receiver, SecurityService securityService) {
		SecureFindAdvice secureFindAdvice = new SecureFindAdvice(securityService);
		// FIXME should also advice getReference
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
