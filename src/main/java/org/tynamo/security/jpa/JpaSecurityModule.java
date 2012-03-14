package org.tynamo.security.jpa;

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;

import javax.persistence.EntityManager;
import javax.persistence.metamodel.SingularAttribute;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.annotations.Advise;
import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.tynamo.security.jpa.annotations.Operation;
import org.tynamo.security.jpa.internal.SecureFindAdvice;
import org.tynamo.security.jpa.internal.SecureWriteAdvice;
import org.tynamo.security.services.SecurityService;

public class JpaSecurityModule {
	@Advise(serviceInterface = EntityManager.class)
	public static void secureEntityOperations(MethodAdviceReceiver receiver, SecurityService securityService,
		HttpServletRequest request, PropertyAccess propertyAccess) {
		SecureFindAdvice secureFindAdvice = new SecureFindAdvice(securityService, request);
		SecureWriteAdvice securePersistAdvice = new SecureWriteAdvice(Operation.INSERT, securityService, request,
			propertyAccess);
		SecureWriteAdvice secureMergeAdvice = new SecureWriteAdvice(Operation.UPDATE, securityService, request,
			propertyAccess);
		SecureWriteAdvice secureDeleteAdvice = new SecureWriteAdvice(Operation.DELETE, securityService, request,
			propertyAccess);
		// FIXME should also advice getReference
		for (final Method m : receiver.getInterface().getMethods()) {
			if (m.getName().startsWith("find")) receiver.adviseMethod(m, secureFindAdvice);
			else if (m.getName().startsWith("persist")) receiver.adviseMethod(m, securePersistAdvice);
			else if (m.getName().startsWith("merge")) receiver.adviseMethod(m, secureMergeAdvice);
			else if (m.getName().startsWith("remove")) receiver.adviseMethod(m, secureDeleteAdvice);
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
