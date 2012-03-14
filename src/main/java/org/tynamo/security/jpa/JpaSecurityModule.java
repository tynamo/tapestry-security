package org.tynamo.security.jpa;

import java.lang.reflect.Method;

import javax.persistence.EntityManager;
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
}
