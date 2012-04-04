package org.tynamo.security.jpa;

import org.apache.tapestry5.ioc.ObjectProvider;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.annotations.Contribute;
import org.apache.tapestry5.ioc.services.MasterObjectProvider;
import org.tynamo.security.jpa.internal.SecureEntityManagerObjectProvider;

public class JpaSecurityModule {
	// @Advise(serviceInterface = EntityManager.class)
	// public static void secureEntityOperations(MethodAdviceReceiver receiver, SecurityService securityService,
	// HttpServletRequest request, PropertyAccess propertyAccess) {
	// SecureFindAdvice secureFindAdvice = new SecureFindAdvice(securityService, request);
	// SecureWriteAdvice securePersistAdvice = new SecureWriteAdvice(Operation.INSERT, securityService, request,
	// propertyAccess);
	// SecureWriteAdvice secureMergeAdvice = new SecureWriteAdvice(Operation.UPDATE, securityService, request,
	// propertyAccess);
	// SecureWriteAdvice secureDeleteAdvice = new SecureWriteAdvice(Operation.DELETE, securityService, request,
	// propertyAccess);
	// // FIXME should also advice getReference
	// for (final Method m : receiver.getInterface().getMethods()) {
	// if (m.getName().startsWith("find")) receiver.adviseMethod(m, secureFindAdvice);
	// else if (m.getName().startsWith("persist")) receiver.adviseMethod(m, securePersistAdvice);
	// else if (m.getName().startsWith("merge")) receiver.adviseMethod(m, secureMergeAdvice);
	// else if (m.getName().startsWith("remove")) receiver.adviseMethod(m, secureDeleteAdvice);
	// }
	//
	// }

	@Contribute(MasterObjectProvider.class)
	public static void provideObjectProviders(final OrderedConfiguration<ObjectProvider> configuration) {
		configuration.overrideInstance("EntityManager", SecureEntityManagerObjectProvider.class,
			"before:AnnotationBasedContributions");
	}
}
