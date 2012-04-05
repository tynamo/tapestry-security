package org.tynamo.security.jpa;

import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.MethodAdviceReceiver;
import org.apache.tapestry5.ioc.annotations.Advise;
import org.apache.tapestry5.ioc.annotations.Autobuild;
import org.apache.tapestry5.jpa.EntityManagerSource;
import org.tynamo.security.jpa.internal.SecureEntityManagerSourceAdvice;

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

	// @Contribute(MasterObjectProvider.class)
	// public static void provideObjectProviders(final OrderedConfiguration<ObjectProvider> configuration) {
	// configuration.overrideInstance("EntityManager", SecureEntityManagerObjectProvider.class,
	// "before:AnnotationBasedContributions");
	// }

	// The following causes a circular reference with ServiceOverride depending on itself
	// @Contribute(ServiceOverride.class)
	// public static void overrideEntityManagerSource(MappedConfiguration<Class, Object> configuration) {
	// configuration.addInstance(EntityManagerSource.class, SecureEntityManagerSource.class);
	// }

	@SuppressWarnings("unchecked")
	@Advise(serviceInterface = EntityManagerSource.class)
	public static void secureEntityManager(final MethodAdviceReceiver receiver,
		@Autobuild SecureEntityManagerSourceAdvice advice) throws SecurityException, NoSuchMethodException {
		receiver.adviseMethod(receiver.getInterface().getMethod("create", new Class[] { String.class }), advice);
	}

	public static void contributeFactoryDefaults(MappedConfiguration<String, String> configuration) {
		configuration.add(JpaSecuritySymbols.ASSOCIATED_REALM, "");
		configuration.add(JpaSecuritySymbols.ASSOCIATED_PRINCIPALTYPE, "");
	}
}
