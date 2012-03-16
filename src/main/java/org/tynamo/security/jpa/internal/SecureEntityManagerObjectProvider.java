package org.tynamo.security.jpa.internal;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.tapestry5.internal.jpa.JpaInternalUtils;
import org.apache.tapestry5.ioc.AnnotationProvider;
import org.apache.tapestry5.ioc.ObjectCreator;
import org.apache.tapestry5.ioc.ObjectLocator;
import org.apache.tapestry5.ioc.ObjectProvider;
import org.apache.tapestry5.ioc.services.PlasticProxyFactory;
import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.apache.tapestry5.jpa.EntityManagerManager;
import org.tynamo.security.services.SecurityService;

public class SecureEntityManagerObjectProvider implements ObjectProvider {

	private EntityManager proxy;

	// this causes a stackoverflow because objectprovider is contributed to MasterObjectProvider
	// private SecurityService securityService;
	// private PropertyAccess propertyAccess;
	// private HttpServletRequest request;
	//
	// public SecureEntityManagerObjectProvider(final SecurityService securityService, final PropertyAccess propertyAccess,
	// final HttpServletRequest request) {
	// this.securityService = securityService;
	// this.propertyAccess = propertyAccess;
	// this.request = request;
	// }

	public <T> T provide(final Class<T> objectType, final AnnotationProvider annotationProvider,
		final ObjectLocator locator) {
		if (objectType.equals(EntityManager.class)) return objectType.cast(getOrCreateProxy(annotationProvider, locator));

		return null;
	}

	private synchronized EntityManager getOrCreateProxy(final AnnotationProvider annotationProvider,
		final ObjectLocator objectLocator) {
		if (proxy == null) {
			final PlasticProxyFactory proxyFactory = objectLocator.getService("PlasticProxyFactory",
				PlasticProxyFactory.class);

			final PersistenceContext annotation = annotationProvider.getAnnotation(PersistenceContext.class);
			final EntityManagerManager entityManagerManager = objectLocator.getService(EntityManagerManager.class);
			final SecurityService securityService = objectLocator.getService(SecurityService.class);
			final PropertyAccess propertyAccess = objectLocator.getService(PropertyAccess.class);
			final HttpServletRequest request = objectLocator.getService(HttpServletRequest.class);

			proxy = proxyFactory.createProxy(EntityManager.class, new ObjectCreator() {
				public Object createObject() {
					final EntityManagerManager entityManagerManager = objectLocator.getService(EntityManagerManager.class);

					return new SecureEntityManager(securityService, propertyAccess, request, JpaInternalUtils.getEntityManager(
						entityManagerManager, annotation));
				}
			}, "<EntityManagerProxy>");
		}

		return proxy;
	}
}
