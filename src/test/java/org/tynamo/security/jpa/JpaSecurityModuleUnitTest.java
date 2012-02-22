package org.tynamo.security.jpa;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Persistence;

import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.tapestry5.ioc.Registry;
import org.apache.tapestry5.ioc.RegistryBuilder;
import org.apache.tapestry5.ioc.services.AspectDecorator;
import org.apache.tapestry5.ioc.services.AspectInterceptorBuilder;
import org.apache.tapestry5.ioc.services.TapestryIOCModule;
import org.apache.tapestry5.ioc.test.IOCTestCase;
import org.apache.tapestry5.jpa.JpaModule;
import org.apache.tapestry5.json.services.JSONModule;
import org.apache.tapestry5.services.TapestryModule;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.tynamo.exceptionpage.services.ExceptionPageModule;
import org.tynamo.security.jpa.annotations.RequiresAssociation;
import org.tynamo.security.services.SecurityModule;
import org.tynamo.security.services.SecurityService;

public class JpaSecurityModuleUnitTest extends IOCTestCase {
	private Registry registry;
	private AspectDecorator aspectDecorator;
	private EntityManager delegate;
	private SecurityService securityService;

	@BeforeClass
	public void setup() {
		EntityManagerFactory emFactory = Persistence.createEntityManagerFactory("testpersistence");
		delegate = emFactory.createEntityManager();
		securityService = mock(SecurityService.class);

		RegistryBuilder builder = new RegistryBuilder();
		builder.add(TapestryModule.class);
		// IOCUtilities.addDefaultModules(builder);
		builder.add(TapestryIOCModule.class);
		builder.add(JSONModule.class);
		builder.add(JpaModule.class);
		builder.add(SecurityModule.class);
		builder.add(ExceptionPageModule.class);
		registry = builder.build();
		// registry = IOCUtilities.buildDefaultRegistry();

		aspectDecorator = registry.getService(AspectDecorator.class);
	}

	@AfterClass
	public void shutdown() {
		delegate.getTransaction().begin();
		delegate.createQuery("DELETE FROM TestEntity m").executeUpdate();
		delegate.createQuery("DELETE FROM TestOwnerEntity t").executeUpdate();
		delegate.getTransaction().commit();

		registry.shutdown();

		aspectDecorator = null;
		registry = null;
	}

	@Test
	public void adviseEntityManagerFind() {
		delegate.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		delegate.persist(owner);
		TestEntity entity = new TestEntity();
		entity.setOwner(owner);
		entity.setId(1L);
		delegate.persist(entity);
		delegate.getTransaction().commit();

		final AspectInterceptorBuilder<EntityManager> builder = aspectDecorator.createBuilder(EntityManager.class,
			delegate, "secureEntityManager");

		Subject subject = mock(Subject.class);
		PrincipalCollection principalCollection = mock(PrincipalCollection.class);
		when(principalCollection.getPrimaryPrincipal()).thenReturn(new Long(1L));
		when(subject.getPrincipals()).thenReturn(principalCollection);
		when(securityService.getSubject()).thenReturn(subject);

		JpaSecurityModule.secureFindOperations(builder, securityService);
		final EntityManager interceptor = builder.build();

		entity = interceptor.find(TestEntity.class, 1L);
		assertNotNull(entity);

	}

	@Entity(name = "TestEntity")
	@RequiresAssociation("owner")
	public static class TestEntity {

		@Id
		private Long id;

		@ManyToOne(optional = true)
		private TestOwnerEntity owner;

		public TestOwnerEntity getOwner() {
			return owner;
		}

		public void setOwner(TestOwnerEntity owner) {
			this.owner = owner;
		}

		public Long getId() {
			return id;
		}

		public void setId(Long id) {
			this.id = id;
		}

	}

	@Entity(name = "TestOwnerEntity")
	public static class TestOwnerEntity {

		@Id
		private Long id;

		public Long getId() {
			return id;
		}

		public void setId(Long id) {
			this.id = id;
		}

	}

}
