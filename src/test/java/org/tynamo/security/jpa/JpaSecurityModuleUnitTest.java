package org.tynamo.security.jpa;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.NonUniqueResultException;
import javax.persistence.Persistence;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.tapestry5.ioc.Registry;
import org.apache.tapestry5.ioc.RegistryBuilder;
import org.apache.tapestry5.ioc.services.AspectDecorator;
import org.apache.tapestry5.ioc.services.PropertyAccess;
import org.apache.tapestry5.ioc.services.TapestryIOCModule;
import org.apache.tapestry5.ioc.test.IOCTestCase;
import org.apache.tapestry5.jpa.JpaModule;
import org.apache.tapestry5.json.services.JSONModule;
import org.apache.tapestry5.services.TapestryModule;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.tynamo.exceptionpage.services.ExceptionPageModule;
import org.tynamo.security.jpa.annotations.Operation;
import org.tynamo.security.jpa.annotations.RequiresAssociation;
import org.tynamo.security.jpa.annotations.RequiresRole;
import org.tynamo.security.jpa.internal.SecureEntityManager;
import org.tynamo.security.jpa.testapp.entities.AdminOnly;
import org.tynamo.security.jpa.testapp.entities.Unsecured;
import org.tynamo.security.services.SecurityModule;
import org.tynamo.security.services.SecurityService;

public class JpaSecurityModuleUnitTest extends IOCTestCase {
	private Registry registry;
	private AspectDecorator aspectDecorator;
	private EntityManager delegate;
	private EntityManager interceptor;
	private SecurityService securityService;
	private HttpServletRequest request;
	private PropertyAccess propertyAccess;
	private SecurityManager securityManager;

	@BeforeClass
	public void setup() {
		EntityManagerFactory emFactory = Persistence.createEntityManagerFactory("testpersistence");
		delegate = emFactory.createEntityManager();
		securityService = mock(SecurityService.class);
		request = mock(HttpServletRequest.class);
		securityManager = mock(SecurityManager.class);

		RegistryBuilder builder = new RegistryBuilder();
		builder.add(TapestryModule.class);
		// IOCUtilities.addDefaultModules(builder);
		builder.add(TapestryIOCModule.class);
		builder.add(JSONModule.class);
		builder.add(JpaModule.class);
		builder.add(SecurityModule.class);
		builder.add(ExceptionPageModule.class);
		// builder.add(JpaSecurityModule.class);
		registry = builder.build();
		// registry = IOCUtilities.buildDefaultRegistry();

		aspectDecorator = registry.getService(AspectDecorator.class);
		propertyAccess = registry.getService(PropertyAccess.class);
		// // final AspectInterceptorBuilder<EntityManager> aspectBuilder = aspectDecorator.createBuilder(EntityManager.class,
		// // delegate, "secureEntityManager");
		// // JpaSecurityModule.secureEntityOperations(aspectBuilder, securityService, request, propertyAccess);
		// interceptor = aspectBuilder.build();
		interceptor = new SecureEntityManager(securityService, propertyAccess, request, delegate, "", null);
	}

	@BeforeMethod
	public void bindMockSecurityManager() {
		ThreadContext.bind(securityManager);
	}

	@AfterMethod
	public void clearDb() {
		if (delegate.getTransaction().isActive()) delegate.getTransaction().rollback();
		delegate.getTransaction().begin();
		delegate.createQuery("DELETE FROM TestEntity m").executeUpdate();
		delegate.createQuery("DELETE FROM TestOwnerEntity t").executeUpdate();
		delegate.getTransaction().commit();
	}

	@AfterClass
	public void shutdown() {
		registry.shutdown();

		aspectDecorator = null;
		registry = null;
	}

	private void mockSubject(Long principalId) {
		Subject subject = mock(Subject.class);
		when(subject.isAuthenticated()).thenReturn(true);
		PrincipalCollection principalCollection = mock(PrincipalCollection.class);
		when(principalCollection.getPrimaryPrincipal()).thenReturn(principalId);
		when(subject.getPrincipals()).thenReturn(principalCollection);
		when(securityService.getSubject()).thenReturn(subject);
	}

	@Test
	public void secureFind() {
		delegate.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		delegate.persist(owner);
		TestEntity entity = new TestEntity();
		entity.setOwner(owner);
		entity.setId(1L);
		delegate.persist(entity);
		delegate.getTransaction().commit();
		mockSubject(1L);

		entity = interceptor.find(TestEntity.class, 1L);
		assertNotNull(entity);
	}

	@Test
	public void unsecurePersistAndFind() {
		delegate.getTransaction().begin();
		Unsecured unsecured = new Unsecured();
		interceptor.persist(unsecured);
		interceptor.getTransaction().commit();

		assertNotNull(interceptor.find(Unsecured.class, unsecured.getId()));

		// test that we can try finding but not find an existing, but secured entity
		AdminOnly adminOnly = new AdminOnly();
		delegate.getTransaction().begin();
		delegate.persist(adminOnly);
		delegate.getTransaction().commit();
		assertNull(interceptor.find(AdminOnly.class, adminOnly.getId()));
	}

	@Test
	public void findByAssociation() {
		delegate.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		delegate.persist(owner);
		TestEntity entity = new TestEntity();
		entity.setOwner(owner);
		entity.setId(1L);
		delegate.persist(entity);
		delegate.getTransaction().commit();

		mockSubject(1L);
		entity = interceptor.find(TestEntity.class, null);
		assertNotNull(entity);
	}

	@Test
	public void findSelfByAssociation() {
		delegate.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		delegate.persist(owner);
		delegate.getTransaction().commit();

		mockSubject(1L);
		owner = interceptor.find(TestOwnerEntity.class, null);
		assertNotNull(owner);

	}

	@Test(expectedExceptions = { NonUniqueResultException.class })
	public void findMultipleByAssociation() {
		delegate.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		delegate.persist(owner);
		TestEntity entity = new TestEntity();
		entity.setOwner(owner);
		entity.setId(1L);
		delegate.persist(entity);
		entity = new TestEntity();
		entity.setOwner(owner);
		entity.setId(2L);
		delegate.persist(entity);
		delegate.getTransaction().commit();

		mockSubject(1L);
		entity = interceptor.find(TestEntity.class, null);
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void persistProtectedByRole() {
		interceptor.getTransaction().begin();
		RoleWriteProtectedEntity rolePersistProtectedEntity = new RoleWriteProtectedEntity();
		interceptor.persist(rolePersistProtectedEntity);
		interceptor.getTransaction().commit();
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void mergeProtectedByRole() {
		interceptor.getTransaction().begin();
		RoleWriteProtectedEntity rolePersistProtectedEntity = new RoleWriteProtectedEntity();
		interceptor.merge(rolePersistProtectedEntity);
		interceptor.getTransaction().commit();
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void removeProtectedByRole() {
		interceptor.getTransaction().begin();
		RoleWriteProtectedEntity rolePersistProtectedEntity = new RoleWriteProtectedEntity();
		interceptor.remove(rolePersistProtectedEntity);
		interceptor.getTransaction().commit();
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void insertProtectedByAssociationOwnerIsNull() {
		mockSubject(2L);
		interceptor.getTransaction().begin();
		InsertAssociationProtectedEntity insertAssociationProtectedEntity = new InsertAssociationProtectedEntity();
		interceptor.persist(insertAssociationProtectedEntity);
		interceptor.getTransaction().commit();
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void insertProtectedByAssociation() {
		mockSubject(2L);
		interceptor.getTransaction().begin();
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		interceptor.persist(owner);
		InsertAssociationProtectedEntity insertAssociationProtectedEntity = new InsertAssociationProtectedEntity();
		insertAssociationProtectedEntity.setOwner(owner);
		interceptor.persist(insertAssociationProtectedEntity);
		interceptor.getTransaction().commit();
	}

	@Test(expectedExceptions = { EntitySecurityException.class })
	public void removeProtectedByAssociation() {
		TestOwnerEntity owner = new TestOwnerEntity();
		owner.setId(1L);
		mockSubject(2L);
		interceptor.getTransaction().begin();
		interceptor.remove(owner);
		interceptor.getTransaction().commit();
	}

	@Test
	public void persistSelfProtectedByAssociation() {
		TestGenerated generated = new TestGenerated();
		// as an exception to the rules, adding (any) self *should* succeed
		mockSubject(1L);
		interceptor.getTransaction().begin();
		interceptor.persist(generated);
		interceptor.getTransaction().commit();
	}

	@Entity(name = "RoleWriteProtectedEntity")
	@RequiresRole(value = "owner", operations = Operation.WRITE)
	public static class RoleWriteProtectedEntity {
		@Id
		@GeneratedValue(strategy = GenerationType.AUTO)
		private Long id;

		public Long getId() {
			return id;
		}
	}

	@Entity(name = "InsertAssociationProtectedEntity")
	@RequiresAssociation(value = "owner", operations = Operation.INSERT)
	public static class InsertAssociationProtectedEntity {
		@Id
		@GeneratedValue(strategy = GenerationType.AUTO)
		private Long id;

		@ManyToOne
		private TestOwnerEntity owner;

		public Long getId() {
			return id;
		}

		public TestOwnerEntity getOwner() {
			return owner;
		}

		public void setOwner(TestOwnerEntity owner) {
			this.owner = owner;
		}
	}

	@Entity(name = "TestEntity")
	@RequiresAssociation("owner")
	public static class TestEntity {

		@Id
		private Long id;

		@ManyToOne
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
	@RequiresAssociation
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

	@Entity(name = "TestGenerated")
	@RequiresAssociation
	public static class TestGenerated {

		@Id
		@GeneratedValue(strategy = GenerationType.AUTO)
		private Long id;

		public Long getId() {
			return id;
		}
	}
}
