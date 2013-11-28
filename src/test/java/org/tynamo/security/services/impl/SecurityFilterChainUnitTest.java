package org.tynamo.security.services.impl;

import static org.testng.Assert.fail;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.services.impl.SecurityFilterChain.Builder;
import org.tynamo.security.shiro.authc.AnonymousFilter;


public class SecurityFilterChainUnitTest {
	private Builder builder;
	private SecurityFilterChainFactory factory;

	@BeforeTest
	public void setUp() {
		builder = new SecurityFilterChain.Builder(null, null, "", null);
		factory = new SecurityFilterChainFactoryImpl(null, null, null, "", "", "", "");
	}
	
	@Test(expectedExceptions = {IllegalArgumentException.class})
	public void builderAddSameFilterWithDifferentConfig() {
		AnonymousFilter filter = factory.anon();
		builder.add(filter, "someconfig");
		builder.add(filter, "anotherconfig");
		fail("IllegalArgumentException was not thrown when re-contributing the same filter");
		
	}

	@Test(expectedExceptions = {IllegalArgumentException.class})
	public void builderAddSameFilterFirstWithoutConfig() {
		AnonymousFilter filter = factory.anon();
		builder.add(filter);
		builder.add(filter, "someconfig");
		fail("IllegalArgumentException was not thrown when re-contributing the same filter");
		
	}
	
	@Test
	public void builderAddSameFilterWithoutAnyConfig() {
		AnonymousFilter filter = factory.anon();
		builder.add(filter);
		builder.add(filter);
	}
}
