package org.tynamo.security.services;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.io.Serializer;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class SecurityModuleUnitTest {
	Logger logger = LoggerFactory.getLogger(SecurityModuleUnitTest.class);
	@SuppressWarnings("rawtypes")
	Serializer serializer;
	Subject subject = mock(Subject.class);
	AuthenticationToken authenticationToken = new UsernamePasswordToken();
	AuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo();

	@SuppressWarnings("unchecked")
	@BeforeClass
	public void setUp() {
		serializer = mock(Serializer.class);
		when(serializer.serialize(any(Object.class))).thenReturn(new byte[12]);
	}

	@Test
	public void buildRememberMeWithHmacPaddingForCipherKey() throws UnsupportedEncodingException {
		AbstractRememberMeManager rememberMeManager = (AbstractRememberMeManager) SecurityModule.buildRememberMeManager(
			serializer, logger, "hmacPassphrase", "");
		rememberMeManager.rememberIdentity(subject, authenticationToken, authenticationInfo);
	}

	@Test(expectedExceptions = CryptoException.class)
	public void buildRememberMeInvalidCipherKey() throws UnsupportedEncodingException {
		AbstractRememberMeManager rememberMeManager = (AbstractRememberMeManager) SecurityModule.buildRememberMeManager(
			serializer, logger, "", "invalidcipher");
		rememberMeManager.rememberIdentity(subject, authenticationToken, authenticationInfo);
	}

	@Test
	public void buildRememberMeValidCipherKey() throws UnsupportedEncodingException {
		AbstractRememberMeManager rememberMeManager = (AbstractRememberMeManager) SecurityModule.buildRememberMeManager(
			serializer, logger, "", "kPH+bIxk5D2deZiIxcaaaA==");
		rememberMeManager.rememberIdentity(subject, authenticationToken, authenticationInfo);
	}

	@Test
	public void buildRememberMeWithHmacTruncatedForCipherKey() throws UnsupportedEncodingException {
		AbstractRememberMeManager rememberMeManager = (AbstractRememberMeManager) SecurityModule.buildRememberMeManager(
			serializer, logger, "averylongstringthatisnotdivisablebysixteen", "");
		rememberMeManager.rememberIdentity(subject, authenticationToken, authenticationInfo);
	}

}
