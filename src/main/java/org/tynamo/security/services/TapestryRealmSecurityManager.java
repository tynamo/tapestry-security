package org.tynamo.security.services;

import java.util.Collection;

import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;

/**
 * This class is needed to point out the right constructor to use (from the three available in
 * DefaultWebSecurityManager) for tapestry-ioc and to allow injecting dependencies  
 */
public class TapestryRealmSecurityManager extends DefaultWebSecurityManager {

	// Could easily make sessionStorageevaluator and sessionManager provided services as well, add as needed
	public TapestryRealmSecurityManager(SubjectFactory subjectFactory, RememberMeManager rememberMeManager, final Collection<Realm> realms) {
    super();
    ((DefaultSubjectDAO) this.subjectDAO).setSessionStorageEvaluator(new DefaultWebSessionStorageEvaluator());
    setSubjectFactory(subjectFactory);
    setRememberMeManager(rememberMeManager);
    setSessionManager(new ServletContainerSessionManager());
    setRealms(realms);
	}

}
