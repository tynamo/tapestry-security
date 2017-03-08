package org.tynamo.security.services;

import java.util.Collection;

import org.tynamo.security.services.impl.SecurityFilterChain;
import org.tynamo.security.shiro.AccessControlFilter;

public interface SecurityFilterChainHub {

	void insertChain(String path, AccessControlFilter filter, String config);

	void updateChain(String path, AccessControlFilter filter, String config);

	void removeChain(String path);

	void commitModifications(Collection<SecurityFilterChain> chains);
}
