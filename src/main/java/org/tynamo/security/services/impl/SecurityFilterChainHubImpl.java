package org.tynamo.security.services.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.shiro.util.RegExPatternMatcher;
import org.apache.tapestry5.func.F;
import org.apache.tapestry5.func.Worker;

import org.slf4j.Logger;
import org.tynamo.security.services.SecurityFilterChainFactory;
import org.tynamo.security.services.SecurityFilterChainHub;
import org.tynamo.security.shiro.AccessControlFilter;

import static org.apache.tapestry5.ioc.internal.util.CollectionFactory.newThreadSafeList;

public class SecurityFilterChainHubImpl implements SecurityFilterChainHub {

	private final Logger logger;
	private final SecurityFilterChainFactory factory;
	private final List<SecurityFilterChain> insertChains = newThreadSafeList();
	private final List<SecurityFilterChainConfig> updateChains = newThreadSafeList();
	private final List<String> removeChains = newThreadSafeList();

	public SecurityFilterChainHubImpl(Logger logger,
									  SecurityFilterChainFactory factory) {
		this.logger = logger;
		this.factory = factory;
	}

	@Override
	public void insertChain(String path, AccessControlFilter filter, String config) {
		insertChains.add(factory.createChainWithAntPath(path).add(filter, config).build());
	}

	@Override
	public void insertChainWithRegEx(String path, AccessControlFilter filter, String config) {
		insertChains.add(factory.createChainWithRegEx(path).add(filter, config).build());
	}

	@Override
	public void updateChain(String path, AccessControlFilter filter, String config) {
		updateChains.add(new SecurityFilterChainConfig(path, filter, config));
	}

	@Override
	public void removeChain(String path) {
		removeChains.add(path);
	}

	@Override
	public void commitModifications(final Collection<SecurityFilterChain> chains) {
		final List<SecurityFilterChain> chainsToRemove = new ArrayList<SecurityFilterChain>();

		F.flow(updateChains).each(new Worker<SecurityFilterChainConfig>() {
			@Override
			public void work(SecurityFilterChainConfig updateChainConfig) {
				try {
					for (SecurityFilterChain chain : chains) {
						if (chain.getPath().equalsIgnoreCase(updateChainConfig.path)) {
							chainsToRemove.add(chain);
							if (chain.getPatternMatcher() instanceof RegExPatternMatcher)
								insertChains.add(factory.createChainWithRegEx(updateChainConfig.path).add(updateChainConfig.filter, updateChainConfig.config).build());
							else
								insertChains.add(factory.createChain(updateChainConfig.path).add(updateChainConfig.filter, updateChainConfig.config).build());
							break;
						}
					}
				}
				catch (RuntimeException ex) {
					logger.error(ex.getLocalizedMessage(), ex);
				}
			}
		});

		F.flow(insertChains).each(new Worker<SecurityFilterChain>() {
			@Override
			public void work(SecurityFilterChain insertChain) {
				try {
					chains.add(insertChain);
				}
				catch (RuntimeException ex) {
					logger.error(ex.getLocalizedMessage(), ex);
				}
			}
		});


		F.flow(removeChains).each(new Worker<String>() {
			@Override
			public void work(String removeChain) {
				try {
					for (SecurityFilterChain chain : chains) {
						if (chain.getPath().equalsIgnoreCase(removeChain)) {
							chainsToRemove.add(chain);
						}
					}
				}
				catch (RuntimeException ex) {
					logger.error(ex.getLocalizedMessage(), ex);
				}
			}
		});

		// cleaning
		insertChains.clear();
		updateChains.clear();
		removeChains.clear();
		chains.removeAll(chainsToRemove);
	}

	private class SecurityFilterChainConfig {
		private AccessControlFilter filter;
		private String path;
		private String config;

		public SecurityFilterChainConfig(String path, AccessControlFilter filter, String config) {
			this.path = path;
			this.filter = filter;
			this.config = config;
		}
	}
}
