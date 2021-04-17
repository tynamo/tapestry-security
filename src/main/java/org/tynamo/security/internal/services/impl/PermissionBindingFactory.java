package org.tynamo.security.internal.services.impl;

import org.apache.tapestry5.Binding;
import org.apache.tapestry5.ComponentResources;
import org.apache.tapestry5.commons.Location;
import org.apache.tapestry5.services.BindingFactory;
import org.tynamo.security.internal.PermissionBinding;
import org.tynamo.security.services.SecurityService;

public class PermissionBindingFactory implements BindingFactory {

    private final SecurityService securityService;

    public PermissionBindingFactory(final SecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public Binding newBinding(final String description, final ComponentResources container,
            final ComponentResources component, final String expression, final Location location) {
        return new PermissionBinding(description, expression, securityService);
    }

}
