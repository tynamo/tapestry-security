package org.tynamo.security.internal;

import org.apache.tapestry5.internal.bindings.AbstractBinding;
import org.tynamo.security.services.SecurityService;

public class PermissionBinding extends AbstractBinding {

    private final SecurityService securityService;
    private final String description;
    private final String permission;

    public PermissionBinding(final String description, final String permission, final SecurityService securityService) {
        this.description = description;
        this.permission = permission;
        this.securityService = securityService;
    }

    @Override
    public Object get() {
        return securityService.hasPermission(permission);
    }

    @Override
    public Class<?> getBindingType() {
        return Boolean.class;
    }

    @Override
    public boolean isInvariant() {
        return false;
    }

    @Override
    public String toString() {
        return String.format("PermissionBinding [description=%s, permission=%s, permissionGranted=%s]", description,
            permission, get());
    }

}