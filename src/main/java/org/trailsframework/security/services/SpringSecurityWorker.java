/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007, 2008 Robin Helgelin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.trailsframework.security.services;

import java.lang.reflect.Modifier;

import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.services.ClassTransformation;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.TransformConstants;
import org.apache.tapestry5.services.TransformMethodSignature;
import org.trailsframework.security.annotations.Secured;

/**
 * @author Ivan Dubrov
 */
public class SpringSecurityWorker implements ComponentClassTransformWorker {
	private SecurityChecker securityChecker;

	public SpringSecurityWorker(final SecurityChecker securityChecker) {
		this.securityChecker = securityChecker;
	}

	public final void transform(final ClassTransformation transformation, final MutableComponentModel model) {
		// Secure methods
		for (TransformMethodSignature method : transformation.findMethodsWithAnnotation(Secured.class)) {
			transformMethod(transformation, method);
		}

		// Secure pages
		Secured annotation = transformation.getAnnotation(Secured.class);
		if (annotation != null) {
			transformPage(transformation, annotation);
		}
	}

	private void transformPage(final ClassTransformation transformation, final Secured annotation) {
		// Security checker
		final String interField = transformation.addInjectedField(SecurityChecker.class, "_$checker", securityChecker);

		// Attribute definition
		final String configField = createConfigAttributeDefinitionField(transformation, annotation);

		// Interceptor token
		final String tokenField = transformation.addField(Modifier.PRIVATE, "org.springframework.security.intercept.InterceptorStatusToken", "_$token");

		// Extend class
		transformation.extendMethod(TransformConstants.BEGIN_RENDER_SIGNATURE, tokenField + " = " + interField + ".checkBefore(" + configField + ");");
		transformation.extendMethod(TransformConstants.CLEANUP_RENDER_SIGNATURE, interField + ".checkAfter(" + tokenField + ", null);");

	}

	private void transformMethod(final ClassTransformation transformation, final TransformMethodSignature method) {
		// Security checker
		final String interField = transformation.addInjectedField(SecurityChecker.class, "_$checker", securityChecker);
		// Interceptor status token
		final String statusToken = transformation.addField(Modifier.PRIVATE, "org.springframework.security.intercept.InterceptorStatusToken", "_$token");

		// Attribute definition
		final Secured annotation = transformation.getMethodAnnotation(method, Secured.class);
		final String configField = createConfigAttributeDefinitionField(transformation, annotation);

		// Prefix and extend method
		transformation.prefixMethod(method, statusToken + " = " + interField + ".checkBefore(" + configField + ");");
		transformation.extendExistingMethod(method, interField + ".checkAfter(" + statusToken + ", null);");
	}

	private String createConfigAttributeDefinitionField(final ClassTransformation transformation, final Secured annotation) {
		// ConfigAttributeDefinition configAttributeDefinition = new ConfigAttributeDefinition(annotation.value());
		// return transformation.addInjectedField(ConfigAttributeDefinition.class, "_$configAttributeDefinition",
		// configAttributeDefinition);
		return null;
	}
}
