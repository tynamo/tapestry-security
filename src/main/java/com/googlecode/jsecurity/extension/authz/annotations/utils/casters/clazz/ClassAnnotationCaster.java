/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.googlecode.jsecurity.extension.authz.annotations.utils.casters.clazz;

import java.lang.annotation.Annotation;

import com.googlecode.jsecurity.extension.authz.annotations.RequiresAuthenticationAll;
import com.googlecode.jsecurity.extension.authz.annotations.RequiresGuestAll;
import com.googlecode.jsecurity.extension.authz.annotations.RequiresPermissionsAll;
import com.googlecode.jsecurity.extension.authz.annotations.RequiresRolesAll;
import com.googlecode.jsecurity.extension.authz.annotations.RequiresUserAll;

/**
 * Class for accepting 
 * {@link com.google.code.jsecurity.extension.authz.annotations.utils.casters.clazz.ClassAnnotationCasterVisitor} 
 * visitors. 
 * <p>
 * Provides call the desired method of the visitor, depending on the annotation type.
 *
 * @see com.google.code.jsecurity.extension.authz.annotations.utils.casters.clazz.ClassAnnotationCasterVisitor
 * @author Valentine Yerastov
 */
public class ClassAnnotationCaster {

	private static final ClassAnnotationCaster instance = new ClassAnnotationCaster(); 
	
	private ClassAnnotationCaster() {}
	
	public void accept(ClassAnnotationCasterVisitor visitor, Annotation annotation) {
		if (annotation instanceof RequiresPermissionsAll) {

			visitor.visitRequiresPermissionsAll((RequiresPermissionsAll) annotation);

		} else if (annotation instanceof RequiresRolesAll) {

			visitor.visitRequiresRolesAll((RequiresRolesAll) annotation);

		} else if (annotation instanceof RequiresUserAll) {

			visitor.visitRequiresUserAll((RequiresUserAll) annotation);

		} else if (annotation instanceof RequiresGuestAll) {

			visitor.visitRequiresGuestAll((RequiresGuestAll) annotation);

		} else if (annotation instanceof RequiresAuthenticationAll) {

			visitor.visitRequiresAuthenticationAll((RequiresAuthenticationAll) annotation);

		} else {

			visitor.visitNotFund();

		}
	}

	public static ClassAnnotationCaster getInstance() {
		return instance;
	}
	
}
