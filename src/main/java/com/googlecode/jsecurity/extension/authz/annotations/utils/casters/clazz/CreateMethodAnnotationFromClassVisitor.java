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
import com.googlecode.jsecurity.extension.authz.annotations.utils.AnnotationFactory;

/**
 * Create method annotations based on the class annotations type.
 * 
 * @author Valentine Yerastov
 */
public class CreateMethodAnnotationFromClassVisitor implements ClassAnnotationCasterVisitor {

	private Annotation resultAnnotation;
	private final AnnotationFactory annotationFactory;
	
	public CreateMethodAnnotationFromClassVisitor(AnnotationFactory annotationFactory) {
		this.annotationFactory = annotationFactory;
		
	}
	
	@Override
	public void visitNotFund() {
		resultAnnotation = null;
	}

	@Override
	public void visitRequiresAuthenticationAll(
			RequiresAuthenticationAll annotation) {
		resultAnnotation = annotationFactory.createRequiresAuthentication();
	}

	@Override
	public void visitRequiresGuestAll(RequiresGuestAll annotation) {
		resultAnnotation = annotationFactory.createRequiresGuest();
	}

	@Override
	public void visitRequiresPermissionsAll(RequiresPermissionsAll annotation) {
		resultAnnotation = annotationFactory.createRequiresPermissions(annotation);
	}

	@Override
	public void visitRequiresRolesAll(RequiresRolesAll annotation) {
		resultAnnotation = annotationFactory.createRequiresRoles(annotation);
	}

	@Override
	public void visitRequiresUserAll(RequiresUserAll annotation) {
		resultAnnotation = annotationFactory.createRequiresUser();	
	}

	public void setResultAnnotation(Annotation resultAnnotation) {
		this.resultAnnotation = resultAnnotation;
	}

	public Annotation getResultAnnotation() {
		return resultAnnotation;
	}

}
