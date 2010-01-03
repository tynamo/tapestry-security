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
package org.tynamo.tapestry5jsecurity;

import java.lang.annotation.Annotation;
import java.util.List;

import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.services.ClassTransformation;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.ComponentMethodAdvice;
import org.apache.tapestry5.services.ComponentMethodInvocation;
import org.apache.tapestry5.services.TransformMethodSignature;

import org.tynamo.jsecurity.extension.authz.aop.AopHelper;
import org.tynamo.jsecurity.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.jsecurity.extension.authz.aop.SecurityInterceptor;



/**
 * Transform components based on annotation.
 * <p>
 * Support annotation on method. 
 * <p>
 * The following rules 
 * <ul>
 * <li>Annotations on methods are <b>not</b> inherited.</li>
 * <li>The annotations only in target class, unlike services </li>
 * <ul>
 * <p>
 *  
 * @see org.tynamo.tapestry5jsecurity.JSecurityModule#buildSecurityFilter(org.slf4j.Logger,
 * org.apache.tapestry5.services.ComponentEventLinkEncoder, 
 * org.apache.tapestry5.services.ComponentClassResolver,
 * org.tynamo.tapestry5jsecurity.services.ClassInterceptorsCache)
 *  
 * @author Valentine Yerastov
 */
public class JSecurityAnnotationWorker implements ComponentClassTransformWorker {

	@Override
	public void transform(ClassTransformation transformation,
			MutableComponentModel model) {
		
		for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationClasses()) {
			
			List<TransformMethodSignature> methodsToTransform = 
				transformation.findMethodsWithAnnotation(annotationClass);
			
			for (TransformMethodSignature tm : methodsToTransform) {
				Annotation annotation = transformation.getMethodAnnotation(tm, annotationClass);
				processTransform(transformation, tm, annotation);
			}
		}
	}

	private void processTransform(ClassTransformation transformation,
			TransformMethodSignature tm, Annotation annotation) {
		final SecurityInterceptor interceptor = new DefaultSecurityInterceptor(annotation);

		ComponentMethodAdvice advice = new ComponentMethodAdvice() {
			public void advise(ComponentMethodInvocation invocation) {
				interceptor.intercept();
				invocation.proceed();
			}
		};
		
		transformation.advise(tm, advice);

	}
	
}
