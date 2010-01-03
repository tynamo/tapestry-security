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
package org.googlecode.jsecurity.extension.authz.annotations.utils.casters.clazz;

import org.googlecode.jsecurity.extension.authz.annotations.RequiresAuthenticationAll;
import org.googlecode.jsecurity.extension.authz.annotations.RequiresGuestAll;
import org.googlecode.jsecurity.extension.authz.annotations.RequiresPermissionsAll;
import org.googlecode.jsecurity.extension.authz.annotations.RequiresRolesAll;
import org.googlecode.jsecurity.extension.authz.annotations.RequiresUserAll;

/**
 * Visitor interface for use in 
 * {@link com.google.code.jsecurity.extension.authz.annotations.utils.casters.clazz.ClassAnnotationCaster}
 * 
 * @see com.google.code.jsecurity.extension.authz.annotations.utils.casters.clazz.ClassAnnotationCaster
 * @author Valentine Yerastov
 */
public interface ClassAnnotationCasterVisitor {

	void visitRequiresPermissionsAll(RequiresPermissionsAll annotation);
	
	void visitRequiresRolesAll(RequiresRolesAll annotation);
	
	void visitRequiresUserAll(RequiresUserAll annotation);
	
	void visitRequiresGuestAll(RequiresGuestAll annotation);
	
	void visitRequiresAuthenticationAll(RequiresAuthenticationAll annotation);
	
	void visitNotFund();
}
