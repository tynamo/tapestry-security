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
package org.tynamo.shiro.extension.authz.annotations.utils.casters.method;

import org.apache.shiro.authz.annotation.*;

/**
 * Visitor interface for use in
 * {@link org.tynamo.shiro.extension.authz.annotations.utils.casters.method.MethodAnnotationCaster}
 *
 * @see org.tynamo.shiro.extension.authz.annotations.utils.casters.method.MethodAnnotationCaster
 */
public interface MethodAnnotationCasterVisitor
{

	void visitRequiresPermissions(RequiresPermissions annotation);

	void visitRequiresRoles(RequiresRoles annotation);

	void visitRequiresUser(RequiresUser annotation);

	void visitRequiresGuest(RequiresGuest annotation);

	void visitRequiresAuthentication(RequiresAuthentication annotation);

	void visitNotFound();

}
