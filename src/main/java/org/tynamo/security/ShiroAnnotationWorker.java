package org.tynamo.security;

import java.lang.annotation.Annotation;
import java.util.List;

import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.plastic.PlasticClass;
import org.apache.tapestry5.plastic.PlasticMethod;
import org.apache.tapestry5.services.Environment;
import org.apache.tapestry5.services.transform.ComponentClassTransformWorker2;
import org.apache.tapestry5.services.transform.TransformationSupport;
import org.tynamo.shiro.extension.authz.aop.AopHelper;
import org.tynamo.shiro.extension.authz.aop.DefaultSecurityInterceptor;
import org.tynamo.shiro.extension.authz.aop.SecurityInterceptor;


/**
 * Transform components based on annotation.
 * <p/>
 * Support annotation on method.
 * <p/>
 * The following rules
 * <ul>
 * <li>Annotations on methods are <b>not</b> inherited.</li>
 * <li>The annotations only in target class, unlike services </li>
 * <ul>
 * <p/>
 *
 * @see org.tynamo.security.services.SecurityModule#buildSecurityFilter(org.slf4j.Logger,
 *      org.apache.tapestry5.services.ComponentEventLinkEncoder,
 *      org.apache.tapestry5.services.ComponentClassResolver,
 *      org.tynamo.security.services.ClassInterceptorsCache)
 */
public class ShiroAnnotationWorker implements ComponentClassTransformWorker2
{
	private final Environment environment;

	public ShiroAnnotationWorker(Environment environment)
	{
		this.environment = environment;
	}

	@Override
	public void transform(PlasticClass plasticClass, TransformationSupport support, MutableComponentModel model)
	{
		for (Class<? extends Annotation> annotationClass : AopHelper.getAutorizationAnnotationClasses())
		{
			List<PlasticMethod> methodsToTransform = plasticClass.getMethodsWithAnnotation(annotationClass);

			for (PlasticMethod tm : methodsToTransform) processTransform(tm, tm.getAnnotation(annotationClass));
		}
	}

	private void processTransform(PlasticMethod tm, Annotation annotation)
	{
		final SecurityInterceptor interceptor = new DefaultSecurityInterceptor(annotation);

		MethodAdvice advice = new MethodAdvice()
		{
			public void advise(MethodInvocation invocation)
			{
				environment.push(MethodInvocation.class, invocation);
				try
				{
					interceptor.intercept();
				}
				finally
				{
					environment.pop(MethodInvocation.class);
				}
				invocation.proceed();
			}
		};

		tm.addAdvice(advice);

	}

}
