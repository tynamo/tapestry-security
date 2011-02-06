package org.apache.shiro.web.filter;

import org.apache.shiro.util.AntPathMatcher;

public class PathMatchingFilterPatternMatcherChanger {
	public static void setLowercasingPathMatcher(PathMatchingFilter filter) {
		AntPathMatcher pathMatcher = new AntPathMatcher() {
	    @Override
			public boolean matches(String pattern, String source) {
	    	return super.matches(pattern, source.toLowerCase());
	    }
		};
		
		filter.pathMatcher = pathMatcher;
	}
}
