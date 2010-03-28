package org.tynamo.security;

/**
 * key/value pair
 * <p>
 * The key/value pair must conform to the format defined by the {@link FilterChainManager#createChain(String,String)}
 * JavaDoc - the property key is an ant URL path expression and the value is the comma-delimited chain definition.
 */
public class FilterChainDefinition
{
	private String antUrlPathExpression;
	private String chainDefinition;

	public FilterChainDefinition(String antUrlPathExpression, String chainDefinition)
	{
		this.antUrlPathExpression = antUrlPathExpression;
		this.chainDefinition = chainDefinition;
	}

	public String getAntUrlPathExpression()
	{
		return antUrlPathExpression;
	}

	public String getChainDefinition()
	{
		return chainDefinition;
	}

	@Override
	public String toString()
	{
		return antUrlPathExpression + " = " + chainDefinition;
	}
}
