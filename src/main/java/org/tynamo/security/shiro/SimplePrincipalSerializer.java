package org.tynamo.security.shiro;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.util.Collection;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.shiro.lang.io.SerializationException;
import org.apache.shiro.lang.io.Serializer;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

/**
 * Creates A GZIPed rememberMe cookie, based on the patch for SHIRO-226 (https://issues.apache.org/jira/browse/SHIRO-226)
 */

public class SimplePrincipalSerializer implements Serializer<PrincipalCollection> {
	/**
	 * Magic number to signal that this is a SimplePrincipalSerializer file so that we don't try to decode something crap.
	 */
	private static final int MAGIC = 0x0BADBEEF;
	@SuppressWarnings("rawtypes")
	private final Collection<Class> knownPrincipalTypes;

	@SuppressWarnings("rawtypes")
	public SimplePrincipalSerializer(Collection<Class> knownPrincipalTypes) {
		this.knownPrincipalTypes = knownPrincipalTypes;
	}

	public byte[] serialize(PrincipalCollection pc) throws SerializationException {
		ByteArrayOutputStream ba = new ByteArrayOutputStream();

		try {
			GZIPOutputStream gout = new GZIPOutputStream(ba);
			ObjectOutputStream out = new ObjectOutputStream(gout);

			// Write the magic number which allows us to decode it later on
			out.writeInt(MAGIC);

			// Limited to 32768 realms. Should be enough for everybody.
			out.writeShort(pc.getRealmNames().size());

			for (String realm : pc.getRealmNames()) {
				out.writeUTF(realm);

				Collection<?> principals = pc.fromRealm(realm);

				// Again, limited to 32768 principals.
				out.writeShort(principals.size());

				for (Object principal : principals) {
					out.writeObject(principal);
				}
			}
			gout.finish();
		} catch (IOException e) {
			throw new SerializationException(e.getMessage());
		}
		return ba.toByteArray();
	}

	public PrincipalCollection deserialize(byte[] serialized) throws SerializationException {
		ByteArrayInputStream ba = new ByteArrayInputStream(serialized);

		try {
			GZIPInputStream gin = new GZIPInputStream(ba);
			ObjectInputStream in = new ObjectInputStream(gin) {
				// only allow deserializing known principal types to protect against deserialization vulnerability
				// see https://www.contrastsecurity.com/security-influencers/java-serialization-vulnerability-threatens-millions-of-applications
				protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
					Class<?> aClass = super.resolveClass(osc);
					if (knownPrincipalTypes.contains(aClass)) return aClass;
					throw new SecurityException("Security violation: attempt to deserialize unauthorized " + aClass);
				}
			};

			SimplePrincipalCollection pc = new SimplePrincipalCollection();

			// Check magic number
			if (in.readInt() != MAGIC)
				throw new SerializationException(
					"Not valid magic number while deserializing stored PrincipalCollection - possibly obsolete cookie.");

			int numRealms = in.readShort();

			// realms loop
			for (int i = 0; i < numRealms; i++) {
				String realmName = in.readUTF();

				int numPrincipals = in.readShort();

				// principals loop
				for (int j = 0; j < numPrincipals; j++) {
					Object principal = in.readObject();

					pc.add(principal, realmName);
				}
			}

			return pc;
		} catch (IOException e) {
			throw new SerializationException(e.getMessage());
		} catch (ClassNotFoundException e) {
			throw new SerializationException(e.getMessage());
		}
	}
}