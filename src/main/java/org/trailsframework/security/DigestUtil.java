package org.trailsframework.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility class for encoding a string with SHA-1 hash and comparing the equality of an encoded string Uses a randomly
 * generated salt with a default length of 2-4 (public class members, changeable if needed)
 * 
 * Implementation adapted from the examples provided at:
 * http://www.koders.com/java/fid9D416D88A1524FCC491B342D7B6A2E70694691D7.aspx
 * http://www.bombaydigital.com/arenared/2003/10/10/1 http://www.glenmccl.com/tip_010.htm
 * 
 */
public class DigestUtil {
	private static final Logger logger = LoggerFactory.getLogger(DigestUtil.class);

	public final static int SALT_MINLENGTH = 2;

	public final static int SALT_MAXLENGTH = 4;

	// As on Xnix
	public static final char SALT_SEPARATOR = '$';

	private static Random random = new Random();

	private static MessageDigest messageDigest = null;

	/**
	 * @return Returns true if a hash for plainTextPassword equals hash for encodedPassword. Returns false if either
	 *         parameter is null or salt wasn't found from the encodedPassword
	 * @param encodedPassword
	 *          containing the salt and the hashed password
	 * @param plainTextPassword
	 */
	public static boolean equalsEncoded(String encodedPassword, String plainTextPassword) {
		boolean result = false;
		if (encodedPassword != null && plainTextPassword != null) {
			int index = encodedPassword.indexOf(SALT_SEPARATOR);
			if (index < 1) {
				logger.warn("Salt was not found from the encodedPassword parameter. Operation expects String encodedPassword, String plainTextPassword");
			} else {
				String salt = encodedPassword.substring(0, index);
				result = encodedPassword.substring(index + 1).equals(new String(createHash(plainTextPassword, salt.getBytes())));
			}
		}
		return result;
	}

	/**
	 * @return Returns an encoded password of form <salt><SALT_SEPARATOR><passwordHash> for clearTextPassword passed in as
	 *         a parameter Returns null if the parameter was null
	 */
	public static String encode(String clearTextPassword) {
		String result = null;
		if (clearTextPassword != null) {
			byte[] saltBytes = randomString(Math.min(SALT_MINLENGTH, SALT_MAXLENGTH), Math.max(SALT_MINLENGTH, SALT_MAXLENGTH)).getBytes();
			result = new String(concatenate(saltBytes, createHash(clearTextPassword, saltBytes)));
		}
		return result;
	}

	private static byte[] createHash(String clearTextPassword, byte[] saltBytes) {
		// kaosko: We would save the cloning cost if md was a static class member,
		// but it wouldn't be threadsafe. However login is already synchronized, so it should be safe to do this.
		if (messageDigest == null) {
			try {
				messageDigest = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e) {
				logger.error("Couldn't create SHA-1 MessageDigest, password encoding doesn't work. Are you using the right version of Java?");
				return null;
			}
		}
		MessageDigest mdLocal = null;
		try {
			mdLocal = (MessageDigest) messageDigest.clone();
		} catch (CloneNotSupportedException e1) {
			logger.error("Couldn't clone static MessageDigest, password encoding doesn't work. Are you using the right version of Java?");
			return null;
		}

		mdLocal.update(clearTextPassword.getBytes());
		mdLocal.update(saltBytes);
		byte[] digest = mdLocal.digest();
		StringBuffer hexString = new StringBuffer();

		for (int i = 0; i < digest.length; i++) {
			hexString.append(Integer.toHexString(0xFF & digest[i]));
		}
		return hexString.toString().getBytes();

	}

	/**
	 * Combine two byte arrays with a salt separator in between
	 */
	private static byte[] concatenate(byte[] left, byte[] right) {
		byte[] result = new byte[left.length + 1 + right.length];
		System.arraycopy(left, 0, result, 0, left.length);
		result[left.length] = SALT_SEPARATOR;
		System.arraycopy(right, 0, result, left.length + 1, right.length);
		return result;
	}

	private static int rand(int low, int high) {
		int width = high - low + 1;
		int offset = random.nextInt() % width;
		if (offset < 0) {
			offset = -offset;
		}
		return low + offset;
	}

	private static String randomString(int low, int high) {
		int length = rand(low, high);
		byte byteArray[] = new byte[length];
		for (int i = 0; i < length; i++) {
			byteArray[i] = (byte) rand('a', 'z');
		}
		return new String(byteArray);
	}
}
