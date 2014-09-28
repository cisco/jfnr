package com.cisco.fnr;



import com.sun.jna.Native;

/**
 * FNR API - uses JNA for calling native implementation of FNR code
 *
 * Created by bhanu on 08/09/14.
 *
 * @author bhanu
 */
public class FNR  {

	private FNRLibrary.fnr_expanded_key.ByReference expanded_key = null;
	private FNRLibrary.fnr_expanded_tweak.ByReference expanded_tweak = null;
	private static FNRLibrary fnrInstance = (FNRLibrary) Native.loadLibrary(
			"fnr", FNRLibrary.class);
	private static FNRLibrary sslInstance = (FNRLibrary) Native.loadLibrary(
			"ssl", FNRLibrary.class);

	public FNR(String password, String tweak, int inputLength) throws Exception {
		// Load the Library

		// 1. FNR Init
		fnrInstance.FNR_init();

		// 2. expand key
		expanded_key = fnrInstance.FNR_expand_key(password.getBytes(), 128,
				new FNRLibrary.size_t(inputLength));

		// 3. create tweak
		expanded_tweak = new FNRLibrary.fnr_expanded_tweak.ByReference();
		fnrInstance.FNR_expand_tweak(expanded_tweak, expanded_key,
				tweak.getBytes(), new FNRLibrary.size_t(tweak.length()));
	}

	public FNR(byte[] encoded, String tweak, int blockSize) {
		tweak = "tweak";
		
		// Load the Library
		fnrInstance = (FNRLibrary) Native.loadLibrary("fnr", FNRLibrary.class);
		// 1. FNR Init
		fnrInstance.FNR_init();

		// 2. expand key
		expanded_key = fnrInstance.FNR_expand_key(encoded, 128,
				new FNRLibrary.size_t(blockSize));

		// 3. create tweak
		expanded_tweak = new FNRLibrary.fnr_expanded_tweak.ByReference();
		fnrInstance.FNR_expand_tweak(expanded_tweak, expanded_key,
				tweak.getBytes(), new FNRLibrary.size_t(tweak.length()));
	}

	public byte[] encrypt(byte[] plainBytes) throws Exception {
		if (plainBytes == null || plainBytes.length > 8
				|| plainBytes.length <= 0)
			throw new Exception("Invalid Input Length");

		byte[] cipherBytes = new byte[plainBytes.length];
		fnrInstance.FNR_encrypt(expanded_key, expanded_tweak, plainBytes,
				cipherBytes);
		return cipherBytes;
	}

	public byte[] decrypt(byte[] cipherBytes) throws Exception {
		if (cipherBytes == null || cipherBytes.length > 8
				|| cipherBytes.length <= 0)
			throw new Exception("Invalid Input Length");

		byte decryptedBytes[] = new byte[cipherBytes.length];

		fnrInstance.FNR_decrypt(expanded_key, expanded_tweak, cipherBytes,
				decryptedBytes);

		return decryptedBytes;
	}

	public byte[] encrypt(byte[] plainBytes, byte[] ivBytes) throws Exception {
		return new byte[0];
	}

	public byte[] decrypt(byte[] cipherText, byte[] ivBytes) throws Exception {
		return new byte[0];
	}

	public byte[] getIvBytes(long id) {
		return new byte[0];
	}


}
