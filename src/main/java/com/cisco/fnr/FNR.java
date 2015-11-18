package com.cisco.fnr;

/*
*    jfnr  - uses JNA for calling native implementation of libFNR
*
*    jfnr extensions are contributed by Bhanu Prakash Gopularam (bhanprak@cisco.com)
*
*    libFNR - A reference implementation library for FNR encryption mode.
*
*    FNR represents "Flexible Naor and Reingold" mode

*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.

*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    jfnr extensions are contributed by Bhanu Prakash Gopularam (bhanprak@cisco.com)
*
*    Copyright (C) 2014 , Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/

import com.sun.jna.Native;


import java.security.InvalidParameterException;

public class FNR  {

    private int blockSize;
    private FNRLibrary.fnr_expanded_key.ByReference expanded_key = null;
	private FNRLibrary.fnr_expanded_tweak.ByReference expanded_tweak = null;
	private FNRLibrary fnrInstance ;


	public FNR(byte[] key, String tweak, int blockSize) throws InvalidParameterException{
        final int MAX_BLOCK_SIZE = 128;
        final int KEY_SIZE = 128;
        final int MAX_TWEAK_LENGTH = 8;
        final int MIN_BLOCK_SIZE = 16;

        if( blockSize < MIN_BLOCK_SIZE || blockSize >= MAX_BLOCK_SIZE)
           throw   new InvalidParameterException("Invalid Block Size");

        if(tweak.length() > MAX_TWEAK_LENGTH)
            throw   new InvalidParameterException("Invalid Tweak Size");

        if(key == null || key.length * 8 != KEY_SIZE)
            throw   new InvalidParameterException("Invalid Key Size");


          try {
              // Load the Library
              fnrInstance = (FNRLibrary) Native.loadLibrary("fnr", FNRLibrary.class);

              // 1. FNR Init
              fnrInstance.FNR_init();

              // 2. expand key
              expanded_key = fnrInstance.FNR_expand_key(key, MAX_BLOCK_SIZE,
                      new FNRLibrary.size_t(blockSize));

              // 3. create tweak
              expanded_tweak = new FNRLibrary.fnr_expanded_tweak.ByReference();
              fnrInstance.FNR_expand_tweak(expanded_tweak, expanded_key,
                      tweak.getBytes(), new FNRLibrary.size_t(tweak.length()));

          }
          catch (UnsatisfiedLinkError error){
              throw  new InvalidParameterException("Invalid library file" +error.getMessage()) ;
          }
        this.blockSize = blockSize;
	}

	public byte[] encrypt(byte[] plainBytes) throws InvalidParameterException {
		if (plainBytes == null
                || (plainBytes.length* Byte.SIZE)  != blockSize)
			throw new InvalidParameterException("Invalid Input Length");

		byte[] cipherBytes = new byte[plainBytes.length];
		fnrInstance.FNR_encrypt(expanded_key, expanded_tweak, plainBytes,
				cipherBytes);
		return cipherBytes;
	}

	public byte[] decrypt(byte[] cipherBytes) throws InvalidParameterException {
		if (cipherBytes == null
                || (cipherBytes.length * Byte.SIZE) != blockSize)
			throw new InvalidParameterException("Invalid Input Length");

		byte decryptedBytes[] = new byte[cipherBytes.length];

		fnrInstance.FNR_decrypt(expanded_key, expanded_tweak, cipherBytes,
				decryptedBytes);

		return decryptedBytes;
	}

}
