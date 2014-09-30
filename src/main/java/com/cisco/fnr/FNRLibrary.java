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
import com.sun.jna.IntegerType;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public interface FNRLibrary extends Library {

    public static class fnr_expanded_key extends Structure {

		public int full_bytes;
		public char final_mask;
		public int full_elements;
		public byte final_element_mask;
		public int num_bits;
		public size_t size;
		AES_KEY expanded_aes_key;
		byte[] aes_key;
		byte green[];
		byte red[] = new byte[1];
    	
        @Override
        protected List getFieldOrder() {

            return Arrays.asList(new String[]{"final_element_mask",
                    "final_mask", "full_bytes", "full_elements",
                    "num_bits", "size",});
        }

        public static class ByReference extends fnr_expanded_key implements
                Structure.ByReference {
        }

        public static class ByValue extends fnr_expanded_key implements
                Structure.ByValue {
        }

    }

    public static class fnr_expanded_tweak extends Structure {
        public static class ByReference extends fnr_expanded_tweak
                implements Structure.ByReference {
        }

        public static class ByValue extends fnr_expanded_tweak implements
                Structure.ByValue {
        }

        public byte[] tweak = new byte[15];

        @Override
        protected List getFieldOrder() {
            return Arrays.asList(new String[] { "tweak" });
        }
    }

    public static class AES_KEY extends Structure {

        public long rd_key[] = new long[4 * (14 + 1)];
        int rounds;

        @Override
        protected List getFieldOrder() {
            return Arrays.asList(new String[] { "rd_key", "rounds" });
        }

        public static class ByReference extends AES_KEY implements
                Structure.ByReference {
        }

        public static class ByValue extends AES_KEY implements
                Structure.ByValue {
        }

    }

    public static class size_t extends IntegerType {
        public size_t() {
            this(0);
        }

        public size_t(long value) {
            super(Native.SIZE_T_SIZE, value);
        }
    }

    public void FNR_init();

    public fnr_expanded_key.ByReference FNR_expand_key(byte[] aes_key,
                                                       int aes_key_size, size_t num_bits);

    public void FNR_expand_tweak(
            fnr_expanded_tweak.ByReference expanded_tweak,
            fnr_expanded_key.ByReference key, byte[] tweak, size_t len_tweak);

    void FNR_encrypt(fnr_expanded_key.ByReference key,
                     fnr_expanded_tweak.ByReference tweak, byte[] plaintext,
                     byte[] ciphertext);

    void FNR_decrypt(fnr_expanded_key.ByReference key,
                     fnr_expanded_tweak.ByReference tweak, byte[] ciphertext,
                     byte[] plaintext);

}
