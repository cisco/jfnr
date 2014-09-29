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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class FNRUtils {
    public static byte[] rankIPAddress(String ipAddress){
        int a,b,c,d ;
        String[] comps = ipAddress.split("\\.");
        a = Integer.valueOf( comps[0]);
        b = Integer.valueOf( comps[1]);
        c = Integer.valueOf( comps[2]);
        d = Integer.valueOf( comps[3]);

        int ip = (a << 24) + (b << 16) + (c << 8) + d;

        return ByteBuffer.allocate(4).putInt(ip).array();
    }


    public static String deRankIPAddress(byte[] ipBytes){
        final int ip = ByteBuffer.wrap(ipBytes).getInt();
        return toIPv4String(ip);

    }
    public  static String toIPv4String (int address)
    {
        StringBuilder sb = new StringBuilder(16);
        for (int ii = 3; ii >= 0; ii--)
        {
            sb.append((int) (0xFF & (address >> (8*ii))));
            if (ii > 0) sb.append(".");
        }
        return sb.toString();
    }

    public static SecretKeySpec getSecretKeySpec(String password, byte[] saltyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int pswdIterations = 65536  ;
        int keySize = 128;

        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec =  new PBEKeySpec( password.toCharArray(),saltyBytes,
                pswdIterations, keySize );


        SecretKey secretKey = factory.generateSecret(spec);

        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public static byte[] getRandomBytes(int count) {

        // Generate the Salt
        SecureRandom random = new SecureRandom();
        byte[] saltyBytes = new byte[count];
        random.nextBytes(saltyBytes);

        return saltyBytes;
    }

}
