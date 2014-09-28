package com.cisco.fnr;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Created by sadara on 9/28/14.
 */
public class FNRApps {
    public static byte[] rankIPAddress(String ipAddress){
        int a,b,c,d ;
       // if(!IPAddress.isValidIPv4(ipAddress)) return  null ;

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
        StringBuffer sb = new StringBuffer(16);
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
    public static void main(String[] args) {

        FNR blockCipher = null;

        try {
            System.out.println("Test String");
            String plainText = "Hello123";
            byte[] plainBytes = plainText.getBytes();
            byte[] saltyBytes = getRandomBytes(20);
            SecretKeySpec spec = getSecretKeySpec("password",
                    saltyBytes);

            blockCipher = new FNR(spec.getEncoded(), "tweak", plainText.getBytes().length * Byte.SIZE);

            byte[] cipherBytes = blockCipher.encrypt(plainBytes);
            byte[] decryptBytes = blockCipher.decrypt(cipherBytes);

            if (Arrays.equals(plainBytes, decryptBytes))
                System.out.println("It works for Strings!");
        } catch (Exception e) {
            System.out
                    .println("Something went wrong .. some where for String .."
                            + e.getMessage());
        }

        try {
            System.out.println("Test IPv4 Address");
            String plainIP = "10.20.30.40";
            String decryptedIP, cipherIP;

            final byte[] intArray = rankIPAddress(plainIP);

            blockCipher = new FNR("password", "tweak", intArray.length
                    * Byte.SIZE);

            byte[] cipherBytes = blockCipher.encrypt(intArray);
            cipherIP = deRankIPAddress(cipherBytes);
            System.out.println("Given IPv4 Address is " + plainIP);
            System.out.println("Encrypted IPv4 Address is " + cipherIP);

            byte[] decryptBytes = blockCipher.decrypt(cipherBytes);
            decryptedIP = deRankIPAddress(decryptBytes);

            if (plainIP.equals(decryptedIP))
                System.out.println("It works for IPv4 Address!");
        } catch (Exception e) {
            System.out
                    .println("Something went wrong .. some where for String .."
                            + e.getMessage());
        }
    }
}
