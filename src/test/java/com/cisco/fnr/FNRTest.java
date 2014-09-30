package com.cisco.fnr;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class FNRTest extends TestCase {
    FNR blockCipher ;
    SecretKeySpec keySpec ;
    String password;
    String tweak;
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public FNRTest (String  testName)

    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( FNRTest.class );
    }


    public void setUp() throws Exception {
        super.setUp();
        blockCipher = null;
        byte[] saltyBytes = FNRUtils.getRandomBytes(20);
        password = "password"; // Not for production
        tweak = "tweak" ; // Not for production
        try {
            // Change Password for production ;
            keySpec = FNRUtils.getSecretKeySpec(password, saltyBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void tearDown() throws Exception {

    }
    /**
     * Rigourous Test :-)
     */
    public void testString(){

        try {
            System.out.println("Test String");
            String plainText = "Hello123";
            byte[] plainBytes = plainText.getBytes();

            blockCipher = new FNR(keySpec.getEncoded(), tweak, plainText.getBytes().length * Byte.SIZE);

            byte[] cipherBytes = blockCipher.encrypt(plainBytes);
            byte[] decryptBytes = blockCipher.decrypt(cipherBytes);

            if (Arrays.equals(plainBytes, decryptBytes)) {
                System.out.println("It works for Strings!");
                assertTrue(true);
            }
        } catch (Exception e) {
            System.out
                    .println("Something went wrong .. some where for String .."
                            + e.getMessage());
                assertTrue(false);
        }
    }

    public void testIPv4(){

        try {
            System.out.println("Test IPv4 Address");
            String plainIP = "10.20.30.40";
            String decryptedIP, cipherIP;

            final byte[] intArray = FNRUtils.rankIPAddress(plainIP);

            blockCipher = new FNR(keySpec.getEncoded(), tweak, intArray.length * Byte.SIZE);

            byte[] cipherBytes = blockCipher.encrypt(intArray);
            cipherIP = FNRUtils.deRankIPAddress(cipherBytes);
            System.out.println("Given IPv4 Address is " + plainIP);
            System.out.println("Encrypted IPv4 Address is " + cipherIP);

            byte[] decryptBytes = blockCipher.decrypt(cipherBytes);
            decryptedIP = FNRUtils.deRankIPAddress(decryptBytes);

            if (plainIP.equals(decryptedIP)) {
                System.out.println("It works for IPv4 Address!");
                assertTrue(true);
            }
        } catch (Exception e) {
            System.out
                    .println("Something went wrong .. some where for String .."
                            + e.getMessage());

            assertTrue(false);
        }

    }

}