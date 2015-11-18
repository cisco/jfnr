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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.concurrent.Exchanger;

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
        password = "password"; // Not for production
        tweak = "tweak" ; // Not for production
        try {
            initKeySpec();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] saltyBytes = FNRUtils.getRandomBytes(20);
        keySpec = FNRUtils.getSecretKeySpec(password, saltyBytes);
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

    public void testTweakSize(){

        System.out.println("Testing tweak size");
        try {
            tweak ="thisislongtweakeeeeeeee"  ;
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 32);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid tweak size", false);
        }

        try {
            tweak ="smalltweak"  ;
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 32);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid tweak size", false);
        }

        try {
            tweak ="tweak"  ;
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 32);
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid tweak size", false);
        }

    }

    public void testBlockSize(){
        System.out.println("Testing Block size");

        try {
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 0);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid block size", false);
        }

        try {
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 130);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid block size", false);
        }

        try {
            blockCipher = new FNR(keySpec.getEncoded(), tweak, 32);
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid block size", false);
        }
    }

    public void testInputLength(){
        System.out.println("Testing Input Lengths in Encryption");
        byte[] bytes = new byte[10];
        Arrays.fill(bytes, (byte) 0); //
        blockCipher = new FNR(keySpec.getEncoded(), tweak, 32);  // 4 bytes

        try {
            blockCipher.encrypt(bytes);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid input size", false);
        }

        try {
            blockCipher.decrypt(bytes);
        }
        catch (InvalidParameterException e){
            assertFalse("Invalid input size", false);
        }

        bytes = new byte[4];
        Arrays.fill(bytes, (byte) 0); //

        try {
            blockCipher.encrypt(bytes);
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid input size" + e.getMessage(), false);
        }

        try {
            blockCipher.decrypt(bytes);
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid input size" + e.getMessage(), false);
        }
    }

    public void testKeySize(){
        System.out.println("Testing Key Sizes in Encryption");
        byte[] plainBytes = new byte[4];
        byte[] keyBytes =  FNRUtils.getRandomBytes(20);

        Arrays.fill(plainBytes, (byte) 0); //

        try {
            blockCipher = new FNR(keyBytes, tweak, 32);  // 4 bytes
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid key size", true);
        }

        password = "password123344555555555"; // Not for production
        tweak = "tweak" ; // Not for production

        try {
            initKeySpec();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        try {
            blockCipher = new FNR(keyBytes, tweak, 32);  // 4 bytes
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid key size", true);
        }

        try {
            blockCipher = new FNR(null, tweak, 32);  // 4 bytes
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid key size", true);
        }

        try {
            keyBytes =  FNRUtils.getRandomBytes(16);
            blockCipher = new FNR(keyBytes, tweak, 32);  // 4 bytes
        }
        catch (InvalidParameterException e){
            assertTrue("Invalid key size", false);
        }

    }


}