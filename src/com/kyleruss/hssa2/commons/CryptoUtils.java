//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.hssa2.commons;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils 
{
    private static final SecureRandom rGen;
    public static final String ALPHA_NUMERIC    =   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    static
    {
        rGen    =   new SecureRandom();
    }
            
    //Generates a random string using the passed charset
    //Length of the string is determined by the passed length
    public static String generateRandomString(int length, String charset)
    {
        StringBuilder builder   =   new StringBuilder();
        
        for(int i = 0; i < length; i++)
        {
            //No charset passed, generate any random character
            if(charset == null)
                builder.append((char) rGen.nextInt(Character.MAX_VALUE));
            
            //Generate characters from the passed charset
            else
            {
                int index   =   rGen.nextInt(charset.length());
                builder.append(charset.charAt(index));
            }
        }
        
        return builder.toString();
    }
    
    //Creates a new public or private key from the passed key bytes
    //publicKey: true to create a public key instance and false to create a private key instance
    public static Key stringToAsymKey(byte[] keyBytes, boolean publicKey) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeySpec keySpec             =   publicKey? new X509EncodedKeySpec(keyBytes) : new PKCS8EncodedKeySpec(keyBytes);   
        KeyFactory keyFactory       =   KeyFactory.getInstance("RSA");
        return publicKey? keyFactory.generatePublic(keySpec) : keyFactory.generatePrivate(keySpec);
    }
    
    //Generates and returns a random byte array 
    //Length of the bytes is determined by the passed length
    public static byte[] generateRandomBytes(int length)
    {
        byte[] bytes    =   new byte[length];
        rGen.nextBytes(bytes);
        return bytes;
    }
}
