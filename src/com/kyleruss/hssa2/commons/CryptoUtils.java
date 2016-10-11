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
import java.util.Base64;

public class CryptoUtils 
{
    private static final SecureRandom rGen;
    public static final String ALPHA_NUMERIC    =   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    static
    {
        rGen    =   new SecureRandom();
    }
            
    public static String generateRandomString(int length, String charset)
    {
        StringBuilder builder   =   new StringBuilder();
        
        for(int i = 0; i < length; i++)
        {
            if(charset == null)
                builder.append((char) rGen.nextInt(Character.MAX_VALUE));
            else
            {
                int index   =   rGen.nextInt(charset.length());
                builder.append(charset.charAt(index));
            }
        }
        
        return builder.toString();
    }
    
    public static Key stringToAsymKey(String keyValue, boolean decode, boolean publicKey) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] keyBytes             =   decode? Base64.getDecoder().decode(keyValue.getBytes("UTF-8")) : keyValue.getBytes("UTF-8");
        KeySpec keySpec             =   publicKey? new X509EncodedKeySpec(keyBytes) : new PKCS8EncodedKeySpec(keyBytes);   
        KeyFactory keyFactory       =   KeyFactory.getInstance("RSA");
        return publicKey? keyFactory.generatePublic(keySpec) : keyFactory.generatePrivate(keySpec);
    }
    
    
    public static byte[] generateRandomBytes(int length)
    {
        byte[] bytes    =   new byte[length];
        rGen.nextBytes(bytes);
        return bytes;
    }
}
