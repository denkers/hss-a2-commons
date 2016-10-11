//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.hssa2.commons;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoCommons 
{
    public static String pbeDecrypt(byte[] password, byte[] salt, byte[] ciphertext) 
    throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKeySpec secretKey =   new SecretKeySpec(password, "AES");
        IvParameterSpec iv      =   new IvParameterSpec(salt);
        
        Cipher cipherDec    =   Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDec.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plaintext = cipherDec.doFinal(ciphertext);
        return new String(plaintext);
    }
    
    public static String pbeEncrypt(byte[] password, byte[] salt, byte[] plaintext) 
    throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKeySpec secretKey =   new SecretKeySpec(password, "AES");
        IvParameterSpec iv      =   new IvParameterSpec(salt);
        
        Cipher cipher           =   Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);
        return Base64.getEncoder().encodeToString(ciphertext);
    }
    
    public static String publicEncrypt(String plaintext, Key key) 
    throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher       =   Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes  =   cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(cipherBytes);
    }
    
    public static String publicDecrypt(String ciphertext, Key key) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher cipher           =   Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded          =   Base64.getDecoder().decode(ciphertext.getBytes("UTF-8"));
        byte[] plaintextBytes   =   cipher.doFinal(decoded);
        return new String(plaintextBytes);
    }
    
    public static String generateHash(byte[] data) 
    throws NoSuchAlgorithmException
    {
        return generateHash(data, "MD5");
    }
    
    public static String generateHash(byte[] data, String algorithm) 
    throws NoSuchAlgorithmException
    {
        MessageDigest md    =  MessageDigest.getInstance(algorithm);
        byte[] digest       =   md.digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }
}
