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
    
    public static byte[] pbeEncrypt(byte[] password, byte[] salt, byte[] plaintext) 
    throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKeySpec secretKey =   new SecretKeySpec(password, "AES");
        IvParameterSpec iv      =   new IvParameterSpec(salt);
        
        Cipher cipher           =   Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);
       return ciphertext;
    }
    
    public static byte[] publicEncrypt(byte[] plaintext, Key key) 
    throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher       =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
    
    public static byte[] publicDecryptBytes(byte[] ciphertext, Key key) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher cipher           =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plaintextBytes   =   cipher.doFinal(ciphertext);
        return plaintextBytes;
    }
    
    public static String publicDecrypt(byte[] ciphertext, Key key) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] plaintextBytes   =   publicDecryptBytes(ciphertext, key);
        return new String(plaintextBytes);
    }
    
    public static byte[] generateHash(byte[] data) 
    throws NoSuchAlgorithmException
    {
        return generateHash(data, "MD5");
    }
    
    public static byte[] generateHash(byte[] data, String algorithm) 
    throws NoSuchAlgorithmException
    {
        MessageDigest md    =  MessageDigest.getInstance(algorithm);
        byte[] digest       =   md.digest(data);
        return digest;
    }
}
