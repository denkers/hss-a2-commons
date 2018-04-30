//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.cryptocommons;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoCommons 
{
    //Decrypts the passed cipher text with AES using a PBE generated key
    //The password and salt param are used to generate the PBE key
    //Both the password and salt should be padded or MD5 hashed to generate 128bit length
    //Password is input as the key while salt is used as the IV
    //Uses CBC mode with PKCS5 padding
    public static byte[] pbeDecryptBytes(byte[] password, byte[] salt, byte[] ciphertext) 
    throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKeySpec secretKey =   new SecretKeySpec(password, "AES");
        IvParameterSpec iv      =   new IvParameterSpec(salt);
        
        Cipher cipherDec    =   Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDec.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plaintext = cipherDec.doFinal(ciphertext);
        
        return plaintext;
    }
    
    //See CryptoCommons@pbeDecryptBytes
    //Returns a decrypted string of the cipher text
    public static String pbeDecrypt(byte[] password, byte[] salt, byte[] ciphertext) 
    throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] plaintext    =   pbeDecryptBytes(password, salt, ciphertext);
        return new String(plaintext);
    }
    
    //Encrypts the passed plaintext with AES using a PBE generated key
    //The password and salt param are used to generate the PBE key
    //Both the password and salt should be padded or MD5 hashed to generate 128bit length
    //Password is input as the key while salt is used as the IV
    //Uses CBC mode with PKCS5 padding
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
    
    //Performs AES encryption/decryption on the passed text bytes
    //keySpec: The secret key to encrypt/decrypt the cipher with
    //text: the plaintext/ciphertext
    //encrypt: true if you wish to encrypt the plaintext; otherwise false to decrypt it
    public static byte[] AES(SecretKeySpec keySpec, byte[] text, boolean encrypt) 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException
    {
        byte[] iv                   =   new byte[16];
        IvParameterSpec ivParam     =   new IvParameterSpec(iv);
        Cipher cipher               =   Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(encrypt? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, ivParam);
        
        return cipher.doFinal(text);
    }
    
    //Encrypts the passed plaintext with RSA using the provided public key
    //Runs in ECB mode with PKCS1 padding
    //Ensure decryption follows mode and padding scheme
    //Returns the encrypted bytes
    public static byte[] publicEncrypt(byte[] plaintext, Key key) 
    throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher       =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
    
    //Decrypts the passed ciphertext with RSA using the provided public key
    //Runs in ECB mode with PKCS1 padding
    //Returns the decrypted bytes
    public static byte[] publicDecryptBytes(byte[] ciphertext, Key key) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher cipher           =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plaintextBytes   =   cipher.doFinal(ciphertext);
        return plaintextBytes;
    }
    
    //See CryptoCommons@publicDecryptBytes
    //Returns the decrypted plain text string
    public static String publicDecrypt(byte[] ciphertext, Key key) 
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        byte[] plaintextBytes   =   publicDecryptBytes(ciphertext, key);
        return new String(plaintextBytes);
    }
    
    //Returns the MD5 hashed bytes of the passed data
    public static byte[] generateHash(byte[] data) 
    throws NoSuchAlgorithmException
    {
        return generateHash(data, "MD5");
    }
    
    //Hashes the passed data using the provided algorithm
    //For default see CryptoCommons@generateHash(byte[]) which defaults to MD5
    //Returns the hashed bytes of the passed data
    public static byte[] generateHash(byte[] data, String algorithm) 
    throws NoSuchAlgorithmException
    {
        MessageDigest md    =  MessageDigest.getInstance(algorithm);
        byte[] digest       =   md.digest(data);
        return digest;
    }
}
