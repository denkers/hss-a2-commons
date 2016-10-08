//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.hssa2.commons;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptedSession 
{
    private byte[] AESKey;
    private SecureRandom rGen;
    private byte[] data;
    private byte[] iv;
    private Cipher AESCipher;
    private Key asymKey;
    
    public void initAES()
    {
        try
        {
            iv  =   new byte[16];
            IvParameterSpec ivParam =   new IvParameterSpec(iv);
            SecretKeySpec keySpec   =   new SecretKeySpec(AESKey, "AES");
            AESCipher               =   Cipher.getInstance("AES/CBC/PKCS5Padding");
            AESCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParam);
        }
        
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            System.out.println("[Error] Failed to initialize AES Cipher: " + e.getMessage());
        }
    }
    
    public byte[] encryptData() throws IllegalBlockSizeException, BadPaddingException
    {
        if(AESCipher == null) return null;
        return AESCipher.doFinal(data);
    }
    
    public byte[] encryptKey() 
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher asymCipher   =   Cipher.getInstance("RSA");
        asymCipher.init(Cipher.ENCRYPT_MODE, asymKey);
        return asymCipher.doFinal(AESKey);
    }
    
    public void initAESKey()
    {
        AESKey  =   new byte[16];
        rGen.nextBytes(AESKey);
    }
    
    
}
