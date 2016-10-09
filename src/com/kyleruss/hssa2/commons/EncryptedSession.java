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
    
    public EncryptedSession()
    {
        initAESKey();
    }
    
    public EncryptedSession(byte[] AESKey, byte[] data, Key asymKey)
    {
        this.AESKey     =   AESKey;
        this.data       =   data;
        this.asymKey    =   asymKey;
    }
    
    public void initAES(int mode)
    {
        try
        {
            iv  =   new byte[16];
            IvParameterSpec ivParam =   new IvParameterSpec(iv);
            SecretKeySpec keySpec   =   new SecretKeySpec(AESKey, "AES");
            AESCipher               =   Cipher.getInstance("AES/CBC/PKCS5Padding");
            AESCipher.init(mode, keySpec, ivParam);
        }
        
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            System.out.println("[Error] Failed to initialize AES Cipher: " + e.getMessage());
        }
    }
    
    public byte[] processData() throws IllegalBlockSizeException, BadPaddingException
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
    
    public void unlock() 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
    IllegalBlockSizeException, BadPaddingException
    {
        Cipher asymCipher   =   Cipher.getInstance("RSA");
        asymCipher.init(Cipher.DECRYPT_MODE, asymKey);
        AESKey              =   asymCipher.doFinal(AESKey);
        initAES(Cipher.DECRYPT_MODE);
        processData();
    }
    
    private void initAESKey()
    {
        AESKey  =   new byte[16];
        rGen.nextBytes(AESKey);
    }

    public byte[] getAESKey() 
    {
        return AESKey;
    }

    public void setAESKey(byte[] AESKey) 
    {
        this.AESKey = AESKey;
    }

    public SecureRandom getrGen() 
    {
        return rGen;
    }

    public void setrGen(SecureRandom rGen) 
    {
        this.rGen = rGen;
    }

    public byte[] getData() 
    {
        return data;
    }

    public void setData(byte[] data) 
    {
        this.data = data;
    }

    public byte[] getIv() 
    {
        return iv;
    }

    public void setIv(byte[] iv) 
    {
        this.iv = iv;
    }

    public Cipher getAESCipher() 
    {
        return AESCipher;
    }

    public void setAESCipher(Cipher AESCipher) 
    {
        this.AESCipher = AESCipher;
    }

    public Key getAsymKey() 
    {
        return asymKey;
    }

    public void setAsymKey(Key asymKey) 
    {
        this.asymKey = asymKey;
    }
}