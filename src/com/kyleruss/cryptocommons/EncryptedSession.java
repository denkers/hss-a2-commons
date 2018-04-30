//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.cryptocommons;

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
    //The AES secret key bytes
    private byte[] AESKey;
    
    //The plain/cipher text bytes
    private byte[] data;
    
    //The AES IV - default is empty[16]
    private byte[] iv;
    
    //The AES cipher instance used to encrypt the data
    private Cipher AESCipher;
    
    //A public/private RSA key 
    //used to encrypt/decrypt the AES key
    private Key asymKey;
    
    public EncryptedSession()
    {
        initAESKey();
    }
    
    public EncryptedSession(byte[] data, Key asymKey)
    {
        this.data       =   data;
        this.asymKey    =   asymKey;
        initAESKey();
    }
    
    public EncryptedSession(byte[] AESKey, byte[] data, Key asymKey)
    {
        this.AESKey     =   AESKey;
        this.data       =   data;
        this.asymKey    =   asymKey;
    }
    
    //Initializes the AES cipher, iv and keys
    //Uses CBC mode and PKCS5 padding
    //mode: enter the cipher mode (Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE)
    public void initCipher(int mode)
    {
        try
        {
            //initialize IV
            iv  =   new byte[16];
            IvParameterSpec ivParam =   new IvParameterSpec(iv);
            
            //initialize AES secret key
            SecretKeySpec keySpec   =   new SecretKeySpec(AESKey, "AES");
            
            //initialize AES cipher
            AESCipher               =   Cipher.getInstance("AES/CBC/PKCS5Padding");
            AESCipher.init(mode, keySpec, ivParam);
        }
        
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            System.out.println("[Error] Failed to initialize AES Cipher: " + e.getMessage());
        }
    }
    
    //Encrypts or decrypts the data using the AES cipher
    //EncryptedSession@initCipher should be called before
    public byte[] processData() 
    throws IllegalBlockSizeException, BadPaddingException
    {
        if(AESCipher == null) return null;
        return AESCipher.doFinal(data);
    }
    
    //Encrypts the AES secret key with the public/private key 
    //Uses RSA encryption in ECB mode with PKCS1 padding
    public byte[] encryptKey() 
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher asymCipher   =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymCipher.init(Cipher.ENCRYPT_MODE, asymKey);
        return asymCipher.doFinal(AESKey);
    }
    
    //Unlocks this encrypted message
    //First decrypts the secret key with RSA decryption using the private/public key
    //Then AES decrypts the data using the decrypted secret key
    public void unlock() 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
    IllegalBlockSizeException, BadPaddingException
    {
        Cipher asymCipher   =   Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymCipher.init(Cipher.DECRYPT_MODE, asymKey);
        AESKey              =   asymCipher.doFinal(AESKey);
        initCipher(Cipher.DECRYPT_MODE);
        data                =   processData();
    }
    
    //Initializes the secret key with 16 random bytes
    private void initAESKey()
    {
        SecureRandom rGen   =   new SecureRandom();
        AESKey              =   new byte[16];
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
