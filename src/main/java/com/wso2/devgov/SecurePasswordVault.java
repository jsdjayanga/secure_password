package com.wso2.devgov;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.*;

/**
 * Created by jayanga on 3/31/14.
 */
public class SecurePasswordVault {

    private static final int AES_KEY_LEN = 16;
    private static final int PASSWORD_LEN = 32;
    
    private static boolean initialized;
    private final String secureFile;
    private final byte[] networkHardwareHaddress;
    private Map<String, String> secureDataMap;
    private List<String> secureDataList;

    SecretKeySpec secretKey;

    public SecurePasswordVault(String filename, String[] secureData) throws IOException, NoSuchPaddingException, ShortBufferException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        initialized = false;
        secureFile = filename;
        networkHardwareHaddress = SecurePasswordVault.readNetworkHardwareAddress();
        secureDataMap = new HashMap<String, String>();

        this.secureDataList = new ArrayList<String>(secureData.length);
        Collections.addAll(secureDataList, secureData);

        byte[] key = new byte[AES_KEY_LEN];
        Arrays.fill(key, (byte)0);

        for(int index = 0; index < networkHardwareHaddress.length; index++){
            key[index] = networkHardwareHaddress[index];
        }

        secretKey = new SecretKeySpec(key, "AES");

        if (!isInitialized()){
            readSecureData(secureDataList);
            persistSecureData();
        }

        readSecureDataFromFile();
    }
    
    private boolean isInitialized(){
        if (initialized == true){
            return true;
        }else{
            File file = new File(secureFile);
            if (file.exists()){
                initialized = true;
                return initialized;
            }
        }
        return false;
    }

    private static byte[] readNetworkHardwareAddress() throws SocketException {
        Enumeration<NetworkInterface> networkInterfaceEnumeration = NetworkInterface.getNetworkInterfaces();
        if (networkInterfaceEnumeration != null){
            NetworkInterface networkInterface = null;
            while (networkInterfaceEnumeration.hasMoreElements()){
                networkInterface = networkInterfaceEnumeration.nextElement();
                if (!networkInterface.isLoopback()){
                    break;
                }
            }

            if (networkInterface == null){
                networkInterface = networkInterfaceEnumeration.nextElement();
            }

            byte[] hwaddr = networkInterface.getHardwareAddress();

            return hwaddr;
        }else{
            throw new RuntimeException("Cannot initialize. Failed to generate unique id.");
        }
    }

    private byte[] encrypt(String word) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] password = new byte[PASSWORD_LEN];
        Arrays.fill(password, (byte)0);

        byte[] pw = word.getBytes("UTF-8");
        for(int index = 0; index < pw.length; index++){
            password[index] = pw[index];
        }

        byte[] cipherText = new byte[password.length];

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        int ctLen = cipher.update(password, 0, password.length, cipherText, 0);

        ctLen += cipher.doFinal(cipherText, ctLen);

        return cipherText;
    }

    private String decrypt(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        byte[] plainText = new byte[PASSWORD_LEN];

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int plen = cipher.update(cipherText, 0, PASSWORD_LEN, plainText, 0);

        plen += cipher.doFinal(plainText, plen);

        return new String(plainText);
    }

    public void readSecureData(List<String> secureDataList) throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, ShortBufferException, InvalidKeyException {
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

        for(int index = 0; index < secureDataList.size(); index++){
            System.out.println("Please enter the value for :" + secureDataList.get(index));

            String value = new String(Base64.encode(encrypt(bufferRead.readLine())));
            secureDataMap.put(secureDataList.get(index), value);
        }
    }

    public String getSecureData(String key) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, ShortBufferException, InvalidKeyException {
        String value = secureDataMap.get(key);
        if (value != null){
            return decrypt(Base64.decode(value.getBytes()));
        }

        throw new RuntimeException("Given key is unknown. [key=" + key + "]");
    }

    private void readSecureDataFromFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(secureFile));

        String line;
        while ((line = br.readLine()) != null){
            int dividerPoint = line.indexOf("=");
            if (dividerPoint > 0){
                secureDataMap.put(line.substring(0, dividerPoint), line.substring(dividerPoint + 1));
            }
        }
    }

    private void persistSecureData() throws IOException {
        FileWriter fileWriter = new FileWriter(secureFile);

        for(String key : secureDataMap.keySet()){
            fileWriter.append(key + "=" + secureDataMap.get(key) + "\n");
        }

        fileWriter.close();
    }
}
