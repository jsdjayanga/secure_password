import com.wso2.devgov.SecurePasswordVault;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * Created by jayanga on 3/28/14.
 */
public class Main {
    static Logger logger = Logger.getLogger(Main.class.getName());

    public static final String fileName = "data.sec";
    public static final int keyLenAES = 16;
    public static final int passLen = 32;
    private static byte[] hwaddr;


    String un1 = "";
    String pw1 = "";
    String un2 = "";
    String pw2 = "";

    SecretKeySpec secretKey;

    public Main() throws SocketException {

        try {
            List<String> list = new ArrayList<String>();
            list.add("BAM pw");
            list.add("UES pw");
            SecurePasswordVault securePasswordVault = new SecurePasswordVault("test.123", list.toArray(new String[list.size()]));

            System.out.println("BAM pw=" + securePasswordVault.getSecureData("BAM pw"));
            System.out.println("BAM pw=" + securePasswordVault.getSecureData("UES pw"));

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


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

            logger.info("Detected interface:" + networkInterface.getName());

            hwaddr = networkInterface.getHardwareAddress();

            byte[] key = new byte[keyLenAES];
            Arrays.fill(key, (byte)0);

            for(int index = 0; index < hwaddr.length; index++){
                key[index] = hwaddr[index];
            }

            secretKey = new SecretKeySpec(key, "AES");
        }else{
            throw new RuntimeException("Cannot initialize. Failed to generate unique id.");
        }

    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, ShortBufferException {
        logger.info("Starting Secure Pass Program");

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Main main = new Main();
        if (args.length == 0){
            main.run();
        }else{
            main.init();
        }

        System.out.println(main.encrypt(main.un1, main.hwaddr));
        System.out.println(main.encrypt(main.pw1, main.hwaddr));
        System.out.println(main.encrypt(main.un2, main.hwaddr));
        System.out.println(main.encrypt(main.pw2, main.hwaddr));

        System.out.println("|" + main.dycrypt(main.encrypt(main.un1, main.hwaddr), main.hwaddr) + "|");
    }

    public void init() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, ShortBufferException {
        logger.info("Initializing.");

        readData();
        persistData();
    }

    private void persistData() throws IOException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("Persisting Data.");

        FileWriter fileWriter = new FileWriter(fileName);
        fileWriter.append("un1=" + un1 + "\n");
        fileWriter.append("pw1=" + new String(Base64.encode(encrypt(pw1))) + "\n");
        fileWriter.append("un2=" + un2 + "\n");
        fileWriter.append("pw2=" + new String(Base64.encode(encrypt(pw2))) + "\n");

        fileWriter.close();
    }

    private void readDataFromFile() throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, ShortBufferException, InvalidKeyException, InvalidParameterSpecException {
        logger.info("Reading data from file.");

        BufferedReader br = new BufferedReader(new FileReader(fileName));

        String line = br.readLine();
        un1 = line.substring(line.indexOf("=") + 1);

        line = br.readLine();
        pw1 = dycrypt(Base64.decode(line.substring(line.indexOf("=") + 1).getBytes()));

        line = br.readLine();
        un2 = line.substring(line.indexOf("=") + 1);

        line = br.readLine();
        pw2 = dycrypt(Base64.decode(line.substring(line.indexOf("=") + 1).getBytes()));
    }

    public void run() throws IOException, NoSuchPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, ShortBufferException {
        logger.info("Starting.");

        if (isInitialized()){
            logger.info("Running the program.");

            readDataFromFile();

            // Do the process related work here.


            System.out.println("Running with following details:" + un1 + "|" + pw1 + "|" + un2 + "|" + pw2);

        }else{
            logger.info("Cannot run without initializing.");
            init();
        }
    }

    private boolean isInitialized(){
        File file = new File(fileName);
        if (file.exists()){
            return true;
        }
        return false;
    }

    private byte[] encrypt(String word) throws NoSuchAlgorithmException, ShortBufferException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, UnsupportedEncodingException, InvalidParameterSpecException, InvalidKeySpecException, IllegalBlockSizeException {
        return encrypt(word, hwaddr);
    }

    private byte[] encrypt(String word, byte[] pkey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, ShortBufferException {

        byte[] password = new byte[passLen];
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

    private String dycrypt(byte[] cipherText) throws NoSuchPaddingException, ShortBufferException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidParameterSpecException {
        return dycrypt(cipherText, hwaddr);
    }

    private String dycrypt(byte[] cipherText, byte[] pkey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeyException, ShortBufferException {

        byte[] plainText = new byte[passLen];

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int plen = cipher.update(cipherText, 0, passLen, plainText, 0);

        plen += cipher.doFinal(plainText, plen);

        return new String(plainText);
    }

    public void readData() throws IOException {
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("un1?");
        un1 = bufferRead.readLine();
        System.out.println("pw1?");
        pw1 = bufferRead.readLine();
        System.out.println("un2?");
        un2 = bufferRead.readLine();
        System.out.println("pw2?");
        pw2 = bufferRead.readLine();

        System.out.println(un1 + " " + pw1 + " " + un2 + " " + pw2 );
    }
}
