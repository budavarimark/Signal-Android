package org.thoughtcrime.securesms;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import org.signal.core.util.logging.Log;
import org.webrtc.audio.WebRtcAudioRecord;
import org.webrtc.audio.WebRtcAudioTrack;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



@RequiresApi(api = 26) public class CryptManager {

    public static String[] validOrder = new String[]{"chat", "chat", "story", "chat", "story"};
    public static boolean hideMode = false;

    public static long touchEventIdCounter = 1;
    public static class TouchEvent{
        public long id;
        public String type;
        public long time;

        public TouchEvent(String type){
            this.type = type;
            this.time = Instant.now().getEpochSecond();
            id = touchEventIdCounter++;
        }
    }

    public static ArrayList<TouchEvent> touchEvents = new ArrayList<>();

    public static void removeTouchEvent(long id){
        for (int i = 0; i < touchEvents.size(); i++) {
            if(touchEvents.get(i).id == id){
                touchEvents.remove(i);
                break;
            }
        }
    }

    public static void removeOldTouchEvents(){
        long now = Instant.now().getEpochSecond();
        ArrayList<Long> toRemove = new ArrayList<>();

        for (int i = 0; i < touchEvents.size(); i++) {
            TouchEvent tmp = touchEvents.get(i);
            if(now-tmp.time > 5){
                toRemove.add(tmp.id);
            }
        }

        for (int i = 0; i < toRemove.size(); i++) {
            removeTouchEvent(toRemove.get(i));
        }
        toRemove.clear();
    }

    public static void checkTouchEvents(){
        if(validOrder.length <= touchEvents.size()) {
            boolean isValid = true;
            for (int i = 0; i < validOrder.length; i++) {
                if (!Objects.equals(validOrder[i], touchEvents.get(i).type)){
                    isValid = false;
                    break;
                }
            }
            if(isValid){
                hideMode = !hideMode;
                touchEvents.clear();
            }
        }
    }

    public static void addToTouchEvent(String type){
        removeOldTouchEvents();
        touchEvents.add(new TouchEvent(type));
        checkTouchEvents();
    }


    public static PrivateKey privateKey;
    public static PublicKey publicKey;

    //public static String key = "F5IyVKHPlYJkkYQ7zeUUGphyq0ZQ8tp3";
    //public static String siv = new String(Base64.getEncoder().encode("F5IyVKHPlYJkkYQ7".getBytes()));
    //public static byte[] iv = "F5IyVKHPlYJkkYQ7".getBytes();

    private static Cipher encryptCipher;
    private static Cipher decryptCipher;

    public static class CallEncoder implements WebRtcAudioRecord.ExtraSecureEncoder{

        public byte getByteFromByte(byte b){
            /*switch(b){
                case 8:
                    return 126;
                default:
                    return b;
            }*/


           /* if(b > 10 && b < 80) {
                return (byte) (b + 40);
            }else if(b < 10 && b > -80){
                return (byte) (b - 40);
            }else{
                return b;
            }*/

            if(b == 0) return b;
            if(b > 0 && b+40 < 120) b = (byte)(b+40);
            if(b < 0 && b-40 > -120) b = (byte)(b-40);
            return (byte)((int)b*-1);
        }

        @Override public byte[] encode(ByteBuffer byteBuffer, int size) {

            /*byte[] returnBytes = new byte[size + 16];

            byte[] bytes    = byteBuffer.array();
            int    leftOver = size % 16;
            byte[] toEncode = new byte[size - leftOver];
            //returnBytes[i] = (byte)(bytes[i] ^ 230);
            //returnBytes[i] = (byte) ((bytes[i] + 1) % 255);
            byte[] iv = getRandomString(16).getBytes();
            System.arraycopy(CryptManager.iv, 0, returnBytes, 0, 16);

            //returnBytes[i] = getByteFromByte(bytes[i]);
            System.arraycopy(toEncode, 0, bytes, 0, size - leftOver);
            byte[] encoded = CryptManager.encryptAES(toEncode, CryptManager.iv);
            System.arraycopy(encoded, 0, returnBytes, 16, encoded.length);
            if (leftOver > 0) {
                System.arraycopy(bytes, size - leftOver, returnBytes, size - leftOver, leftOver);
            }

            //System.arraycopy(bytes, 0, returnBytes, 0, size);
            //return CryptManager.encryptAES(returnBytes, siv);
            return returnBytes;*/

            byte[] returnBytes = new byte[size];
            System.arraycopy(byteBuffer.array(), 0, returnBytes, 0, size);
            //Arrays.fill(returnBytes, (byte) 1);
            return returnBytes;
        }

        /*@Override public byte[] encode(ByteBuffer byteBuffer, int i) {
            return new byte[0];
        }*/
    }

    public static class CallDecoder implements WebRtcAudioTrack.ExtraSecureDecoder {

        public byte getByteFromByte(byte b){
           /* switch(b){
                case 126:
                    return 8;
                case 80:
                    return 9;
                default:
                    return b;
            }*/
           /* if(b > 50 && b < 120){
                return (byte)(b-40);
            }else{
                return b;
            }*/

            if(b == 0) return b;
            if(b > 0 && b < 120) b = (byte)(b-40);
            if(b < 0 && b > -120) b = (byte)(b+40);
            return (byte)((int)b*-1);
        }

        @Override public ByteBuffer decode(ByteBuffer byteBuffer, int size) {
            byte[] returnBytes = new byte[size];
            System.arraycopy(byteBuffer.array(), 0, returnBytes, 0, size);

            /*int leftOver = size % 16;
            byte[] iv = new byte[16];
            byte[] encoded = new byte[size-16-leftOver];

            byte[] bytes = byteBuffer.array();

            //returnBytes[i-16] = getByteFromByte(bytes[i]);
            System.arraycopy(bytes, 0, iv, 0, 16);
            System.arraycopy(bytes, 0, encoded, 0, size-16-leftOver);
            byte[] decoded = CryptManager.decryptAES(encoded, CryptManager.iv);

            System.arraycopy(decoded, 0, returnBytes, 0, decoded.length);
            System.arraycopy(bytes, size-16-leftOver, returnBytes, decoded.length, leftOver);*/

            //System.arraycopy(bytes, 16, returnBytes, 0, size - 16);
            return ByteBuffer.wrap(returnBytes);
            //returnBytes[i] = (byte) ((bytes[i] - 1) % 255);
            //returnBytes[i] = (byte)(bytes[i] ^ 230);
            //System.arraycopy(bytes, 0, returnBytes, 0, size);
            //return ByteBuffer.wrap(CryptManager.decryptAES(returnBytes, siv));
            //return byteBuffer;
        }
    }


    public CryptManager(){

    }

    //public static

    static {
        generateRsa();
        requestKeys();
    }

    @SuppressLint("LogTagInlined") public static void generateRsa(){
        try {
            privateKey = null;
            publicKey = null;
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if(!keyStore.isKeyEntry("SIGNAL_KEY")){

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

                kpg.initialize(new KeyGenParameterSpec.Builder(
                    "SIGNAL_KEY",
                    KeyProperties.PURPOSE_ENCRYPT |
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN |
                    KeyProperties.PURPOSE_VERIFY)
                                   .setRandomizedEncryptionRequired(false)
                                   .setDigests(
                                       KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_MD5,
                                       KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA224,
                                       KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384,
                                       KeyProperties.DIGEST_SHA512)
                                   .setEncryptionPaddings(
                                       KeyProperties.ENCRYPTION_PADDING_NONE,
                                       KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
                                       KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                   .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                   //.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                   .setKeySize(2048)
                                   .build());

                KeyPair keyPair = kpg.generateKeyPair();

                //KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");


            //Toast.makeText(QrActivity.this, new String(publicKey.getEncoded()), Toast.LENGTH_LONG).show();
            }
        }catch (Exception e){
            Log.e("CRYPTMANAGER", e);
        }
    }

    @SuppressLint("LogTagInlined") public static void requestKeys() {
        if(privateKey == null || publicKey == null){
            try {
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                if(!keyStore.isKeyEntry("SIGNAL_KEY")) {
                    generateRsa();
                }
                KeyStore.Entry entry = keyStore.getEntry("SIGNAL_KEY", null);
                //PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
                privateKey = (PrivateKey) keyStore.getKey("SIGNAL_KEY", null);
                publicKey = keyStore.getCertificate("SIGNAL_KEY").getPublicKey();
            }catch (Exception e){
                Log.e("CRYPTMANAGER", e);
            }
        }
    }

    public static String generateKeyExchangeText(){
        return "";
    }

    public static String getPublicKeyBase64(){
        if(privateKey == null || publicKey == null) {
            requestKeys();
        }

        return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
    }

    public static String getKeyFromInit(String msg){
        String[] msgs = msg.split("\\|\\|");
        if(msgs.length > 1) {
            return msgs[1];
        }
        return "";
    }

    private static final String ALLOWED_CHARACTERS ="0123456789qwertyuiopasdfghjklzxcvbnm";
    public static String getRandomString(final int sizeOfRandomString)
    {
        final Random        random =new Random();
        final StringBuilder sb     =new StringBuilder(sizeOfRandomString);
        for(int i=0;i<sizeOfRandomString;++i)
            sb.append(ALLOWED_CHARACTERS.charAt(random.nextInt(ALLOWED_CHARACTERS.length())));
        return sb.toString();
    }

    public static String encryptRSAString(String string){
        return encryptRSAString(string, "MY_PRIVATE", "");
    }

    public static String encryptRSAString(String string, String key){
        return encryptRSAString(string, "OTHER", key);
    }

    public static String encryptRSAString(String string, String keyType, String key){
        try {
            requestKeys();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            if(keyType.equals("MY_PRIVATE")) {
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            }else{
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
                PublicKey serverPubKey = kf.generatePublic(keySpecX509);
                cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
            }

            return new String(Base64.getEncoder().encode(cipher.doFinal(string.getBytes())));
        }catch(Exception e){
            return "";
        }
    }

    public static String decryptRSAString(String string){
        return decryptRSAString(string, "MY_PRIVATE", "");
    }

    public static String decryptRSAString(String string, String key){
        return decryptRSAString(string, "OTHER", key);
    }

    public static String decryptRSAString(String string, String keyType, String key){
        try {
            if(keyType.equals("OTHER")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
                PublicKey serverPubKey = kf.generatePublic(keySpecX509);

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, serverPubKey);

                return new String(cipher.doFinal(Base64.getDecoder().decode(string)));
                //return new String(Base64.getEncoder().encode(cipher.doFinal(string.getBytes())));
            }else{
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);

                return new String(cipher.doFinal(Base64.getDecoder().decode(string)));
            }
        }catch(Exception e){
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = 26) public static String encryptManager(String key, String string){
        String iv = new String(Base64.getEncoder().encode(getRandomString(16).getBytes()));
        return iv + "||" + encryptAESString(key, string, iv);
    }

    @RequiresApi(api = 26) public static String decryptManager(String key, String string){
        String[] sections = string.split("\\|\\|");
        //String iv = new String(Base64.getEncoder().encode(getRandomString(16).getBytes()));
        //return iv + "|" + encryptAESString(string, iv);

        if(sections.length == 2) {
            return decryptAESString(key, sections[1], sections[0]);
        }

        return "";
    }

    @RequiresApi(api = 26) public static byte[] encryptAES(String key, byte[] bytes, byte[] iv){
        try {
            if(encryptCipher == null){
                encryptCipher = Cipher.getInstance("AES/CBC/nopadding");
            }

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return encryptCipher.doFinal(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[]{0};
    }


    @RequiresApi(api = 26) public static byte[] decryptAES(String key, byte[] encrypted, byte[] iv){
        try {
            if(decryptCipher == null){
                decryptCipher = Cipher.getInstance("AES/CBC/nopadding");
            }

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return decryptCipher.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[]{0};
    }

    @RequiresApi(api = 26) public static String encryptAESString(String key, String string, String iv){
        try {

            if(encryptCipher == null){
                encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            }

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encryptedText = encryptCipher.doFinal(string.getBytes());
            return new String(Base64.getEncoder().encode(encryptedText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }


    @RequiresApi(api = 26) public static String decryptAESString(String key, String string, String iv){
        try {

            if(decryptCipher == null){
                decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            }

            //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            //Log.e("HTML", string);
            byte[] encrypted = Base64.getDecoder().decode(string);
            byte[] decryptedText = decryptCipher.doFinal(encrypted);
            //Log.e("HTML", new String(decryptedText));
            return new String(decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}
