/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ctsesamgui;

import java.io.UnsupportedEncodingException;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Vkyr
 */
public class CtSESAM {

    public static byte[] sha512HMAC(byte[] key, byte[] password) {
        try {
            Mac sha512_HMAC = Mac.getInstance("HmacSHA512");
            sha512_HMAC.init(new SecretKeySpec(key, "HmacSHA512"));
            return sha512_HMAC.doFinal(password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return password;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return password;
        }
    }

    private static byte[] F(byte[] password, byte[] salt, int iterations, int i) {
        byte[] Si = new byte[salt.length + 4];
        System.arraycopy(salt, 0, Si, 0, salt.length);
        byte[] iByteArray = ByteBuffer.allocate(4).putInt(i).array();
        System.arraycopy(iByteArray, 0, Si, salt.length, iByteArray.length);
        byte[] U = sha512HMAC(password, Si);
        byte[] T = new byte[U.length];
        System.arraycopy(U, 0, T, 0, T.length);
        for (int c = 1; c < iterations; c++) {
            U = sha512HMAC(password, U);
            for (int k = 0; k < U.length; k++) {
                T[k] = (byte) (((int) T[k]) ^ ((int) U[k]));
            }
        }
        return T;
    }

    public static byte[] PBKDF2_HMAC_sha512(byte[] hashString, byte[] salt, int iterations) {
        int dkLen = 64;
        int hLen = 64;
        int l = (int) Math.ceil(dkLen / hLen);
        int r = dkLen - (l - 1) * hLen;
        byte[] dk = new byte[dkLen];
        for (int i = 1; i <= l; i++) {
            byte[] T = F(hashString, salt, iterations, i);
            for (int k = 0; k < T.length; k++) {
                if (i - 1 + k < dk.length) {
                    dk[i - 1 + k] = T[k];
                }
            }
        }
        return dk;
    }

    public static String getPassword(byte[] hashValue,
            boolean specialCharacters,
            boolean letters,
            boolean numbers,
            int length) {
        byte[] positiveHashValue = new byte[hashValue.length + 1];
        positiveHashValue[0] = 0;
        System.arraycopy(hashValue, 0, positiveHashValue, 1, hashValue.length);
        BigInteger hashNumber = new BigInteger(positiveHashValue);
        String password = "";
        if (specialCharacters || letters || numbers) {
            List<String> characterSet = new ArrayList<>();
            if (letters) {
                characterSet.add("a");
                characterSet.add("b");
                characterSet.add("c");
                characterSet.add("d");
                characterSet.add("e");
                characterSet.add("f");
                characterSet.add("g");
                characterSet.add("h");
                characterSet.add("i");
                characterSet.add("j");
                characterSet.add("k");
                characterSet.add("l");
                characterSet.add("m");
                characterSet.add("n");
                characterSet.add("o");
                characterSet.add("p");
                characterSet.add("q");
                characterSet.add("r");
                characterSet.add("s");
                characterSet.add("t");
                characterSet.add("u");
                characterSet.add("v");
                characterSet.add("w");
                characterSet.add("x");
                characterSet.add("y");
                characterSet.add("z");
                characterSet.add("A");
                characterSet.add("B");
                characterSet.add("C");
                characterSet.add("D");
                characterSet.add("E");
                characterSet.add("F");
                characterSet.add("G");
                characterSet.add("H");
                characterSet.add("J");
                characterSet.add("K");
                characterSet.add("L");
                characterSet.add("M");
                characterSet.add("N");
                characterSet.add("P");
                characterSet.add("Q");
                characterSet.add("R");
                characterSet.add("T");
                characterSet.add("U");
                characterSet.add("V");
                characterSet.add("W");
                characterSet.add("X");
                characterSet.add("Y");
                characterSet.add("Z");
            }
            if (numbers) {
                characterSet.add("0");
                characterSet.add("1");
                characterSet.add("2");
                characterSet.add("3");
                characterSet.add("4");
                characterSet.add("5");
                characterSet.add("6");
                characterSet.add("7");
                characterSet.add("8");
                characterSet.add("9");
            }
            if (specialCharacters) {
                characterSet.add("#");
                characterSet.add("!");
                characterSet.add("\"");
                characterSet.add("§");
                characterSet.add("$");
                characterSet.add("%");
                characterSet.add("&");
                characterSet.add("/");
                characterSet.add("(");
                characterSet.add(")");
                characterSet.add("[");
                characterSet.add("]");
                characterSet.add("{");
                characterSet.add("}");
                characterSet.add("=");
                characterSet.add("-");
                characterSet.add("_");
                characterSet.add("+");
                characterSet.add("*");
                characterSet.add("<");
                characterSet.add(">");
                characterSet.add(";");
                characterSet.add(":");
                characterSet.add(".");
            }
            BigInteger setSize = BigInteger.valueOf(characterSet.size());
            while (hashNumber.compareTo(setSize) >= 0 && password.length() < length) {
                BigInteger[] divAndMod = hashNumber.divideAndRemainder(setSize);
                hashNumber = divAndMod[0];
                int mod = divAndMod[1].intValue();
                password += characterSet.get(mod);
            }
            if (hashNumber.compareTo(setSize) < 0 && password.length() < length) {
                password += characterSet.get(hashNumber.intValue());
            }
        }
        return password;
    }

    public static void main(String[] args) {
        Scanner user_input = new Scanner(System.in);
        String domain;
        System.out.print("Domain: ");
        domain = user_input.next();
        while (domain.length() < 1) {
            System.out.println("Please provide a domain for the generated Password.");
            System.out.print("Domain: ");
            domain = user_input.next();
        }
        String masterPassword;
        System.out.print("Masterpassword: ");
        masterPassword = user_input.next();
        try {
            byte[] hashString = (domain + masterPassword).getBytes("UTF-8");
            byte[] salt = ("pepper").getBytes("UTF-8");
            byte[] digest = PBKDF2_HMAC_sha512(hashString, salt, 4096);
            System.out.println("Password: " + getPassword(digest, true, true, true, 10));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}
