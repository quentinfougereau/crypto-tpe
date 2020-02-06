package PKCS1;// -*- coding: utf-8 -*-

import java.math.BigInteger;
import java.util.Random;

public class RSA_PKCS1 {

    public static void main(String[] args) throws Exception {
        //------------------------------------------------------------------
        //  Construction et affichage de la clef
        //------------------------------------------------------------------
        BigInteger n = new BigInteger(
                                      "00af7958cb96d7af4c2e6448089362"+
                                      "31cc56e011f340c730b582a7704e55"+
                                      "9e3d797c2b697c4eec07ca5a903983"+
                                      "4c0566064d11121f1586829ef6900d"+
                                      "003ef414487ec492af7a12c34332e5"+
                                      "20fa7a0d79bf4566266bcf77c2e007"+
                                      "2a491dbafa7f93175aa9edbf3a7442"+
                                      "f83a75d78da5422baa4921e2e0df1c"+
                                      "50d6ab2ae44140af2b", 16);
        BigInteger e = BigInteger.valueOf(0x10001);
        BigInteger d = new BigInteger(
                                      "35c854adf9eadbc0d6cb47c4d11f9c"+
                                      "b1cbc2dbdd99f2337cbeb2015b1124"+
                                      "f224a5294d289babfe6b483cc253fa"+
                                      "de00ba57aeaec6363bc7175fed20fe"+
                                      "fd4ca4565e0f185ca684bb72c12746"+
                                      "96079cded2e006d577cad2458a5015"+
                                      "0c18a32f343051e8023b8cedd49598"+
                                      "73abef69574dc9049a18821e606b0d"+
                                      "0d611894eb434a59", 16);

        System.out.println("Module          (n): " + n + " ("+n.bitLength()+" bits)");
        System.out.println("Exposant public (e): " + e + " ("+e.bitLength()+" bits)");
        System.out.println("Exposant privé  (d): " + d + " ("+d.bitLength()+" bits)");
        
        //------------------------------------------------------------------
        //  Construction et affichage du message clair
        //------------------------------------------------------------------
        byte[] m = { 0x4B, 0x59, 0x4F, 0x54, 0x4F } ;
        System.out.println("Message clair      : " + toHex(m) );
        
        //------------------------------------------------------------------
        //  Du message m à l'entier représentatif x (partie à modifier)
        //------------------------------------------------------------------
        byte[] em = bourragePKCS1(m);
        System.out.println("Message bourré     : " + toHex(em) );

        BigInteger x = new BigInteger(1, em);          // Encodage du message
        System.out.println("x = " +  x  + " (en décimal)");
        // Affichage de x en décimal
        System.out.println("x = 0x" + String.format("%X", x) + " (en hexadécimal)");
                                            // Affichage de x en hexadécimal
        //------------------------------------------------------------------
        //  Chiffrement de l'entier représentatif
        //------------------------------------------------------------------
        BigInteger c = x.modPow(e, n);
        System.out.println("x^e mod n = " + c + " ("+c.bitLength()+" bits)");

        //------------------------------------------------------------------
        //  Décodage de l'entier représentatif
        //------------------------------------------------------------------
        byte[] chiffré = c.toByteArray(); 
        System.out.println("Message chiffré    : " + toHex(chiffré) );
    }
    
    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) sb.append(String.format("0x%02X ", k));
        sb.append(" (" + données.length + " octets)");
        return sb.toString();
    }

    public static byte[] bourragePKCS1(byte[] m) {
        byte[] res = new byte[128];
        res[0] = 0x00;
        res[1] = 0x02;
        for (int i = 2; i < 128 - m.length - 1; i++) {
            Random random = new Random();
            res[i] = (byte) random.nextInt(0xFF);
        }
        res[128 - m.length] = 0x00;
        for (int i = 0; i < m.length; i++) {
            res[(128 - m.length) + i] = m[i];
        }
        return res;
    }
}

/*
  $ make
  javac *.java 
  $ java RSA_PKCS1
  Module          (n): 12322204109610601400...299   (1024 bits)
  Exposant public (e): 65537 (17 bits)
  Exposant privé  (d): 37767385438721355925...209   (1022 bits)
  Message clair      : 0x4B 0x59 0x4F 0x54 0x4F     (5 octets)
  x = 323620918351 (en décimal)
  x = 0x4B594F544F (en hexadécimal)
  x^e mod n = 65891982980551359715048403549...638   (1023 bits)
  Message chiffré    : 0x5D 0xD5 0x53 0x0B ... 0x26 (128 octets)
*/

/* Test avec un message légèrement différent
  $ make
  javac *.java 
  $ java RSA_PKCS1
  Module          (n): 12322204109610601400...299    (1024 bits)
  Exposant public (e): 65537 (17 bits)
  Exposant privé  (d): 37767385438721355925...209    (1022 bits)
  Message clair      : 0x3B 0x59 0x4F 0x54 0x4F      (5 octets)
  x = 254901441615 (en décimal)
  x = 0x3B594F544F (en hexadécimal)
  x^e mod n = 99064005127797152176285166470...427    (1024 bits)
  Message chiffré    : 0x00 0x8D 0x12 0x63 ... 0xB3  (129 octets)
*/
