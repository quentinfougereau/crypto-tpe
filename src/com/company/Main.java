package com.company;

import java.math.BigInteger;

public class Main {

    public static void main(String[] args) {
        //System.out.println(stringToInt("KYOTO"));

        System.out.println(stringToLong("KYOTO"));
        System.out.println(decimalToBinary(156));
        System.out.println(decimalToBase256(stringToLong("KYOTO")));
        System.out.println(decimalToHexa(stringToLong("KYOTO"))); //A réfléchir
    }

    /*
    public static BigInteger stringToInt(String str) {
        BigInteger res = new BigInteger("0", 10);
        for (int i = 1; i <= str.length(); i++) {
            int characterASCII = str.charAt(i - 1);
            res = res.add(BigInteger.valueOf((long) (characterASCII * Math.pow(256, str.length() - i))));
        }
        return res;
    }
     */

    public static long stringToLong(String str) {
        long res = 0;
        for (int i = 1; i <= str.length(); i++) {
            int characterASCII = str.charAt(i - 1);
            res += (long) (characterASCII * Math.pow(256, str.length() - i));
        }
        return res;
    }

    public static String decimalToBinary(int decimal) {
        String res = "";
        while (decimal != 0) {
            int tmp = decimal;
            decimal = decimal / 2;
            res = tmp % 2 + res;
        }
        return res;
    }

    public static String decimalToBase256(long decimal) {
        String res = "";
        while (decimal != 0) {
            long tmp = decimal;
            decimal = decimal / 256;
            res = tmp % 256 + res;
        }
        return res;
    }

    public static String decimalToHexa(long decimal) {
        String res = "";
        while (decimal != 0) {
            long tmp = decimal;
            decimal = decimal / 16;
            res = tmp % 16 + res;
        }
        return res;
    }

}
