package com.company;

import javax.naming.OperationNotSupportedException;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws IOException, OperationNotSupportedException, BadMessageException, ClassNotFoundException {
            //Ex1();

            //Ex4();

        String string = "";
        for(String element : args)
        {
            string += " "+element;
        }
        string = string.trim();
        //Exercise5
        /*

            Ex5(string);

            Ex5a(stream);
*/
            Ex6(string);
            ObjectInputStream stream = new ObjectInputStream(new FileInputStream(new File("signated.txt")));
            Ex6a(stream);

    }

    public static void Ex1()
    {
        System.out.println("für 128: "+helperEx1(128));
        System.out.println("für 256: "+helperEx1(256));
        System.out.println("für 384: "+helperEx1(384));
        System.out.println("für 512: "+helperEx1(512));
    }

    private static long helperEx1(int w)
    {
        long b = 1;
        double ziel = Math.pow(2,(double)w);
        while(Math.exp(1.92*Math.pow(b,1.0/3.0)*Math.pow(Math.log(b),2.0/3.0))<ziel)
        {
            //System.out.println(Math.exp(1.92*Math.pow(b,1.0/3.0)*Math.pow(Math.log(b),2.0/3.0)));
            b++;
        }
        //System.out.println(Math.exp(1.92*Math.pow(b,1.0/3.0)*Math.pow(Math.log(b),2.0/3.0)));
        return b;


    }

    public static void Ex4()
    {
        RSA rsa = new RSA();
        File file = new File("publicnprivate.txt");
        try {
            FileWriter fw = new FileWriter(file);
            fw.write(rsa.getPrivateKey());
            fw.write("\n");
            fw.write(rsa.getPublicKey());
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        file = new File("public.txt");
        try {
            FileWriter fw = new FileWriter(file);
            fw.write(rsa.getPublicKey());
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public static void Ex5(String str) throws BadMessageException, IOException, OperationNotSupportedException {

        RSA rsaKeys = new RSA();
        rsaKeys.save(new ObjectOutputStream((new FileOutputStream(new File("keys.txt")))));
        RSA rsa = new RSA(new ObjectInputStream(new FileInputStream(new File("keys.txt"))));
        BigInteger result = rsa.encrypt(helperStringToBigInteger(str));

        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("encrypted.txt"))))
        {
            oos.writeObject(result);
        }

    }

    public static void Ex5a(ObjectInputStream stream) throws OperationNotSupportedException, BadMessageException, IOException, ClassNotFoundException {
        BigInteger bigI = (BigInteger) stream.readObject();

        RSA rsa = new RSA(new ObjectInputStream(new FileInputStream(new File("keys.txt"))));

        BigInteger result = rsa.decrypt(bigI);
        System.out.println(helperBigIntegerToString(result));
    }

    public static BigInteger helperStringToBigInteger(String string)
    {

        String result = "";
        for (int i = 0; i < string.length(); i++)
        {
            char element = string.charAt(i);
            int elem = (int)element;
            if(elem<100)
            {
                result += "0";
                result += (int)element;
            }
            else
            {
                result += (int)element;
            }

        }

        return new BigInteger(result);
    }

    public static String helperBigIntegerToString(BigInteger bigI)
    {
        String string = bigI.toString();
        while (string.length() % 3 != 0)
        {
            string = '0' + string;
        }
        String result = "";
        for (int i = 0; i < string.length(); i += 3)
        {
            result += (char)(Integer.parseInt(string.substring(i, i + 3)));
        }

        return result;
    }

    public static void Ex6(String str) throws IOException, OperationNotSupportedException, BadMessageException {
        RSA rsaKeys = new RSA();
        rsaKeys.save(new ObjectOutputStream((new FileOutputStream(new File("signkeys.txt")))));
        RSA rsa = new RSA(new ObjectInputStream(new FileInputStream(new File("signkeys.txt"))));
        BigInteger result = rsa.sign(helperStringToBigInteger(str));

        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("signated.txt"))))
        {
            oos.writeObject(helperStringToBigInteger(str));
            oos.writeObject(result);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void Ex6a(ObjectInputStream stream) throws OperationNotSupportedException, BadMessageException, IOException, ClassNotFoundException {
        BigInteger str = (BigInteger) stream.readObject();
        BigInteger signature = (BigInteger) stream.readObject();

        RSA rsa = new RSA(new ObjectInputStream(new FileInputStream(new File("signkeys.txt"))));

        if(rsa.verify(str,signature))
        {
            System.out.println("Verified: "+helperBigIntegerToString(str));
        }
        else
        {
            System.out.println("nope ...");
        }

    }
}
