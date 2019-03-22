package com.company;
import javax.naming.OperationNotSupportedException;
import java.io.*;
import java.math.BigInteger;
import java.nio.channels.UnsupportedAddressTypeException;
import java.util.Random;
import java.util.Scanner;

public class RSA {
    private BigInteger n; // number
    private BigInteger e; // part of public key
    private BigInteger d; // part of private key
    private boolean encryptOnly = false;

    public String getPrivateKey()
    {
        return d.toString();
    }

    public String getPublicKey()
    {
        return e.toString();
    }

    public RSA() // Generates random RSA key pair
    {

        BigInteger p = new BigInteger(1015,100, new Random());;
        BigInteger q = new BigInteger(1033,100, new Random());
        this.n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        this.e = new BigInteger("65537");
        this.d = e.modInverse(phi);
    }

    // Reads public key or key pair from input stream
    public RSA(ObjectInputStream is) throws IOException
    {
        try
        {
            //read n
            this.n = (BigInteger) is.readObject();

            //read e
            this.e = (BigInteger) is.readObject();

            //try to read d => if EOF => no decrypt possible
            this.d = (BigInteger) is.readObject();
        }
        catch(IOException e)
        {
            encryptOnly = true;
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

    }
    public BigInteger encrypt(BigInteger plain) throws BadMessageException
    {
        if(plain.compareTo(this.n.subtract(BigInteger.ONE))==1 || plain.compareTo(BigInteger.ONE) == -1)
        {
            throw new BadMessageException();
        }

        return plain.modPow(this.e,this.n);
    }

    public BigInteger decrypt(BigInteger cipher) throws BadMessageException, OperationNotSupportedException {

        if(encryptOnly)
        {
            throw new OperationNotSupportedException();
        }
        if(cipher.compareTo(this.n.subtract(BigInteger.ONE))==1 || cipher.compareTo(BigInteger.ONE) == -1)
        {
            throw new BadMessageException();
        }
        return cipher.modPow(this.d,this.n);
    }
    public void save(ObjectOutputStream os) throws IOException, OperationNotSupportedException {
        if(encryptOnly)
        {
            throw new OperationNotSupportedException();
        }

        os.writeObject(this.n);
        os.writeObject(this.e);
        os.writeObject(this.d);
    }
    public void savePublic(ObjectOutputStream os) throws IOException
    {
        os.writeObject(this.n);
        os.writeObject(this.e);
    }

    public static BigInteger helperGcdExtended(BigInteger a, BigInteger b, BigInteger x, BigInteger y)
    {
        // Base Case
        if (a.equals(new BigInteger("0"))) {
            x = new BigInteger("0");
            y = new BigInteger("1");
            return b;
        }

        BigInteger x1 = new BigInteger("1"), y1 =  new BigInteger("1"); // To store results of recursive call
        BigInteger gcd = helperGcdExtended(b.mod(a), a, x1, y1);

        // Update x and y using results of recursive
        // call
        x = y1.subtract(b.divide(a).multiply(x1));
        y = x1;

        return gcd;
    }

    public BigInteger phi(BigInteger n, BigInteger step)
    {
        BigInteger result = new BigInteger("1");
        for (BigInteger i = step; i.compareTo(n)==-1; i=i.add(step))
        {
            if (i.gcd(n).equals(BigInteger.ONE))
            {
                result.add(BigInteger.ONE);
            }

        }

        return result;
    }

    public BigInteger sign(BigInteger message) throws BadMessageException, OperationNotSupportedException {
        if(encryptOnly)
        {
            throw new OperationNotSupportedException();
        }
        return this.encrypt(message);

    }

    public boolean verify(BigInteger message, BigInteger signature) throws OperationNotSupportedException, BadMessageException
    {
        BigInteger shouldBeMessage = this.decrypt(signature);

        return message.equals(shouldBeMessage);

    }



}
