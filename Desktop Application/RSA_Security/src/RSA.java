/*package whatever //do not write package name here */
import java.io.*;
import java.math.*;
import java.util.*;

import javax.swing.JOptionPane;
/*
* Java program for RSA asymmetric cryptographic algorithm.
* For demonstration, values are
* relatively small compared to practical application
*/
public class RSA {
	
	 private static BigInteger p, q, n, phi, e, d;
	 private static boolean Valid = true;
	 public static BigInteger gcd(BigInteger a, BigInteger h)
	{
		
		BigInteger temp ;
		while (true) {
			temp = a.mod(h);
			if (temp.compareTo(BigInteger.ZERO) == 0)
				return h;
			a = h;
			h = temp;
		}
	}
	 public static boolean isPrime(BigInteger number) {
	        if (number.compareTo(BigInteger.ONE) < 0) {
	            return false;
	        }

	        for (BigInteger i = BigInteger.TWO; i.compareTo(number.sqrt()) <= 0; i=i.add(BigInteger.ONE)) {
	            if (number.mod(i).compareTo(BigInteger.ZERO) == 0) {
	                return false;
	            }
	        }

	        return true;
	    }
	public static void generateKeys(String e) {
		if(!RSA.Valid) {
			return;
		}
		RSA.n = RSA.p.multiply(q);

		// Finding the other part of public key.
		// double e stands for encrypt
		if (n.isProbablePrime(100)) {
            // Condition 1: n is a prime number. phi(n) = n-1
            RSA.phi = n.subtract(BigInteger.ONE);
        } else if (!p.equals(q)) {
            // Condition 2: n is a product of two not equal primes. phi(n) = (p-1)*(q-1)
            RSA.phi = (RSA.p.subtract(BigInteger.ONE)).multiply(RSA.q.subtract(BigInteger.ONE));
        } else {
            // Condition 3: n is a product of two equal primes. phi(n) = (p-1)*q
            RSA.phi = (RSA.p.subtract(BigInteger.ONE)).multiply(q);
        }
		
		
		RSA.setE(new BigInteger(e));
	        
	    if(!RSA.getValid()) {
	    	return;
	    }
		RSA.d = RSA.e.modInverse(RSA.phi);
	}
	
	 public static String encrypt(String plaintext) {
		if(!RSA.Valid) {
				return "";
		}
		 System.out.println("Message data = " + plaintext);
		 ArrayList<BigInteger> list = new ArrayList<BigInteger>();
		 for (char char_at : plaintext.toCharArray()) {
			 System.out.println("char data = " + char_at);
			 int ascii = (int)char_at;
			 System.out.println(char_at + " ascii is: "+ ascii);
			 String toBigInt = "" + ascii;
			 BigInteger c = new BigInteger(toBigInt).pow(RSA.e.intValue());
			 c = c.mod(RSA.n);
			 list.add(c);
			 System.out.println("Encrypted data = " + c);
			 
		 }
		 
		 return list.toString();	 

		
	 }
	 
	 public static String decrypt(String ciphertext) {
		if(!RSA.Valid) {
				return "";
		}
		 String [] array = ciphertext.split(",");
		 
		 int i=0;
		 array[0] = array[0].trim().substring(1).trim();
		 System.out.println("after first element trim & substring: " + array[0]);
		 while( i<array.length-1){
			 array[i] = array[i++].trim();
		 }
		 
		 array[i] = array[i].substring(0, array[i].length() - 1).trim();
		 StringBuffer output = new StringBuffer("");
		 char c;
		 
		 for (String s : array) {
			 BigInteger m = new BigInteger(s);
			 System.out.println("s : " + s);
			 //m = m.mod(n);
			 m = m.pow(RSA.d.intValue());
			 System.out.println("m : " + m.toString());
			 m = m.mod(RSA.n);
			 System.out.println("m : " + m.toString());
			 System.out.println("m.intValue: " + m.intValue());
			 c = (char)m.intValue();
			 System.out.println("c : " + c);
			 output.append(c);
		 }
		 return output.toString();
		 
	 }
	 
	public static BigInteger getP() {
        return RSA.p;
    }

    public static BigInteger getQ() {
        return RSA.q;
    }

    public static BigInteger getN() {
        return RSA.n;
    }

    public static BigInteger getPhi() {
        return RSA.phi;
    }

    public static BigInteger getE() {
        return RSA.e;
    }

    public static BigInteger getD() {
        return RSA.d;
    }

    public static void setP(BigInteger p) {
    	if(RSA.isPrime(p)) {
    		RSA.p = p;
    		RSA.Valid = true;
    	}
    	else {
    		JOptionPane.showMessageDialog(null, "The p must be a prime number!");
    	}
    }

    public static void setQ(BigInteger q) {
    	if(RSA.isPrime(q)) {
    		RSA.q = q;
    		RSA.Valid = true;
    	}
    	else {
    		JOptionPane.showMessageDialog(null, "The q must be a prime number!");
    	}
    }

    public static void setN(BigInteger n) {
    	RSA.n = n;
    }

    public static void setPhi(BigInteger phi) {
    	RSA.phi = phi;
    }

    public static void setE(BigInteger e) {
    	 HashSet<BigInteger> SetOfVals = new HashSet<BigInteger>(); 
    	 BigInteger i = BigInteger.TWO;
 		while (i.compareTo(RSA.phi) < 0) {
             if (RSA.gcd(i, RSA.phi).equals(BigInteger.ONE)) {
                 SetOfVals.add(i);
             }
             i=i.add(BigInteger.ONE);
         }
    	 
        if(!SetOfVals.contains(e)) {
        	RSA.Valid = false;
        	JOptionPane.showMessageDialog(null, "The e must be among these numbers:"+SetOfVals);
        }
        else{
        	RSA.e = e;
        	RSA.Valid = true;
        }
    }

    public static void setD(BigInteger d) {
    	RSA.d = d;
    }
    
    public static boolean getValid() {
    	return RSA.Valid;
    }

}

