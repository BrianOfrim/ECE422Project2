import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class Client {
	private static final Integer COMSPORT = 16000;
	private static final String SERVERADDRESS = "localhost";
	private static final String ACCESSGRANTED = "G";
	private static final String ACCESSDENIED = "D";
	private static final String SIGNUP = "U";
	private static final String SIGNOUT = "I";
	private static final String FILEFOUND = "F";
	private static final String FILENOTFOUND = "N";
	private static final String ACK = "ACK";
	
	private Socket socket;
	private byte TEAkey[];
	
	Encryption encryptTEA;
	Decryption decryptTEA;
	
	static{
		System.loadLibrary("encrypt");
		System.loadLibrary("decrypt");

	}
	
	// diffie helman stuff from
	// https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
    // The 1024 bit Diffie-Hellman modulus values used by SKIP
    private static final byte skip1024ModulusBytes[] = {
        (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
        (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
        (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
        (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
        (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
        (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
        (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
        (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
        (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
        (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
        (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
        (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
        (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
        (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
        (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
        (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
        (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
        (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
        (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
        (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
        (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
        (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
        (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
        (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
        (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
        (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
        (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
        (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
        (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
        (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
        (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
        (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
    };
    // The SKIP 1024 bit modulus
    private static final BigInteger skip1024Modulus
    = new BigInteger(1, skip1024ModulusBytes);
    
    // The base used with the SKIP 1024 bit modulus
    private static final BigInteger skip1024Base = BigInteger.valueOf(2);

			
	public static SecretKey genKey(){
		KeyGenerator keyGen = null;
		try{
			keyGen = KeyGenerator.getInstance("AES");
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
		SecureRandom random = new SecureRandom(); // cryptograph. secure random 
		keyGen.init(random); 
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}
	
	private byte[] formatToSend(String s){
		int datalen = s.getBytes().length;
		//System.out.println("Original Data len:");
		//System.out.println(datalen);
		int numBytesToSend = datalen + (8 - (datalen % 8));
		System.out.println("New Data len:");
		System.out.println(numBytesToSend);
		byte[] tempData = s.getBytes();
		byte[] data = new byte[numBytesToSend];
		for(int i = 0; i < numBytesToSend; i ++){
			if(i < datalen){
				data[i] = tempData[i];
			}else{
				data[i] = (byte)0x00;
			}
		}
		return data;
	}
	
	private void sendString(String s,OutputStream outputStream,PrintWriter output){
		// send the length of the string 
		int datalen = s.getBytes().length;
		//System.out.println("Original Data len:");
		//System.out.println(datalen);
		int numBytesToSend = datalen + (8 - (datalen % 8));
		// send the length of the string 
		output.println(numBytesToSend);
		// send the encrypted payload;
		byte[] bytesToSend = encryptTEA.encrypt(formatToSend(s), TEAkey);
		try{
			outputStream.write(bytesToSend);
		}catch(IOException e){
			e.printStackTrace();
		}
	}
	
	private byte[] readData(BufferedInputStream inStream,BufferedReader input){
		// get the length of data to read
		Integer datalen = null; 
		try{
			datalen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}
		
		System.out.print("Data length");
		
        byte[] encryptedData = new byte[datalen];
        int byteCount = 0;
        try{
            while(byteCount < datalen && (byteCount = inStream.read(encryptedData)) > 0){
            	System.out.println("Current bytecount: " + byteCount); // debug
            }
        }catch(IOException e){
        	e.printStackTrace();
        }
        byte[] decryptedData = decryptTEA.decrypt(encryptedData,TEAkey);
        return decryptedData;
	}
	
	private String readString(BufferedInputStream inStream,BufferedReader input){
		byte[] rawBytes = readData( inStream, input);
		return new String(rawBytes);
	}
	


	
	public static void main(String[] args) throws IOException {
		
		Client client = new Client(new Socket(SERVERADDRESS, COMSPORT));
		client.run();
	}
	Client(Socket soc){
		socket = soc;
		encryptTEA = new Encryption();
		decryptTEA = new Decryption();
		
	}
	
	public byte[] establishKey(){
		BufferedReader input = null;
		PrintWriter output = null;

		BufferedInputStream inStream = null;
		OutputStream outStream = null;
		try{
			input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			output = new PrintWriter(socket.getOutputStream(), true);
			inStream = new BufferedInputStream(socket.getInputStream());
			outStream = socket.getOutputStream();
		} catch(Exception e){
			e.printStackTrace();
		}
		
		DHParameterSpec dhSkipParamSpec = new DHParameterSpec(skip1024Modulus,skip1024Base);
		KeyPairGenerator aliceKpairGen = null;
		try{
		    aliceKpairGen = KeyPairGenerator.getInstance("DH");
		    aliceKpairGen.initialize(dhSkipParamSpec);
		}catch(Exception e){
			e.printStackTrace();
		}
		
		KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
		KeyAgreement aliceKeyAgree = null;
		try{
			aliceKeyAgree = KeyAgreement.getInstance("DH");
			aliceKeyAgree.init(aliceKpair.getPrivate());
		}catch(Exception e){
			e.printStackTrace();
		}
		
		byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
		
		output.println(alicePubKeyEnc.length); // send the length of the key
		System.out.println(Arrays.toString(alicePubKeyEnc));//debug
		try{
			outStream.write(alicePubKeyEnc);
			outStream.flush();
		}catch(Exception e){
			e.printStackTrace();
		}
		
		
		//recive bob's key
		//degbug
		System.out.println("Now recive bob's key");
		Integer keyLen = null; 
		try{
			keyLen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}
		
		System.out.print("Length of bob's key");
        byte[] bobPubKeyEnc = new byte[keyLen];
        int byteCount = 0;
        try{
            while(byteCount < keyLen && (byteCount = inStream.read(bobPubKeyEnc)) > 0){
            	System.out.println("Current bytecount: " + byteCount); // debug
            }
        }catch(Exception e){
        	e.printStackTrace();
        }

        System.out.println("Bob's key");
        System.out.println(Arrays.toString(bobPubKeyEnc));//debug
        
        KeyFactory aliceKeyFac = null;
        try{
        aliceKeyFac= KeyFactory.getInstance("DH");
        }catch(Exception e){
        	e.printStackTrace();
        }
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = null;
        try{
        	bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        	aliceKeyAgree.doPhase(bobPubKey, true);
        }catch(Exception e){
        	e.printStackTrace();
        }
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        //return aliceSharedSecret
        System.out.println("Shared secret key:"); // debug
        System.out.println(Arrays.toString(aliceSharedSecret)); // debug
        System.out.println("Secret key len"); // debug
        System.out.println(aliceSharedSecret.length); // debug
        
        // use the first 16 bytes of the shared secret for the TEA KEY
        byte TEAkeyGenerated[] =  Arrays.copyOf(aliceSharedSecret, 16);	
        return TEAkeyGenerated;
		
	}
	
	public void run(){
		try{
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			BufferedInputStream inStream = new BufferedInputStream(socket.getInputStream());
			OutputStream outStream = socket.getOutputStream();
			
			output.println(ACK); // Send an ack to initialize
			

			TEAkey  = establishKey();
			
			sendString("Hey what is up dude?",outStream,output);
			
			
			System.out.println("Signin (" + SIGNOUT + "), Signup (" + SIGNUP + ")");
			String userInput;
			userInput = stdIn.readLine();
			
			if(userInput.equals("U")){
				//output.println("U");
				sendString("U",outStream,output);
				System.out.println("Username: ");
				String userName =  stdIn.readLine();
				System.out.println("Password: ");
				String password =  stdIn.readLine();
				if(userName.contains(" ")){
					System.out.println("ERROR: username cannot contain spaces, exiting.");
				}else{
					output.println(userName);
					output.println(password);
					System.out.println("Account created please log back in to use it, exiting.");
				}
	
				
				
			}else if(userInput.equals("I")){
				sendString("I",outStream,output);
				System.out.println("Username: ");
				String userName =  stdIn.readLine();
				output.println(userName);
				System.out.println("Password: ");
				String password =  stdIn.readLine();
				output.println(password);
				String credentialCheckMsg = input.readLine();
				if(credentialCheckMsg.equals(ACCESSGRANTED)){
					System.out.println ("Valid credentials enter filenames (\"exit\" to quit)");
					
					while ((userInput = stdIn.readLine()) != null){
						
				         // end loop
				         if (userInput.equals("exit")){
				        	 System.out.println("Exiting...");
				        	 break;
				         }
				         System.out.println("Requesting file: " + userInput);   
						
						output.println(userInput); // send the name of the file
						String fileFound = input.readLine();
						System.out.println("file has been found: " + fileFound); // debug
						if(fileFound.equals(FILEFOUND)){
							Integer lengthOfFile = Integer.parseInt(input.readLine());
							System.out.println("Length of file :" + lengthOfFile + " bytes" );
							// Receive the file 
					        inStream = new BufferedInputStream(socket.getInputStream());
					        System.out.println("Reciving file: " + userInput);
					        outStream = new FileOutputStream("./" + userInput);
					        
					        byte[] fileBytes = new byte[lengthOfFile];
					        
					        int byteCount = 0;
					        while(byteCount < lengthOfFile && (byteCount = inStream.read(fileBytes)) > 0){
					        	System.out.println("Current bytecount: " + byteCount); // debug
					        	outStream.write(fileBytes, 0, byteCount);
					        }
					        System.out.println("File "+ userInput +" has been recived");
					        
						}else if(fileFound.equals(FILENOTFOUND)){
							System.out.println("Sorry file not found");
						}else{
							System.out.println("Protocal error, exiting.");
							break;
						}
						
						System.out.println ("Enter filenames (\"exit\" to quit)");
					}
			   }else if(credentialCheckMsg.equals(ACCESSDENIED)){
				   System.out.println("Invalid cedentials, exiting.");
			   }else{
				   System.out.println("Protocal error, exiting.");
			   }
			}
			if(inStream != null)
				inStream.close();
			if(outStream != null)
				outStream.close();
			
			output.close();
			input.close();
			stdIn.close();
			socket.close();
		} catch(IOException e){
			e.printStackTrace();
	        System.err.println("Problem with Communication Server");
	        System.exit(1); 
		}
	}

}
