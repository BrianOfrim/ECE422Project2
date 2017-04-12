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
import java.util.concurrent.TimeUnit;

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
	private static final String SIGNIN = "I";
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

    
	public static void main(String[] args) throws IOException {
		
		Client client = new Client(new Socket(SERVERADDRESS, COMSPORT));
		client.run();
	}
	
	Client(Socket soc){
		socket = soc;
		encryptTEA = new Encryption();
		decryptTEA = new Decryption();
		
	}
			
	// format a string to bytes, add trailing 0x00 bytes to ensure byte array has a length
    // that is a multiple of 8
	private byte[] formatToSend(String s){
		int datalen = s.getBytes().length;

		int numBytesToSend = datalen + (8 - (datalen % 8));

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
	
	// encrypt a string and then send it 
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
			Thread.sleep(500);
			outputStream.write(bytesToSend);
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	// wait for, read then decrypt a stream of bytes
	private byte[] readData(BufferedInputStream inStream,BufferedReader input){
		// get the length of data to read
		Integer datalen = null; 
		try{
			datalen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}
		
		//System.out.print("Data length " +  datalen);
		
        byte[] encryptedData = new byte[datalen];
        int byteCount = 0;
        try{
            while(byteCount < datalen && (byteCount = inStream.read(encryptedData)) > 0){
            	//System.out.println("Current bytecount: " + byteCount); // debug
            }
        }catch(IOException e){
        	e.printStackTrace();
        }
        byte[] decryptedData = decryptTEA.decrypt(encryptedData,TEAkey);
        
        // remove the trailing 0x00 byte
        int i;
        for(i = 0; i < decryptedData.length; i++ ){
        	if(decryptedData[decryptedData.length - 1 - i] != (byte) 0x00){
        		break;
        	}
        }
        int lastNonZeroByte = decryptedData.length - i;
        //System.out.println("Number of non zerobytes: " + lastNonZeroByte);// debug
        byte [] decryptedDataZerosRemoved = Arrays.copyOf(decryptedData,lastNonZeroByte);
        //System.out.println("The decrypted array"); // debug
        //System.out.println(Arrays.toString(decryptedDataZerosRemoved));
        return decryptedDataZerosRemoved;
	}
	
	// turn an array of bytes into a string
	private String readString(BufferedInputStream inStream,BufferedReader input){
		byte[] rawBytes = readData( inStream, input);
		return new String(rawBytes);
	}
	
	
	// secure key exchange
	// go through the protocal for establishing Diffie Helman shared key to use as TEA key
	// based off of: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
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
		try{
			// ensure that the other side is waiting
			TimeUnit.SECONDS.sleep(2);
			outStream.write(alicePubKeyEnc);
			outStream.flush();
		}catch(Exception e){
			e.printStackTrace();
		}
		
		
		//recive bob's key
		Integer keyLen = null; 
		try{
			keyLen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}
		
        byte[] bobPubKeyEnc = new byte[keyLen];
        int byteCount = 0;
        try{
            while(byteCount < keyLen && (byteCount = inStream.read(bobPubKeyEnc)) > 0){
            	//System.out.println("Current bytecount: " + byteCount); // debug
            }
        }catch(Exception e){
        	e.printStackTrace();
        }

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
			
			System.out.println("Establishing connection...");
			
			output.println(ACK); // Send an ack to initialize

			// preform a secure key exchange
			TEAkey  = establishKey();
			
			sendString("Hey what is up dude?",outStream,output);
			
			// Determine if the user wants to sign in or sign up
			System.out.println("Signin (" + SIGNIN + "), Signup (" + SIGNUP + ")");
			String userInput;
			userInput = stdIn.readLine();
			
			if(userInput.equals(SIGNUP)){
				// tell the server that the user wishes to sign up
				sendString(SIGNUP,outStream,output);
				// retrive credentials
				System.out.println("Username: ");
				String userName =  stdIn.readLine();
				System.out.println("Password: ");
				String password =  stdIn.readLine();
				
				if(userName.contains(" ")){
					System.out.println("ERROR: username cannot contain spaces, exiting.");
				}else{
					sendString(userName,outStream,output);
					sendString(password,outStream,output);
					System.out.println("Account created please log back in to use it, exiting.");
				}
	
			}else if(userInput.equals(SIGNIN)){
				// tell the server that the client wants to signin
				sendString(SIGNIN,outStream,output);
				// retrive the users credentials
				System.out.println("Username: ");
				String userName =  stdIn.readLine();
				sendString(userName,outStream,output);
				System.out.println("Password: ");
				String password =  stdIn.readLine();
				sendString(password,outStream,output);
				String credentialCheckMsg = input.readLine();
				if(credentialCheckMsg.equals(ACCESSGRANTED)){
					System.out.println ("Valid credentials enter filenames (\"exit\" to quit)");
					
					while ((userInput = stdIn.readLine()) != null){
						
				         // end loop
				         if (userInput.equals("exit")){
				        	 sendString(userInput,outStream,output);
				        	 System.out.println("Exiting...");
				        	 break;
				         }
				        System.out.println("Requesting file: " + userInput);   
						
				        sendString(userInput,outStream,output); // send the name of the file
						String fileFound = readString(inStream,input);
						//System.out.println("file has been found: " + fileFound); // debug
						if(fileFound.equals(FILEFOUND)){
							System.out.println("File in being transfered...");
							byte[] rawBytes = readData( inStream, input);
							FileOutputStream outFileStream = new FileOutputStream("./" + userInput);
							//File outStream.write(rawBytes, 0, rawBytes.length);
							outFileStream.write(rawBytes,0,rawBytes.length);
							outFileStream.close();
							
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
