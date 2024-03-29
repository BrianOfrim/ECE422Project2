import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.interfaces.*;


public class Server extends Thread{
	private Socket socket;
	private byte TEAkey[];
	private static final Integer COMSPORT = 16000;
	private static final String SHADOWFILENAME = "shadow.txt";
	private static final String ACCESSGRANTED = "G";
	private static final String ACCESSDENIED = "D";
	private static final String SIGNUP = "U";
	private static final String SIGNIN = "I";
	private static final String FILEFOUND = "F";
	private static final String FILENOTFOUND = "N";
	private static final String ACK = "ACK";
	
	static{
		System.loadLibrary("encrypt");
		System.loadLibrary("decrypt");

	}
	
	Encryption encryptTEA;
	Decryption decryptTEA;
	
	public static void main(String[] args) throws IOException {
		 ServerSocket serverSocket = null; 
		 serverSocket = new ServerSocket(COMSPORT);
		 while (true){
			 new Server(serverSocket.accept());
		 }
	}
	

	
	Server(Socket s){
		socket = s;
		encryptTEA = new Encryption();
		decryptTEA = new Decryption();
		start();
	}
	
	
	// copied from https://stackoverflow.com/questions/4895523/java-string-to-sha1
	private static String byteArrayToHexString(byte[] b) {
		  String result = "";
		  for (int i=0; i < b.length; i++) {
		    result +=
		          Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
		  }
		  return result;
	}
	
	// modified from https://stackoverflow.com/questions/4895523/java-string-to-sha1
	private static String hashPassword(byte[] pw){
	    MessageDigest md = null;
	    try {
	        md = MessageDigest.getInstance("SHA-1");
	    }
	    catch(NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    } 
	    return byteArrayToHexString(md.digest(pw));
		
	}
	
	// some code copied from http://beginnersbook.com/2014/01/how-to-append-to-a-file-in-java/
	private static Boolean writeToShadow(String userName, String hashedPasseord){
		try{
			
			File file = new File(SHADOWFILENAME);
	    	if(!file.exists()){
	     	   file.createNewFile();
	     	}	
	    	FileWriter fw = new FileWriter(file,true);
	    	BufferedWriter bw = new BufferedWriter(fw);
	    	
	    	bw.write(userName + " " + hashedPasseord + System.lineSeparator() );
	    	bw.close();
		}catch(IOException ioe){
			return false;
		}
		return true;
	}
	
	private static Boolean validateCredentials(String userName, String hashedPassword){
		ArrayList<String> Lines = new ArrayList<String>();
		try{
			Files.lines(Paths.get("./" + SHADOWFILENAME)).forEach(line -> Lines.add(line));
		}catch(IOException ioe){
			return false;
		}
		for(String line: Lines){
			String[] credentials = line.split(" ");
			if(credentials.length == 2 && credentials[0].equals(userName) && credentials[1].equals(hashedPassword)){
				return true;
			}
		}
		return false;
	}
	
	private static File retriveFile(String fileName){
		File f = new File(fileName);
		if(f.exists() && !f.isDirectory()) { 
		    return f;
		}
		return null;
	}
	
	// secure key exchange
	// go through the protocal for establishing Diffie Helman shared key to use as TEA key
	// based off of: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
	public byte[] establishKey(){
		PrintWriter output = null;
		BufferedReader input = null;
		OutputStream outputStream = null;
		BufferedInputStream inStream = null;
		
		try{
			output = new PrintWriter(socket.getOutputStream(), true); 
			input = new BufferedReader(new InputStreamReader( socket.getInputStream()));
			outputStream = socket.getOutputStream();
			inStream = new BufferedInputStream(socket.getInputStream());
		}catch(IOException e){
			e.printStackTrace();
		}
		
		// recive alice public key
		Integer keyLen = null;
		try{
			keyLen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}
		
        byte[] alicePubKeyEnc = new byte[keyLen];
        int byteCount = 0;
        //System.out.println("Allce key len: "+ keyLen);
        try{
	        while(byteCount < keyLen && (byteCount = inStream.read(alicePubKeyEnc)) > 0){
	        	System.out.println("Current bytecount: " + byteCount); // debug
	        }
        
		}catch(Exception e){
			e.printStackTrace();
		}
        //System.out.println(Arrays.toString(alicePubKeyEnc));// debug
        		
		KeyFactory bobKeyFac = null;
		try{
			bobKeyFac = KeyFactory.getInstance("DH");
		}catch(Exception e){
			e.printStackTrace();
		}
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec
            (alicePubKeyEnc);
        PublicKey alicePubKey = null;
        try{
        	alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
		}catch(Exception e){
			e.printStackTrace();
		}
        
        DHParameterSpec dhParamSpec = ((DHPublicKey)alicePubKey).getParams();
        KeyPairGenerator bobKpairGen = null;
        try{
        	bobKpairGen = KeyPairGenerator.getInstance("DH");
        	bobKpairGen.initialize(dhParamSpec);
        }catch(Exception e){
			e.printStackTrace();
		}
       
        KeyPair bobKpair = bobKpairGen.generateKeyPair();
        KeyAgreement bobKeyAgree = null;
        try{
	        bobKeyAgree = KeyAgreement.getInstance("DH");
	        bobKeyAgree.init(bobKpair.getPrivate());
        }catch(Exception e){
			e.printStackTrace();
		}
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
        
		
		output.println(bobPubKeyEnc.length); // send the length of the key

		// wait a bit for the client to avoid a race condition
		try{
			TimeUnit.SECONDS.sleep(2);
		}catch(Exception e){
			e.printStackTrace();
		}
		
		try{	
			outputStream.write(bobPubKeyEnc);
			outputStream.flush();
		}catch(Exception e){
			e.printStackTrace();
		}
		
		try{
			bobKeyAgree.doPhase(alicePubKey, true);
		}catch(Exception e){
			e.printStackTrace();
		}
		
		byte[] bobSharedSecret =  new byte[128];
		
        int bobLen;
        try{
        	bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);
        }catch(Exception e){
        	e.printStackTrace();
        }
        
        // use the first 16 bytes of the shared secret for the TEA KEY
        byte TEAkeyGenerated[] =  Arrays.copyOf(bobSharedSecret, 16);	
        return TEAkeyGenerated;
		
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
		int datalen = s.getBytes().length;
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
	
	// turn a file into a stream of bytes, encrypt it then send it
	private void sendFile(File file ,OutputStream outputStream,PrintWriter output){
		int datalen = (int) file.length();
		// ensure steam length is a multiple of 8 for encryption purposes
		int numBytesToSend = datalen + (8 - (datalen % 8));
		try{
			TimeUnit.SECONDS.sleep(1);
		}catch(Exception e){
			
		}
		
		// send the length of file
    	output.println(numBytesToSend); 
    	
    	// write the file to the socket
    	byte[] fileByteArray = new byte[numBytesToSend];
    	FileInputStream fileInputStream = null;
    	try{
    		fileInputStream = new FileInputStream(file);
    	}catch(Exception e){
    		e.printStackTrace();
    	}
    	int numBytes;
    	try{
	    	while((numBytes = fileInputStream.read(fileByteArray)) > 0){
	    		System.out.println("Reading in file...");
	    	}
	    	fileInputStream.close();
    	}catch(Exception e){
    		e.printStackTrace();
    	}
    	
    	// encrypt the file 
    	byte[] encryptedFileByteArray = encryptTEA.encrypt(fileByteArray, TEAkey);
    	try{
    		// wait for the client to begin reading 
			TimeUnit.SECONDS.sleep(1);
    		outputStream.write(encryptedFileByteArray,0,numBytesToSend);
    		System.out.println("file sent");
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
        
        // remove the trailing 0x00 byte
        int i;
        for(i = 0; i < decryptedData.length; i++ ){
        	if(decryptedData[decryptedData.length - 1 - i] != (byte) 0x00){
        		break;
        	}
        }
        int lastNonZeroByte = decryptedData.length - i;
        byte [] decryptedDataZerosRemoved = Arrays.copyOf(decryptedData,lastNonZeroByte);
        return decryptedDataZerosRemoved;
	}
	
	// turn an array of bytes into a string
	private String readString(BufferedInputStream inStream,BufferedReader input){
		byte[] rawBytes = readData( inStream, input);
		return new String(rawBytes);
	}
	

	
	public void run(){
		try{
		PrintWriter output = new PrintWriter(socket.getOutputStream(), true); 
		BufferedReader input = new BufferedReader(new InputStreamReader( socket.getInputStream()));
		OutputStream outputStream = socket.getOutputStream();
		BufferedInputStream inStream = new BufferedInputStream(socket.getInputStream());
		
		String inputLine;
		
		//read the ack
		inputLine = input.readLine();
		if(inputLine.equals(ACK)){
			System.out.println("connection established");
		}else{
			System.out.println("Protocal error, no ACK");
			System.exit(1); 
		}
		     
        // peform secure key exchange
		TEAkey  = establishKey();
        
		String logInOption = readString(inStream,input);
		// determine the log in type
		if(logInOption.equals(SIGNUP)){
			System.out.println("User is signing up");
			
			String userName = readString(inStream,input);
			String password = readString(inStream,input);
			String hashedPW = hashPassword((password + userName).getBytes());
			
			System.out.println("Username: " + userName);
			System.out.println("Hashed password: " + hashedPW);
			// write the new users credentials to the shadow file
			writeToShadow(userName,hashedPW);
			
		}else if(logInOption.equals(SIGNIN)){
			System.out.println("User signing in");
			
			String userName = readString(inStream,input);
			String password = readString(inStream,input);
			String hashedPW = hashPassword((password + userName).getBytes());
			
			System.out.println("Username: " + userName);
			System.out.println("Hashed password: " + hashedPW);
			// validate the users credentials
			if(validateCredentials(userName, hashedPW)){
				System.out.println("Valid credentials");
				output.println(ACCESSGRANTED);
		        while ((inputLine = readString(inStream,input)) != null) { 
		            if (inputLine.equals("exit")) {
		            	System.out.println("Client exiting now");
		            	break;
		            }
		                 
		            System.out.println ("File requested: " + inputLine); 
		            
		            
		            File file = retriveFile(inputLine);
		            if(file != null){ // file exists sent it
		            	sendString(FILEFOUND, outputStream, output);		            	
		            	sendFile(file, outputStream, output);
		            	System.out.println("file has been sent");
		            	
		            }else{ // file does not exits
		            	sendString(FILENOTFOUND, outputStream, output);;
		            	
		            }
		        } 
			}else{
				System.out.println("Invalid credentials");
				// the user has entered invalid credentials
				output.println(ACCESSDENIED);
			}

		}else{
			System.out.println("Protocal Error");
		}
		
		if(outputStream != null)
			outputStream.close();
		
        output.close(); 
        input.close(); 
        socket.close();
		
		}catch(IOException e){
			e.printStackTrace();
	        System.err.println("Problem with Communication Server");
	        System.exit(1); 
		}

	}
}
