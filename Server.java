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

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.interfaces.*;


public class Server extends Thread{
	private Socket socket;
	private static final Integer COMSPORT = 16000;
	private static final String SHADOWFILENAME = "shadow.txt";
	private static final String ACCESSGRANTED = "G";
	private static final String ACCESSDENIED = "D";
	private static final String SIGNUP = "U";
	private static final String SIGNOUT = "I";
	private static final String FILEFOUND = "F";
	private static final String FILENOTFOUND = "N";
	private static final String ACK = "ACK";
	
	// from https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
	
    // from https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        }
        return buf.toString();
    }
	
	//https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
	public static byte[] generatePrivateKey(byte[] alicePubKeyEnc,Socket socket,PrintWriter output,OutputStream outputStream,BufferedReader input){
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
        
		
		//outputStream = socket.getOutputStream();
		System.out.println(Arrays.toString(bobPubKeyEnc));//debug
		System.out.println("Send bob's key, length = ");//debug
		System.out.println(bobPubKeyEnc.length);//debug
		output.println(bobPubKeyEnc.length); // send the length of the key
		
		try{
			//outputStream = socket.getOutputStream();
			outputStream.write(bobPubKeyEnc);
			
			System.out.println("Bob's key sent");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		try{
			bobKeyAgree.doPhase(alicePubKey, true);
		}catch(Exception e){
			e.printStackTrace();
		}
		
		// get the length of the secret key
		Integer aliceLen = null;
		try{
			aliceLen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}	
			
		
		byte[] bobSharedSecret =  new byte[aliceLen];
		
        int bobLen;
        try{
        	bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 1);
        }catch(Exception e){
        	e.printStackTrace();
        }
        return bobSharedSecret;
        
	}
	
	public static void main(String[] args) throws IOException {
		 ServerSocket serverSocket = null; 
		 serverSocket = new ServerSocket(COMSPORT);
		 while (true){
			 new Server(serverSocket.accept());
		 }
	}
	
	Server(Socket s){
		socket = s;
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
	

	
	public void run(){
		try{
		PrintWriter output = new PrintWriter(socket.getOutputStream(), true); 
		BufferedReader input = new BufferedReader(new InputStreamReader( socket.getInputStream()));
		OutputStream outputStream = socket.getOutputStream();
		InputStream inStream = socket.getInputStream();
		
		String inputLine;
		
		//read the ack
		inputLine = input.readLine();
		if(inputLine.equals(ACK)){
			System.out.println("connection established");
		}else{
			System.out.println("Protocal error, no ACK");
			System.exit(1); 
		}
		
		// recive alice public key
		Integer keyLen = Integer.parseInt(input.readLine());
        byte[] alicePubKeyEnc = new byte[keyLen];
        int byteCount = 0;
        while(byteCount < keyLen && (byteCount = inStream.read(alicePubKeyEnc)) > 0){
        	System.out.println("Current bytecount: " + byteCount); // debug
        }
        System.out.println(Arrays.toString(alicePubKeyEnc));// debug
        
        //send back bob's public key
        //byte[] bobPubKeyEnc = generatePrivateKey(alicePubKeyEnc);
        
        //byte[] bobSharedSecret = generatePrivateKey(alicePubKeyEnc, socket, output, outputStream, input);
        
        //System.out.println("Bob secret: " +
                //toHexString(bobSharedSecret));
//		output.println(bobPubKeyEnc.length); // send the length of the key
//		outputStream = socket.getOutputStream();
//		System.out.println(Arrays.toString(bobPubKeyEnc));//debug
//		outputStream.write(bobPubKeyEnc);
        		
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
        
		
		//outputStream = socket.getOutputStream();
		System.out.println(Arrays.toString(bobPubKeyEnc));//debug
		System.out.println("Send bob's key, length = ");//debug
		System.out.println(bobPubKeyEnc.length);//debug
		output.println(bobPubKeyEnc.length); // send the length of the key
		output.flush();
		try{
			//outputStream = socket.getOutputStream();
			outputStream.write(bobPubKeyEnc);
			
			System.out.println("Bob's key sent");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		try{
			bobKeyAgree.doPhase(alicePubKey, true);
		}catch(Exception e){
			e.printStackTrace();
		}
		
		// get the length of the secret key
		Integer aliceLen = null;
		try{
			aliceLen = Integer.parseInt(input.readLine());
		}catch(Exception e){
			e.printStackTrace();
		}	
			
		
		byte[] bobSharedSecret =  new byte[aliceLen];
		
        int bobLen;
        try{
        	bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 1);
        }catch(Exception e){
        	e.printStackTrace();
        }
        
        
        
        
        
        
        
        
		String logInOption = input.readLine();
		if(logInOption.equals(SIGNUP)){
			System.out.println("User signing up");
			
			String userName = input.readLine();
			String password = input.readLine();
			String hashedPW = hashPassword((password + userName).getBytes());
			
			System.out.println("Username: " + userName);
			System.out.println("Hashed password: " + hashedPW);
			writeToShadow(userName,hashedPW);
			
		}else if(logInOption.equals(SIGNOUT)){
			System.out.println("User signing in");
			
			String userName = input.readLine();
			String password = input.readLine();
			String hashedPW = hashPassword((password + userName).getBytes());
			
			System.out.println("Username: " + userName);
			System.out.println("Hashed password: " + hashedPW);
			if(validateCredentials(userName, hashedPW)){
				System.out.println("Valid credentials");
				output.println(ACCESSGRANTED);
		        while ((inputLine = input.readLine()) != null) { 
		            if (inputLine.equals("exit")) {
		            	System.out.println("Client exiting now");
		            	break;
		            }
		                 
		            System.out.println ("File requested: " + inputLine); 
		            
		            
		            File file = retriveFile(inputLine);
		            if(file != null){ // file exists sent it
		            	output.println(FILEFOUND);
		            	output.println(file.length()); // send the length of file
		            	// write the file to the socket
		            	byte[] fileByteArray = new byte [(int) file.length()];
		            	FileInputStream fileInputStream = new FileInputStream(file);
		            	outputStream = socket.getOutputStream();
		            	int numBytes;
		            	while((numBytes = fileInputStream.read(fileByteArray)) > 0){
		            		outputStream.write(fileByteArray,0,numBytes);
		            	}
		            	System.out.println("file has been sent");
		            	
		            }else{ // file does not exits
		            	output.println(FILENOTFOUND);
		            	
		            }
		        } 
		        System.out.println("exited while loop"); // debug 
			}else{
				System.out.println("Invalid credentials");
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
