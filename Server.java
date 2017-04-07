import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


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
		OutputStream outputStream = null;
		
		String inputLine;
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
