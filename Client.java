import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;

public class Client {
	private static final Integer COMSPORT = 16000;
	private static final String SERVERADDRESS = "localhost";
	private static final String ACCESSGRANTED = "G";
	private static final String ACCESSDENIED = "D";
	private static final String SIGNUP = "U";
	private static final String SIGNOUT = "I";
	private static final String FILEFOUND = "F";
	private static final String FILENOTFOUND = "N";
			
	
	public static void main(String[] args) throws IOException {
		Socket socket = new Socket(SERVERADDRESS, COMSPORT);
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
		System.out.println("Signin (" + SIGNOUT + "), Signup (" + SIGNUP + ")");
		String userInput;
		userInput = stdIn.readLine();
		
		if(userInput.equals("U")){
			output.println("U");
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
			output.println("I");
			System.out.println("Username: ");
			String userName =  stdIn.readLine();
			output.println(userName);
			System.out.println("Password: ");
			String password =  stdIn.readLine();
			output.println(password);
			String credentialCheckMsg = input.readLine();
			if(credentialCheckMsg.equals(ACCESSGRANTED)){
				System.out.println ("Valid credentials, enter filenames (\"exit\" to quit)");
				
				while ((userInput = stdIn.readLine()) != null){
					output.println(userInput); // send the name of the file
					String fileFound = input.readLine();
					
					if(fileFound.equals(FILEFOUND)){
						Integer lengthOfFile = Integer.parseInt(input.readLine());
						// Receive the file 
				        InputStream in = socket.getInputStream();
				        System.out.println("Reciving file: " + userInput);
				        OutputStream out = new FileOutputStream("./" + userInput);
				        
				        byte[] fileBytes = new byte[lengthOfFile];
				        
				        int byteCount;
				        while((byteCount = in.read(fileBytes)) > 0){
				        	out.write(fileBytes, 0, byteCount);
				        }
				        out.close();
				        in.close();
				        
					}else if(fileFound.equals(FILENOTFOUND)){
						System.out.println("Sorry file not found.");
					}else{
						System.out.println("Protocal error, exiting.");
						break;
					}
					
	
		         // end loop
		         if (userInput.equals("exit"))
		             break;
	
			    System.out.println("echo: " + input.readLine());
				}
		   }else if(credentialCheckMsg.equals(ACCESSDENIED)){
			   System.out.println("Invalid cedentials, exiting.");
		   }else{
			   System.out.println("Protocal error, exiting.");
		   }
		}

		output.close();
		input.close();
		stdIn.close();
		socket.close();

	}

}
