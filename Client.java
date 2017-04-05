import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Client {
	private static final Integer COMSPORT = 16000;
	private static final String SERVERADDRESS = "localhost";
	public static void main(String[] args) throws IOException {
		Socket socket = new Socket(SERVERADDRESS, COMSPORT);
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String userInput;
		System.out.println ("Type Message (\"Bye.\" to quit)");
		while ((userInput = stdIn.readLine()) != null){
			output.println(userInput);

         // end loop
         if (userInput.equals("Bye."))
             break;

	    System.out.println("echo: " + input.readLine());
	   }
		output.close();
		input.close();
		stdIn.close();
		socket.close();

	}

}
