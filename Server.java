import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server extends Thread{
	private Socket socket;
	private static final Integer COMSPORT = 16000;
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
	public void run(){
		try{
		PrintWriter output = new PrintWriter(socket.getOutputStream(), true); 
		BufferedReader input = new BufferedReader(new InputStreamReader( socket.getInputStream()));
		String inputLine;
		
        while ((inputLine = input.readLine()) != null) { 
            System.out.println ("Server: " + inputLine); 
            output.println(inputLine); 

            if (inputLine.equals("Bye.")) 
                break; 
        } 
        output.close(); 
        input.close(); 
        socket.close();
		
		}catch(IOException e){
	         System.err.println("Problem with Communication Server");
	         System.exit(1); 
		}

	}
}
