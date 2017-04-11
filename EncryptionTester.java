import java.util.Arrays;

public class EncryptionTester {
	static{
		System.loadLibrary("encrypt");

	}
	public static void main(String[] args){
		String str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse vitae risus mi. Sed rutrum sed.";
		
	
		int datalen = str.getBytes().length;
		
		byte[] data = new byte[datalen + (8 - (datalen % 8))];
		System.out.println("The data");
		System.out.println(Arrays.toString(data));
		data = str.getBytes();
		System.out.println("Spaces");
		System.out.println(" ".getBytes());
		//need to pad file with spaces if nessasary
		
		byte[] key = {(byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
				        (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
				        (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
				        (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D};
		Encryption en = new Encryption();
		en.encrypt(data, key);
	}

}
