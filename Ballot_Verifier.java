/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.Base64;

//import sun.misc.BASE64Encoder;
//import sun.misc.BASE64Decoder;


public class BallotVerifier {
	public static PublicKey loadPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
			// Read public key
			byte[] keyBytes;
			keyBytes = Files.readAllBytes(new File(fileName).toPath());
			X509EncodedKeySpec spec =
					new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
	}
	
	/**
	 * Verify a signature
	 * @param args - Program arguments
	 * 		args[0] = signature file
	 * 		args[1] = public key file
	 */
	public static void main(String args[])	{
		byte[] sig_Byte = null;
		byte[] data = null;
		try {
			// Load the data and the signature from args[0]
			String path = System.getProperty("user.dir");
			FileReader f_Reader = new FileReader(path + "/" + args[0]);
			BufferedReader buff_Reader = new BufferedReader(f_Reader);
			
			data = buff_Reader.readLine().getBytes();
			//System.out.println(data);
			String sig_BytesString = buff_Reader.lines().collect(Collectors.joining());
			//System.out.println(sig_BytesString);
            buff_Reader.close();        

            sig_Byte = Base64.getDecoder().decode(sig_BytesString.trim());
				
			
			// Load the public key from args[1]
            String keyFile = path + "/" + args[1];
            PublicKey p_Key = loadPublicKey(keyFile);
            
			// Verify the signature matches the data
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initVerify(p_Key);
			sig.update(data);
			System.out.println(sig.verify(sig_Byte));
            
		} catch (Exception ex) {
			Logger.getLogger(BallotVerifier.class.getName()).log(Level.SEVERE, null, ex);
		}
	}
}
