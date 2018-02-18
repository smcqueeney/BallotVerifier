/**
 *
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;



/**
 * @author Kevin Bryan
 */
public class Ballot {

	List<String> options = new ArrayList<>();
	List<Integer> selections = new ArrayList<>();

	/**
	 * Return options (unmodifiable)
	 *
	 * @return Options
	 */
	public List<String> getOptions() {
		return Collections.unmodifiableList(options);
	}

	/**
	 * Load options
	 *
	 * @param input Configuration file (currently just a per-line list of
	 * strings)
	 * @throws IOException
	 */
	public void loadOptions(BufferedReader input) throws IOException {
		String line;
		options.clear();
		try {
			while ((line = input.readLine()) != null) {
				options.add(line);
			}
		} catch (IOException e) {
			throw new IOException("Failed reading config file", e);
		}
	}

	/**
	 * Write options with selectors
	 *
	 * @param out Stream to write options to
	 */
	public void printOptions(PrintStream out) {
		int optionSelector = 1;
		for (String option : options) {
			out.print(optionSelector++);
			out.print('\t');
			out.println(option);
		}
	}

	/**
	 * Convert the user input to an integer, and check the range
	 *
	 * @param str User Input
	 * @return User selected Index
	 */
	public int selectionToIndex(String str) throws IndexOutOfBoundsException, IllegalArgumentException {
		int idx = Integer.parseInt(str, 10);
		if ((idx < 1) || (idx > options.size())) {
			throw new IndexOutOfBoundsException("No such option");
		} else if (selections.contains(idx)) {
			throw new IllegalArgumentException("Duplicate entry");
		}
		return idx;
	}

	/**
	 * Read selections from the user as a numbers, one per line
	 *
	 * @param in Stream to read selections from
	 * @throws java.io.IOException
	 */
	public void inputSelection(InputStream in) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
		String str;
		int idx;
		selections.clear();
		while (selections.size() != options.size()) {
			try {
				str = reader.readLine();
				if (str == null) {
					throw new IOException("Premature end of input");
				}
				idx = selectionToIndex(str);
			} catch (IllegalArgumentException | IndexOutOfBoundsException e) {
				System.err.println(e.getMessage());
				continue;
			} catch (IOException e) {
				throw new IOException("Failed reading user input", e);
			}
			selections.add(idx);
		}
	}

	/**
	 * Writes selected items in order previously specified
	 *
	 * @param out Stream to write selections
	 */
	public void printSelectionOrder(PrintStream out) {
		for (int idx : selections) {
			out.print(options.get(idx - 1));
		}
	}

	/**
	 *
	 * @param fileName - File to load private key from
	 * @return PrivateKey loaded from file
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey loadPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			byte[] pkeyBytes = Files.readAllBytes(new File(fileName).toPath());
			PKCS8EncodedKeySpec rspec;
			rspec = new PKCS8EncodedKeySpec(pkeyBytes);
			return kf.generatePrivate(rspec);
	}

	/**
	 * @param args - Program arguments
	 *             - First argument is config file
	 *             - Second argument is Ballot Private Key file
	 */
	public static void main(String[] args) {
		Ballot ballot = new Ballot();
		if (args.length < 1) {
			System.err.println("Please provide an options file");
			runTests();
			System.exit(-1);
		}
		try {
			// Load Private key from args[1]
			String keyFile = args[1];
			PrivateKey p_Key = loadPrivateKey(keyFile);

			BufferedReader configFile;
			configFile = new BufferedReader(new InputStreamReader(new FileInputStream(args[0]), StandardCharsets.UTF_8));
			ballot.loadOptions(configFile);
			ballot.printOptions(System.out);
			ballot.inputSelection(System.in);
			ballot.printSelectionOrder(System.out);

			// Use ByteArrayOutputStream and print the selections into it
			//  Consider the format used so that you can load it in the next phase
			ByteArrayOutputStream out_Stream = new ByteArrayOutputStream();
			PrintStream p_Stream = new PrintStream(out_Stream);
			PrintStream last = System.out;
			System.setOut(p_Stream);
			ballot.printSelectionOrder(System.out);
			System.out.flush();
			System.setOut(last);
			
			// Sign the data in the output stream with loaded private key
			Signature s_Data = Signature.getInstance("SHA1withRSA");
			s_Data.initSign(p_Key);
			s_Data.update(out_Stream.toByteArray());
			byte[] s_Byte = s_Data.sign();
						
			
			// Write the data  and the signature (base64 encoded) to a file called "ballot.txt"
			String path = System.getProperty("user.dir");
			FileWriter f_Writer = new FileWriter(path + "/ballot.txt");
			f_Writer.write(out_Stream + "\n" + Base64.getEncoder().encodeToString(s_Byte));
			f_Writer.close();
			
			
			
		} catch (IOException ex) {
			Logger.getLogger(Ballot.class.getName()).log(Level.SEVERE, null, ex);
		} catch (Exception ex) {
			Logger.getLogger(Ballot.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	public static void runTests() {
		String[] goodTestInputs = {
			"1\n2\n3\n",
			"3\n1\n2\n",
			"1\n1\n2\n3\n", // duplicate number, but fixed
			"1\n2\n3\n4\n" // more input ok
		};
		String[] badTestInputs = {
			"", // No input
			"1", // new newline
			"1\n", // insufficient number
			"a\n", //not a number
		};

		runTestSet("** GOOD **", goodTestInputs);
		runTestSet("** BAD  **", badTestInputs);
	}

	public static void runTestSet(String setName, String[] testInputs) {
		System.err.println(setName);
		String testConfigString = "Option1\nOption2\nOption3\n";
		InputStream testConfig = new ByteArrayInputStream(testConfigString.getBytes());
		BufferedReader configFile = new BufferedReader(new InputStreamReader(testConfig));
		Ballot ballot = new Ballot();
		try {
			ballot.loadOptions(configFile);
		} catch (IOException ex) {
			// Should never happen on static input
			Logger.getLogger(Ballot.class.getName()).log(Level.SEVERE, null, ex);
		}

		for (String input : testInputs) {
			System.out.println("Input: '" + input + "'");
			try {
				ByteArrayInputStream test = new ByteArrayInputStream(input.getBytes());
				ballot.inputSelection(test);
				ballot.printSelectionOrder(System.out);
			} catch (Exception e) {
				System.err.println(e.getMessage());
			}
		}
	}
}