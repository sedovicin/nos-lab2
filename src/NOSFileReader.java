import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class NOSFileReader {

    private final Map<String, String> fields;

    public NOSFileReader(final File file) {
	fields = new HashMap<>();
	try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
	    String line = reader.readLine();
	    if (!line.equals("---BEGIN OS2 CRYPTO DATA---")) {
		throw new Exception("Not a NOS crypto file");
	    }

	    line = reader.readLine();

	    String fieldName = null;
	    StringBuffer sb = new StringBuffer();
	    while (!line.equals("---END OS2 CRYPTO DATA---")) {
		if (line.length() <= 1) {
		    if (sb.length() >= 1) {
			fields.put(fieldName, sb.toString());
		    }
		    sb = new StringBuffer();
		} else if (line.startsWith("    ")) {
		    sb.append(line.substring(4));
		} else {
		    fieldName = line.substring(0, line.length() - 1);
		}
		line = reader.readLine();
	    }
	} catch (FileNotFoundException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (Exception e) {
	    e.printStackTrace();
	}

    }

    public String readField(final String fieldName) {
	return fields.get(fieldName);
    }

    public byte[] readFieldHex(final String fieldName) {
	String value = fields.get(fieldName);
	byte[] originalValue = new byte[value.length()];

	for (int i = 0; i < originalValue.length; ++i) {
	    originalValue[i] = (byte) Character.digit(value.charAt(i), 16);
	}
	byte[] byteValue = new byte[value.length() / 2];

	for (int i = 0; i < originalValue.length; ++i) {
	    if ((i % 2) == 0) {
		byteValue[i / 2] = (byte) (originalValue[i] << 4);
	    } else {
		byteValue[i / 2] = originalValue[i];
	    }

	}

	return byteValue;

    }

}
