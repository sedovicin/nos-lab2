import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Base64;

public class NOSFileWriter {

    private final BufferedWriter writer;

    public NOSFileWriter(final File file) throws IOException {
	FileOutputStream os = new FileOutputStream(file, false);
	writer = new BufferedWriter(new OutputStreamWriter(os, "ASCII"));

	writer.write("---BEGIN OS2 CRYPTO DATA---");
	writer.newLine();
    }

    public void writeFieldString(final String fieldName, final String... values) throws IOException {
	writer.write(fieldName + ":");
	writer.newLine();
	for (int i = 0; i < values.length; ++i) {
	    writer.write("    " + values[i]);
	    writer.newLine();
	}
	writer.newLine();
    }

    public void writeFieldHex(final String fieldName, final byte[] value) throws IOException {
	writer.write(fieldName + ":");
	writer.newLine();
	writer.write(byteToHexFormatted(value));
	writer.newLine();
	writer.newLine();
    }

    public void writeFieldBase64(final String fieldName, final byte[] value) throws IOException {
	writer.write(fieldName + ":");
	writer.newLine();
	writer.write(byteToBase64Formatted(value));
	writer.newLine();
	writer.newLine();
    }

    public void flush() throws IOException {
	writer.write("---END OS2 CRYPTO DATA---");
	writer.newLine();
	writer.flush();
	writer.close();
    }

    private static String byteToHexFormatted(final byte[] bytes) {
	StringBuilder sb = new StringBuilder();
	sb.append("    ");
	for (byte b : bytes) {
	    int lastIndex = sb.lastIndexOf("\n");
	    if (((sb.length() % 64) == 0) && (lastIndex < 0)) {
		sb.append(System.lineSeparator());
		sb.append("    ");

	    } else if ((((lastIndex + 1) - (sb.length() % 64)) % 64) == 0) {
		sb.append(System.lineSeparator());
		sb.append("    ");
	    }
	    sb.append(String.format("%02x", b));
	}
	return sb.toString();
    }

    private static String byteToBase64Formatted(final byte[] bytes) {
	byte[] valueB64 = Base64.getEncoder().encode(bytes);
	String stringB64 = new String(valueB64);

	StringBuilder sb = new StringBuilder();
	for (int i = 0; i < stringB64.length(); i += 60) {

	    sb.append("    ");
	    if ((i + 60) >= stringB64.length()) {
		sb.append(stringB64.substring(i));
	    } else {
		sb.append(stringB64.substring(i, i + 60));
		sb.append(System.lineSeparator());
	    }

	}
	return sb.toString();
    }
}
