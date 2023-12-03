import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class App {
    public static void main(String[] args) throws Exception {
        // Load the X509 certificate file
        FileInputStream fis = new FileInputStream("./nintendo.pem");

        // Create a CertificateFactory object
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Parse the X509 certificate
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

        // Display the field values
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Issuer: " + cert.getIssuerDN());
        System.out.println("Serial Number: " + cert.getSerialNumber());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid Until: " + cert.getNotAfter());
        System.out.println("Public Key: " + cert.getPublicKey());
    }
}
