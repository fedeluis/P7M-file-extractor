package fedeluis.proj.psm;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.util.Store;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;

public class PSM {

    public static void main(String[] args) {
        String filePath = "<global file path>.p7m";
        try {
            // load file
            byte[] buffer = Files.readAllBytes(Paths.get(filePath));

            Certificate cert = null;

            InputStream is = new FileInputStream(filePath);
            // certificate generation
            CertificateFactory bcfact = new CertificateFactory();
            cert = bcfact.engineGenerateCertificate(is);
            byte[] decodedCert = cert.getEncoded();

            // some information extraction
            java.security.cert.CertificateFactory fact = java.security.cert.CertificateFactory.getInstance("X.509");
            X509Certificate xcert = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(decodedCert));

            System.out.println("Subject DN: " + xcert.getSubjectDN().getName());
            System.out.println("Issuer: " + xcert.getIssuerDN().getName());
            System.out.println("Not After: " + xcert.getNotAfter());
            System.out.println("Not Before: " + xcert.getNotBefore());
            System.out.println("Version: " + xcert.getVersion());
            System.out.println("Serial number: " + xcert.getSerialNumber());
            System.out.println("Sign alg: " + xcert.getSigAlgName());

            // public key generation
            PublicKey publicKey = xcert.getPublicKey();
            System.out.println("PublicKey: \n" + publicKey);

            System.out.println(Base64.getEncoder().encodeToString(xcert.getSignature()));

            // starting extraction of signed content from file
            CMSSignedData signature = new CMSSignedData(buffer);
            Store cs = signature.getCertificates();
            SignerInformationStore signerInfos = signature.getSignerInfos();
            Collection c = signerInfos.getSigners();
            Iterator it = c.iterator();

            // byte array that contains P7M file content
            byte[] data = null;
            X509CertificateHolder certificateHolder = null;

            while (it.hasNext()) {
                // certificate and signer extraction
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = cs.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                certificateHolder = (X509CertificateHolder) certIt.next();

                // signed content extraction
                CMSProcessable sc = signature.getSignedContent();
                data = (byte[]) sc.getContent();

                // output file generation
                String outputFile = "<global file path>.pdf";
                FileUtils.writeByteArrayToFile(new File(outputFile), data);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
