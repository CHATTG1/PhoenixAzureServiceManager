package com.phoenix.azure;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.phoenix.utils.XmlFormatter;

public class PhoenixAzureServiceManager {

	// holds the name of the store which will be used to build the output
	private String outStore;
	// holds the name of the publishSettingsFile
	private String publishSettingsFile;
	// The value of the subscription id that is being used
	private String subscriptionId;
	private SSLSocketFactory factory;

	private String azureRestAPIEndPoint = "https://management.core.windows.net/";

	public PhoenixAzureServiceManager(String publishSettingsFile,
			String subscriptionId) throws Exception {
		super();
		this.publishSettingsFile = publishSettingsFile;
		this.subscriptionId = subscriptionId;
		this.outStore = "temp.cert";

		// Step 1: Read in the .publishsettings file
		File file = new File(getPublishSettingsFile());
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(file);
		doc.getDocumentElement().normalize();

		// Step 2: Get the PublishProfile
		NodeList ndPublishProfile = doc.getElementsByTagName("PublishProfile");
		Element publishProfileElement = (Element) ndPublishProfile.item(0);

		// Step 3: Get the PublishProfile
		String certificate = publishProfileElement
				.getAttribute("ManagementCertificate");
		System.out.println("Base 64 cert value: " + certificate);

		// Step 4: Load certificate into keystore
		setFactory(getFactory(certificate));
	}

	/*
	 * Used to create the PKCS#12 store - important to note that the store is
	 * created on the fly so is in fact passwordless - the JSSE fails with
	 * masqueraded exceptions so the BC provider is used instead - since the
	 * PKCS#12 import structure does not have a password it has to be done this
	 * way otherwise BC can be used to load the cert into a keystore in advance
	 * and password
	 */
	private KeyStore createKeyStorePKCS12(String base64Certificate)
			throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore store = KeyStore.getInstance("PKCS12",
				BouncyCastleProvider.PROVIDER_NAME);
		store.load(null, null);

		// read in the value of the base 64 cert without a password (PBE can be
		// applied afterwards if this is needed
		InputStream sslInputStream = new ByteArrayInputStream(
				Base64.decode(base64Certificate));
		store.load(sslInputStream, "".toCharArray());

		// we need to a create a physical keystore as well here
		OutputStream out = new FileOutputStream(getOutStore());
		store.store(out, "".toCharArray());
		out.close();
		return store;
	}

	/*
	 * Used to get an SSL factory from the keystore on the fly - this is then
	 * used in the request to the service management which will match the
	 * .publishsettings imported certificate
	 */
	private SSLSocketFactory getFactory(String base64Certificate)
			throws Exception {
		KeyManagerFactory keyManagerFactory = KeyManagerFactory
				.getInstance("SunX509");
		KeyStore keyStore = createKeyStorePKCS12(base64Certificate);

		// gets the TLS context so that it can use client certs attached to the
		SSLContext context = SSLContext.getInstance("TLS");
		keyManagerFactory.init(keyStore, "".toCharArray());
		context.init(keyManagerFactory.getKeyManagers(), null, null);

		return context.getSocketFactory();
	}

	// gets the name of the java keystore
	public String getOutStore() {
		return outStore;
	}

	// sets the name of the java keystore
	public void setOutStore(String outStore) {
		this.outStore = outStore;
	}

	// gets the name of the publishsettings file
	public String getPublishSettingsFile() {
		return publishSettingsFile;
	}

	// sets the name of the java publishsettings file
	public void setPublishSettingsFile(String publishSettingsFile) {
		this.publishSettingsFile = publishSettingsFile;
	}

	// get the value of the subscription id
	public String getSubscriptionId() {
		return subscriptionId;
	}

	// sets the value of the subscription id
	public void setSubscriptionId(String subscriptionId) {
		this.subscriptionId = subscriptionId;
	}

	public SSLSocketFactory getFactory() {
		return factory;
	}

	public void setFactory(SSLSocketFactory factory) {
		this.factory = factory;
	}

	// deletes the outstore keystore when it has finished with it
	private void deleteOutStoreFile() {
		// the file will exist if we reach this point
		try {
			java.io.File file = new java.io.File(getOutStore());
			file.delete();
		} catch (Exception ex) {
		}
	}

	public String getAzureAPIEndPoint() {
		return this.azureRestAPIEndPoint + this.getSubscriptionId();
	}

	public void getResourceExtensions() throws IOException {
		URL url = new URL(this.getAzureAPIEndPoint()
				+ "/services/resourceextensions");
		System.out.println("Service Management request: " + url.toString());
		this.restAPIGet(url);
	}

	public void getHostedServices() throws IOException {
		URL url = new URL(this.getAzureAPIEndPoint()
				+ "/services/hostedservices");
		System.out.println("Service Management request: " + url.toString());
		this.restAPIGet(url);
	}

	public void getStorageAccounts() throws IOException {
		URL url = new URL(this.getAzureAPIEndPoint()
				+ "/services/storageservices");
		System.out.println("Service Management request: " + url.toString());
		this.restAPIGet(url);
	}

	public void getLocationRegion() throws IOException {
		URL url = new URL(this.getAzureAPIEndPoint() + "/locations");
		System.out.println("Service Management request: " + url.toString());
		this.restAPIGet(url);
	}

	public void restAPIGet(URL url) throws IOException {
		HttpsURLConnection connection = (HttpsURLConnection) url
				.openConnection();
		// Add certificate to request
		connection.setSSLSocketFactory(getFactory());

		// Generate response
		connection.setRequestMethod("GET");
		connection.setRequestProperty("x-ms-version", "2012-03-01");
		int responseCode = connection.getResponseCode();

		// response code should be a 200 OK - other likely code is a 403
		// forbidden if the certificate has not been added to the
		// subscription for any reason

		InputStream responseStream = null;
		if (responseCode == 200) {
			responseStream = connection.getInputStream();
		} else {
			responseStream = connection.getErrorStream();
		}
		BufferedReader buffer = new BufferedReader(new InputStreamReader(
				responseStream));
		// response will come back on a single line
		String inputLine = buffer.readLine();
		buffer.close();
		System.out.println(new XmlFormatter().format(inputLine));
	}

	protected void finalize() {
		this.deleteOutStoreFile();
	}

	public static void main(String[] args) {
		try {
			
			// Use your own pubilshersettings file for Azure subscription.
						PhoenixAzureServiceManager manager = new PhoenixAzureServiceManager(
					"E:\\chirag-azure.publishsettings",
					"40a031a0-5444-4209-8136-ce768a393840");
			manager.getHostedServices();
			manager.getResourceExtensions();
			manager.getStorageAccounts();
			manager.getLocationRegion();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
