package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.util.Utils;
import lombok.NonNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to interprete Parsec URI.
 */
public class ParsecURI {
  private static final String PARSEC_TYPE_PRIVATE = "private";
  private static final String PARSEC_TYPE_CERT = "cert";

  public static final String PARSEC_SCHEME = "parsec";
  private static final String LABEL_KEY = "object";
  private static final String TYPE_KEY = "type";

  private final URI uri;
  private final Map<String, String> attributeMap = new HashMap<>();

  /**
   * Constructor of Parsec URI.
   *
   * @param str String used to parse parsec attributes
   * @throws URISyntaxException if str is not valid URI
   */
  public ParsecURI(@NonNull String str) throws URISyntaxException {
    this(new URI(str));
  }

  /**
   * Constructor of Parsec URI.
   *
   * @param uri URI used to parse parsec attributes
   */
  public ParsecURI(URI uri) {
    this.uri = uri;
    if (!PARSEC_SCHEME.equalsIgnoreCase(this.uri.getScheme())) {
      throw new IllegalArgumentException(String.format("URI scheme is not %s: %s", PARSEC_SCHEME, uri));
    }
    parseAttributes(this.uri.getSchemeSpecificPart());
  }

  private void parseAttributes(String schemeSpecificPart) {
    String[] attributes = schemeSpecificPart.split(";");
    for (String attribute : attributes) {
      int i = attribute.indexOf('=');
      if (i != -1) {
        attributeMap.put(attribute.substring(0, i).trim(), attribute.substring(i + 1).trim());
      }
    }
  }

  public String getLabel() {
    return attributeMap.get(LABEL_KEY);
  }

  public String getType() {
    return attributeMap.get(TYPE_KEY);
  }

  @Override
  public String toString() {
    return this.uri.toString();
  }




  public static ParsecURI validatePrivateKeyUri(URI privateKeyUri) throws KeyLoadingException {
    ParsecURI keyUri;
    try {
      keyUri = new ParsecURI(privateKeyUri);
    } catch (IllegalArgumentException e) {
      throw new KeyLoadingException(String.format("Invalid private key URI: %s", privateKeyUri), e);
    }

    if (Utils.isEmpty(keyUri.getLabel())) {
      throw new KeyLoadingException("Empty key label in private key URI");
    }
    if (!PARSEC_TYPE_PRIVATE.equals(keyUri.getType())) {
      throw new KeyLoadingException(String.format("Private key must be a Parsec %s type, but was %s",
              PARSEC_TYPE_PRIVATE, keyUri.getType()));
    }
    return keyUri;
  }

  public static ParsecURI validateCertificateUri(URI certUri, ParsecURI keyUri) throws KeyLoadingException {
    ParsecURI certPkcs11Uri;
    try {
      certPkcs11Uri = new ParsecURI(certUri);
    } catch (IllegalArgumentException e) {
      throw new KeyLoadingException(String.format("Invalid certificate URI: %s", certUri), e);
    }
    if (!PARSEC_TYPE_CERT.equals(certPkcs11Uri.getType())) {
      throw new KeyLoadingException(String.format("Certificate must be a Parsec %s type, but was %s",
              PARSEC_TYPE_CERT, certPkcs11Uri.getType()));
    }
    if (!keyUri.getLabel().equals(certPkcs11Uri.getLabel())) {
      throw new KeyLoadingException("Private key and certificate labels must be the same");
    }
    return certPkcs11Uri;
  }
}
