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

  public static final String PARSEC_SCHEME = "parsec";
  private static final String IMPORT_KEY = "import";
  private static final String LABEL_KEY = "object";

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

  public ParsecURI(@NonNull String label, @NonNull String importFile) {
    this(URI.create(String.format("%s:%s=%s;%s=%s", PARSEC_SCHEME, IMPORT_KEY, importFile, LABEL_KEY, label)));
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
  public String getImport() {
    return attributeMap.get(IMPORT_KEY);
  }

  public String getLabel() {
    return attributeMap.get(LABEL_KEY);
  }


  @Override
  public String toString() {
    return this.uri.toString();
  }

  public static boolean isParsecUri(String uri) {
    try {
      validateParsecURI(URI.create(uri));
      return true;
    } catch (KeyLoadingException e) {
      return false;
    }
  }

  public static ParsecURI validateParsecURI(URI key) throws KeyLoadingException {
    ParsecURI keyUri;
    try {
      keyUri = new ParsecURI(key);
    } catch (IllegalArgumentException e) {
      throw new KeyLoadingException(String.format("Invalid key URI: %s", key), e);
    }
    if (Utils.isEmpty(keyUri.getLabel())) {
      throw new KeyLoadingException("Empty key label in key URI");
    }
    return keyUri;
  }

  public static ParsecURI validateKeyAndCertUris(URI certUri, ParsecURI keyUri) throws KeyLoadingException {
    ParsecURI certPkcs11Uri = validateParsecURI(certUri);
    if (!keyUri.getLabel().equals(certPkcs11Uri.getLabel())) {
      throw new KeyLoadingException("Private key and certificate labels must be the same");
    }
    return certPkcs11Uri;
  }
}
