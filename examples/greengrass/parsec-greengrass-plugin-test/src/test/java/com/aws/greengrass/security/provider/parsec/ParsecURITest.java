/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.hamcrest.core.Is;
import org.hamcrest.core.IsNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.net.URI;
import java.net.URISyntaxException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(GGExtension.class)
class ParsecURITest {

    @Test
    void GIVEN_expected_parsec_key_uri_WHEN_create_object_THEN_return_proper_attributes() throws Exception {
        String uriStr = "parsec:object=private-key;type=private";
        ParsecURI uri = new ParsecURI(uriStr);
        assertThat(uri.getLabel(), Is.is("private-key"));
        assertThat(uri.getType(), Is.is("private"));
        assertThat(uri.toString(), Is.is(uriStr));
    }

    @Test
    void GIVEN_parsec_key_uri_missing_type_WHEN_create_object_THEN_return_null_type() throws Exception {
        ParsecURI uri = new ParsecURI("parsec:object=private-key");
        assertThat(uri.getLabel(), Is.is("private-key"));
        assertThat(uri.getType(), IsNull.nullValue());
    }

    @Test
    void GIVEN_expected_parsec_cert_uri_WHEN_create_object_THEN_return_proper_attributes() throws Exception {
        ParsecURI uri = new ParsecURI("parsec:object=cert-label;type=cert;id=12345;token=/path/to/lib");
        assertThat(uri.getLabel(), Is.is("cert-label"));
        assertThat(uri.getType(), Is.is("cert"));
    }

    @Test
    void GIVEN_file_uri_WHEN_create_object_THEN_throw_exception() {
        String path = "file:///path/to/file";
        Exception e = assertThrows(IllegalArgumentException.class,  () -> new ParsecURI(URI.create(path)));
        assertThat(e.getMessage(), containsString("URI scheme is not parsec: " + path));
    }

    @Test
    void GIVEN_null_string_WHEN_create_object_THEN_throw_exception() {
        String str = null;
        assertThrows(NullPointerException.class,  () -> new ParsecURI(str));
    }

    @Test
    void GIVEN_empty_string_WHEN_create_object_THEN_throw_exception() {
        assertThrows(URISyntaxException.class,  () -> new ParsecURI("  "));
    }

    @Test
    void GIVEN_uri_missing_scheme_WHEN_create_object_THEN_throw_exception() {
        assertThrows(IllegalArgumentException.class,  () -> new ParsecURI("object=private-key;type=private"));
    }

    @Test
    void GIVEN_uri_missing_separator_WHEN_create_object_THEN_missing_attribute() throws Exception {
        String uriStr = "parsec:object=private-keytype=private";
        ParsecURI uri = new ParsecURI(uriStr);
        assertThat(uri.getLabel(), Is.is("private-keytype=private"));
        assertThat(uri.getType(), IsNull.nullValue());
    }
}