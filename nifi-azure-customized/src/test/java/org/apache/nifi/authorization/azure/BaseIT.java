/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.nifi.authorization.azure;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.file.FileUtils;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class BaseIT {
    protected static final Properties CONFIG;

    protected static final String CREDENTIALS_FILE = System.getProperty("user.home") + "/azure-accesspolicyprovider.PROPERTIES";

    static {
        CONFIG = new Properties();
        try {
            final FileInputStream fis = new FileInputStream(CREDENTIALS_FILE);
            try {
                CONFIG.load(fis);
            } catch (IOException e) {
                fail("Could not open credentials file " + CREDENTIALS_FILE + ": " + e.getLocalizedMessage());
            } finally {
                FileUtils.closeQuietly(fis);
            }
        } catch (FileNotFoundException e) {
            fail("Could not open credentials file " + CREDENTIALS_FILE + ": " + e.getLocalizedMessage());
        }
    }
    protected NiFiProperties getNiFiProperties(final Properties properties) {
        final NiFiProperties nifiProperties = Mockito.mock(NiFiProperties.class);
        when(nifiProperties.getPropertyKeys()).thenReturn(properties.stringPropertyNames());

        when(nifiProperties.getProperty(anyString())).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return properties.getProperty((String)invocationOnMock.getArguments()[0]);
            }
        });

        when(nifiProperties.getProperty(anyString(), anyString())).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                String lookup = properties.getProperty((String)invocationOnMock.getArguments()[0]);
                if(lookup != null || lookup == "") {
                    return lookup;
                }else {
                    return (String)invocationOnMock.getArguments()[1];
                }
            }
        });

        when(nifiProperties.getKerberosServicePrincipal()).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return "instance/host@domain";
            }
        });        
        return nifiProperties;
    }
}
