/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.util;

import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.ErrorMessage;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceClientException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceServerException;

/**
 * Error utilities.
 */
public class ErrorUtils {

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return JWTClientAuthenticatorServiceServerException instance.
     */
    public static JWTClientAuthenticatorServiceServerException handleServerException(ErrorMessage error,
                                                                                     String... data) {

        return new JWTClientAuthenticatorServiceServerException
                (String.format(error.getDescription(), data), error.getCode());
    }

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return JWTClientAuthenticatorServiceServerException instance.
     */
    public static JWTClientAuthenticatorServiceServerException handleServerException(ErrorMessage error,
                                                                                     Throwable e,
                                                                                     String... data) {

        return new JWTClientAuthenticatorServiceServerException
                (String.format(error.getDescription(), data), error.getCode(),
                        e);
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return JWTClientAuthenticatorServiceClientException instance.
     */
    public static JWTClientAuthenticatorServiceClientException handleClientException(ErrorMessage error,
                                                                                     String... data) {

        return new JWTClientAuthenticatorServiceClientException(String.format(error.getDescription(), data),
                error.getCode());
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return JWTClientAuthenticatorServiceClientException instance.
     */
    public static JWTClientAuthenticatorServiceClientException handleClientException(ErrorMessage error,
                                                                                     Throwable e,
                                                                                     String... data) {

        return new JWTClientAuthenticatorServiceClientException(String.format(error.getDescription(), data),
                error.getCode(),
                e);
    }
}
