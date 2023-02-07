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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key used to access JWT Cache Entry..
 */
public class JWTCacheKey extends CacheKey {

    private static final long serialVersionUID = 718492345264523421L;

    private final String jti;
    private final int tenantId;

    public JWTCacheKey(String jti, int tenantId) {

        this.jti = jti;
        this.tenantId = tenantId;
    }

    public JWTCacheKey(String jti) {

        this.jti = jti;
        this.tenantId = -1;
    }

    public String getJti() {

        return jti;
    }

    public int getTenantId() {

        return tenantId;
    }

    /**
     * Equals method to compare two JWT Cache Key.
     *
     * @param o java.lang.Object
     * @return True if both objects are same.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        JWTCacheKey that = (JWTCacheKey) o;

        if (!jti.equals(that.getJti())) {
            return false;
        }
        return tenantId == (that.getTenantId());
    }

    /**
     * This method used to derive hash value for this class.
     * Idea of this hash method is return same value for same object and return different value for different object.
     * Number 31 is used as common prime number to multiply result to get unique hash value.
     *
     * @return Hashcode.
     */
    @Override
    public int hashCode() {

        int result = super.hashCode();
        result = 31 * result + jti.hashCode();
        result = 31 * result + tenantId;
        return result;
    }
}
