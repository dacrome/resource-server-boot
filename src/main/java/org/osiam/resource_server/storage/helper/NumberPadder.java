/*
 * Copyright (C) 2013 tarent AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.osiam.resource_server.storage.helper;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

@Service
public class NumberPadder {

    private static final String OFFSET = "100000000000000000000";
    private static final BigInteger BIG_OFFSET = new BigInteger(OFFSET);
    private static final int PAD_LENGTH = OFFSET.length();

    /**
     * Adds an offset and padding to a number
     *
     * @param value
     *            the number as {@link String}
     * @return the padded string with the added offset.
     */
    public String pad(String value) {
        String integralPart = value;
        String fractionalPart = "";

        if (value.contains(".")) {
            int indexOfDecimalSeparator = value.indexOf('.');
            integralPart = value.substring(0, indexOfDecimalSeparator);
            fractionalPart = value.substring(indexOfDecimalSeparator);
        }

        // The max allowed length of the integral part depends on the presence of a '-' as first character.
        // If it is present 21 characters are allowed, otherwise 20 (This is done by applying indexOf magic).
        if (integralPart.length() > (PAD_LENGTH + integralPart.indexOf('-'))) {
            throw new IllegalArgumentException("The given value has more than " + (PAD_LENGTH - 1) + " digits.");
        }

        integralPart = new BigInteger(integralPart).add(BIG_OFFSET).toString();
        integralPart = Strings.padStart(integralPart, PAD_LENGTH, '0');

        return integralPart + fractionalPart;
    }

    /**
     * Removes the offset and padding from a number
     *
     * @param value
     *            the padded number as {@link String}
     * @return the number decreased by offset and leading '0's removed
     */
    public String unpad(String value) {
        BigDecimal decimalValue = new BigDecimal(value);
        BigDecimal returnDecimalValue = new BigDecimal(decimalValue.toBigInteger().subtract(BIG_OFFSET));
        BigDecimal signum = new BigDecimal(returnDecimalValue.signum());
        BigDecimal fractionalPart = decimalValue.remainder(BigDecimal.ONE).multiply(signum);
        returnDecimalValue = returnDecimalValue.add(fractionalPart);
        return returnDecimalValue.toString();
    }
}
