// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Globalization;
using Xunit;

namespace System.Globalization.Tests
{
    public class NumberFormatInfoCurrencyDecimalDigits
    {
        // PosTest1: Verify property CurrencyDecimalDigits default value
        [Fact]
        public void PosTest1()
        {
            NumberFormatInfo nfi = new NumberFormatInfo();
            Assert.Equal(2, nfi.CurrencyDecimalDigits);
        }

        // PosTest2: Verify set value of property CurrencyDecimalDigits
        [Fact]
        public void PosTest2()
        {
            NumberFormatInfo nfi = new NumberFormatInfo();

            for (int i = 0; i < 100; i++)
            {
                nfi.CurrencyDecimalDigits = i;
                Assert.Equal(i, nfi.CurrencyDecimalDigits);
            }
        }

        // TestArgumentOutOfRange: ArgumentOutOfRangeException is thrown
        [Fact]
        public void TestArgumentOutOfRange()
        {
            VerificationHelper<ArgumentOutOfRangeException>(-1);
            VerificationHelper<ArgumentOutOfRangeException>(100);
        }

        // TestInvalidOperation: InvalidOperationException is thrown
        [Fact]
        public void TestInvalidOperation()
        {
            NumberFormatInfo nfi = new NumberFormatInfo();
            NumberFormatInfo nfiReadOnly = NumberFormatInfo.ReadOnly(nfi);
            Assert.Throws<InvalidOperationException>(() =>
            {
                nfiReadOnly.CurrencyDecimalDigits = 1;
            });
        }

        // TestLocale1: Verify value of property CurrencyDecimalDigits for specific locale
        [Fact]
        public void TestLocale1()
        {
            CultureInfo myTestCulture = new CultureInfo("en-US");
            NumberFormatInfo nfi = myTestCulture.NumberFormat;
            int expected = nfi.CurrencyDecimalDigits;
            // todo: determine why some values are different
            Assert.True(expected == 3 || expected == 2); //ICU=3, 2=Windows
        }

        // TestLocale2: Verify value of property CurrencyDecimalDigits for specific locale
        [Fact]
        public void TestLocale2()
        {
            CultureInfo myTestCulture = new CultureInfo("ko");
            NumberFormatInfo nfi = myTestCulture.NumberFormat;
            int expected = nfi.CurrencyDecimalDigits;
            // todo: determine why some values are different
            Assert.True(expected == 2 || expected == 0); //ICU=2, 0=Windows
        }

        private void VerificationHelper<T>(int i) where T : Exception
        {
            NumberFormatInfo nfi = new NumberFormatInfo();
            Assert.Throws<T>(() =>
            {
                nfi.CurrencyDecimalDigits = i;
                int actual = nfi.CurrencyDecimalDigits;
            });
        }
    }
}
