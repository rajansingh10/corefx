// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq.Expressions;
using Xunit;

namespace System.Linq.Tests.LegacyTests
{
    public class LastOrDefaultTests : EnumerableBasedTests
    {
        [Fact]
        public void Empty()
        {
            Assert.Null(Enumerable.Empty<int?>().AsQueryable().LastOrDefault());
        }

        [Fact]
        public void OneElement()
        {
            int[] source = { 5 };
            Assert.Equal(5, source.AsQueryable().LastOrDefault());
        }

        [Fact]
        public void ManyElementsLastIsDefault()
        {
            int?[] source = { -10, 2, 4, 3, 0, 2, null };
            Assert.Null(source.AsQueryable().LastOrDefault());
        }

        [Fact]
        public void ManyElementsLastIsNotDefault()
        {
            int?[] source = { -10, 2, 4, 3, 0, 2, null, 19 };
            Assert.Equal(19, source.AsQueryable().LastOrDefault());
        }

        [Fact]
        public void ManyElementsPredicateFalseForAll()
        {
            int[] source = { 9, 5, 1, 3, 17, 21 };
            Assert.Equal(0, source.AsQueryable().LastOrDefault(i => i % 2 == 0));
        }

        [Fact]
        public void PredicateTrueForSome()
        {
            int[] source = { 3, 7, 10, 7, 9, 2, 11, 18, 13, 9 };
            Assert.Equal(18, source.AsQueryable().LastOrDefault(i => i % 2 == 0));
        }

        [Fact]
        public void NullSource()
        {
            Assert.Throws<ArgumentNullException>("source", () => ((IQueryable<int>)null).LastOrDefault());
        }

        [Fact]
        public void NullSourcePredicateUsed()
        {
            Assert.Throws<ArgumentNullException>("source", () => ((IQueryable<int>)null).LastOrDefault(i => i != 2));
        }

        [Fact]
        public void NullPredicate()
        {
            Expression<Func<int, bool>> predicate = null;
            Assert.Throws<ArgumentNullException>("predicate", () => Enumerable.Range(0, 3).AsQueryable().LastOrDefault(predicate));
        }

        [Fact]
        public void LastOrDefault1()
        {
            var val = (new int[] { 0, 1, 2 }).AsQueryable().LastOrDefault();
            Assert.Equal(2, val);
        }

        [Fact]
        public void LastOrDefault2()
        {
            var val = (new int[] { 0, 1, 2 }).AsQueryable().LastOrDefault(n => n > 1);
            Assert.Equal(2, val);
        }
    }
}
