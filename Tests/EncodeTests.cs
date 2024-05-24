using System.Collections.Generic;
using NUnit.Framework;

namespace JWT.Tests
{
    [TestFixture]
    public class EncodeTests
    {
        private static readonly Customer Customer = new Customer(firstName: "Bob", age: 37);

        private const string TOKEN =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";

        private const string EXTRA_HEADERS_TOKEN =
            "eyJmb28iOiJiYXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.slrbXF9VSrlX7LKsV-Umb_zEzWLxQjCfUOjNTbvyr1g";

        [Test]
        public void Should_Encode_Type()
        {
            string result = JsonWebToken.Encode(Customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(TOKEN, result);
        }

        [Test]
        public void Should_Encode_Type_With_Extra_Headers()
        {
            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };

            string result = JsonWebToken.Encode(extraheaders, Customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(EXTRA_HEADERS_TOKEN, result);
        }

        [Test]
        public void Should_Encode_Type_With_Newtonsoft_Serializer()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();
            string result = JsonWebToken.Encode(Customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(TOKEN, result);
        }

        [Test]
        public void Should_Encode_Type_With_Newtonsoft_Serializer_And_Extra_Headers()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            var extraheaders = new Dictionary<string, object> { { "foo", "bar" } };
            string result = JsonWebToken.Encode(extraheaders, Customer, "ABC", JwtHashAlgorithm.HS256);

            Assert.AreEqual(EXTRA_HEADERS_TOKEN, result);
        }
    }
}
