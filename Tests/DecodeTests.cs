using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace JWT.Tests
{
    [TestFixture]
    public class DecodeTests
    {
        private static readonly Customer Customer = new(firstName: "Bob", age:  37 );

        private const string TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";
        private const string MALFORMED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9eyJGaXJzdE5hbWUiOiJCb2IiLCJBZ2UiOjM3fQ.cr0xw8c_HKzhFBMQrseSPGoJ0NPlRp_3BKzP96jwBdY";

        private static readonly IDictionary<string, object> DictionaryPayload = new Dictionary<string, object>
        {
            { "FirstName", "Bob" },
            { "Age", 37 }
        };

        [Test]
        public void Should_Decode_Token_To_Json_Encoded_String()
        {
            var jsonSerializer = new NewtonJsonSerializer();
            var expectedPayload = jsonSerializer.Serialize(Customer);

            string decodedPayload = JsonWebToken.Decode(TOKEN, "ABC", false);

            Assert.AreEqual(expectedPayload, decodedPayload);
        }

        [Test]
        public void Should_Decode_Token_To_Dictionary()
        {
            object decodedPayload = JsonWebToken.DecodeToObject(TOKEN, "ABC", false);

            Assert.AreEqual(DictionaryPayload, decodedPayload);
        }

        [Test]
        public void Should_Decode_Token_To_Dictionary_With_Newtonsoft()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            object decodedPayload = JsonWebToken.DecodeToObject(TOKEN, "ABC", false);

            Assert.AreEqual(DictionaryPayload, decodedPayload);
        }

        [Test]
        public void Should_Decode_Token_To_Generic_Type()
        {
            Customer decodedPayload = JsonWebToken.DecodeToObject<Customer>(TOKEN, "ABC", false);

            Assert.AreEqual(Customer, decodedPayload);
        }

        [Test]
        public void Should_Decode_Token_To_Generic_Type_With_Newtonsoft()
        {
            JsonWebToken.JsonSerializer = new NewtonJsonSerializer();

            Customer decodedPayload = JsonWebToken.DecodeToObject<Customer>(TOKEN, "ABC", false);

            Assert.AreEqual(Customer, decodedPayload);
        }

        [Test]
        public void Should_Throw_On_Malformed_Token()
        {
            Assert.Throws<ArgumentException>(() => JsonWebToken.DecodeToObject<Customer>(MALFORMED_TOKEN, "ABC", false));
        }

        [Test]
        public void Should_Throw_On_Invalid_Key()
        {
            string invalidkey = "XYZ";

            Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject<Customer>(TOKEN, invalidkey, true));
        }

        [Test]
        public void Should_Throw_On_Invalid_Expiration_Claim()
        {
            var invalidexptoken = JsonWebToken.Encode(new { exp = "asdsad" }, "ABC", JwtHashAlgorithm.HS256);

            Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true));
        }

        [Test]
        public void Should_Throw_On_Expired_Token()
        {
            var anHourAgoUtc = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0));
            Int32 unixTimestamp = (Int32)(anHourAgoUtc.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            var invalidexptoken = JsonWebToken.Encode(new { exp = unixTimestamp }, "ABC", JwtHashAlgorithm.HS256);

            Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject<Customer>(invalidexptoken, "ABC", true));
        }
    }

    public class Customer
    {
        public string FirstName { get; }

        public int Age { get; }
        
        public Customer(string firstName, int age)
        {
            FirstName = firstName;
            Age = age;
        }

        public override bool Equals(object obj)
        {
            return obj is Customer customer &&
                   FirstName == customer.FirstName &&
                   Age == customer.Age;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(FirstName, Age);
        }
    }
}
