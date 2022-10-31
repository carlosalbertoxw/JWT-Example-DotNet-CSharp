using JWT_Example_DotNet_CSharp;
using NUnit.Framework;

namespace NUnitTest
{
    public class JWTTest
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void CreateAndVerifyTokenTest()
        {
            string username = "carlosalbertoxw";
            string issuer = "carlosalbertoxw.com";
            string audience = "carlosalbertoxw.com/test";
            long SecondsToExpire = 60;
            string key = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            
            JWT jWT = new JWT();

            string token = jWT.CreateJWT(username, issuer, audience, key, SecondsToExpire);
            Console.WriteLine(token);
            Assert.That(jWT.VerifyJWT(token, issuer, audience, key), Is.EqualTo(username));
        }
    }
}
