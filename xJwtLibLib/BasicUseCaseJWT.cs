using JwtLibLib;
using System;
using System.Security.Claims;
using Xunit.Abstractions;

namespace xJwtLibLib
{
    public class BasicUseCaseJWT
    {
        private ITestOutputHelper console;
        public BasicUseCaseJWT(ITestOutputHelper csle) => console = csle;


        [Fact(DisplayName ="JWT factory random key")]
        public void JWT_factory_random_key()
        {
            // Make all possible constructor
            JwtFactory jwtRandomKey_1 = new JwtFactory();
            JwtFactory jwtRandomKey_2 = new JwtFactory();
            JwtFactory jwProvidedKey = new JwtFactory(Path.GetRandomFileName());

            // Create two JWT using two different validator
            string tokenfrom_1 = jwtRandomKey_1.GenerateJSONWebTokens(new[] { new Claim("id", "My super value") , new Claim("id_user", "TEST") });
            string tokenfrom_2 = jwtRandomKey_2.GenerateJSONWebTokens(new Dictionary<string, string>() {
                    ["id"] = "My super value" ,
                    ["user_id"] = Guid.NewGuid().ToString()
                });

            // Validation of first JWT
            var res = jwtRandomKey_1.ValidateToken(tokenfrom_1);

            // Get claims from validated JWT
            var firstClaimsDataFrom_1 = res.First(x => x.Type == "id").Value;
            var secondClaimsDataFrom_1 = res.First(x => x.Type == "id_user").Value;

            // Debug
            foreach( var claim in res!) console.WriteLine(claim.ToString());

            // Verify Claims value
            Assert.Equal("My super value", firstClaimsDataFrom_1);
            Assert.Equal("TEST", secondClaimsDataFrom_1);

            // Verify cannot validate token using wrong factory
            res = jwtRandomKey_1.ValidateToken(tokenfrom_2);
            Assert.Null(res);

            // Verify cannot validate token using wrong factory
            res = jwProvidedKey.ValidateToken(tokenfrom_2);
            Assert.Null(res);
        }

        [Fact(DisplayName = "JWT factory expiry")]
        public async void JWT_factory_expiry()
        {
            // Random key
            JwtFactory jwtFactory = new JwtFactory();

            // Two different expiry JWT
            string tokenExpiryInMilisecond = jwtFactory.GenerateJSONWebTokens(new Dictionary<string, string>(){ ["id"]= "My super value"}, milisecondeBeforeExpiration: 1000);
            string tokenExpiryInDays = jwtFactory.GenerateJSONWebTokens(new[] { new Claim("id", "My super value") }, daysBeforeExpiration: 1);

            // JWT Milisecond life expiry can be readed
            var res = jwtFactory.ValidateToken(tokenExpiryInMilisecond);
            var idFromToken = res.First(x => x.Type == "id").Value;
            Assert.Equal("My super value", idFromToken);

            // JWT Day life expiry can be readed
            res = jwtFactory.ValidateToken(tokenExpiryInDays);
            idFromToken = res.First(x => x.Type == "id").Value;
            Assert.Equal("My super value", idFromToken);

            // Make JWT Milisecond life expired
            await Task.Delay(1000);

            // Verify expired JWT Milisecond life
            res = jwtFactory.ValidateToken(tokenExpiryInMilisecond);
            Assert.Null(res);

            // Verify still correct JWT Day life
            res = jwtFactory.ValidateToken(tokenExpiryInDays);
            idFromToken = res.First(x => x.Type == "id").Value;
            Assert.Equal("My super value", idFromToken);
        }
    }
}