using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtLibLib;

/// <summary>
/// Utils for JWT; based on this <see href="https://jasonwatmore.com/post/2021/06/02/net-5-create-and-validate-jwt-tokens-use-custom-jwt-middleware">ressources</see>
/// Can be added as middleware; based on this <see href="https://stackoverflow.com/questions/61214267/custom-middleware-or-authorize-for-specific-route-in-asp-net-core-3-1-mvc">ressources</see>
/// </summary>
public class JwtFactory
{
    private Byte[] byteKey;
    private JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
    private const uint DEFAULT_EXPIRY_HOURS = 12;

    public JwtFactory() : this($"{Guid.NewGuid().ToString()}${new Random().Next(10_000, 99_999)}{Guid.NewGuid().ToString()}") { }
    public JwtFactory(string key) => byteKey = Encoding.UTF8.GetBytes(key);

    /// <summary>
    /// Allow to get a token, by default it expire within the next 12 hour. If any argument like ___BeforeExpiration is set, it become the expiry value.
    /// </summary>
    /// <param name="claims"></param>
    /// <param name="daysBeforeExpiration"></param>
    /// <param name="hoursBeforeExpiration"></param>
    /// <param name="minutesBeforeExpiration"></param>
    /// <param name="secondeBeforeExpiration"></param>
    /// <param name="milisecondeBeforeExpiration"></param>
    /// <returns>The token with encrypted data. By default, field nbf,exp and iat are present.
    /// <list type="bullet">
    ///     <item>
    ///         <description>nbf stand for Not BeFore</description>
    ///     </item>
    ///     <item>
    ///         <description>exp stand for Expire in</description>
    ///     </item>
    ///     <item>
    ///         <description> iat stand for Issue AT</description>
    ///     </item>
    /// </list>
    /// </returns>
    public string GenerateJSONWebTokens(Dictionary<string, string> claims, ushort daysBeforeExpiration = 0, double hoursBeforeExpiration = 0, double minutesBeforeExpiration = 0, double secondeBeforeExpiration = 0, double milisecondeBeforeExpiration = 0)
    {
        var mapDictToClaims = claims.Select(a => new Claim(a.Key, a.Value)).ToArray();
        return GenerateJSONWebTokens(mapDictToClaims,daysBeforeExpiration,hoursBeforeExpiration,minutesBeforeExpiration,secondeBeforeExpiration,milisecondeBeforeExpiration);
    }

    ///<inheritdoc cref = "JwtLibLib.JwtFactory.GenerateJSONWebTokens"/>
    public string GenerateJSONWebTokens(Claim[] claims, ushort daysBeforeExpiration = 0, double hoursBeforeExpiration = 0, double minutesBeforeExpiration = 0, double secondeBeforeExpiration = 0, double milisecondeBeforeExpiration = 0)
    {
        if (daysBeforeExpiration is 0 && hoursBeforeExpiration is 0 && minutesBeforeExpiration is 0 && secondeBeforeExpiration is 0 && milisecondeBeforeExpiration is 0) hoursBeforeExpiration = DEFAULT_EXPIRY_HOURS;
        // Expire in or exp in jwt
        DateTime exp = DateTime.UtcNow.AddDays(daysBeforeExpiration)
                                      .AddHours(hoursBeforeExpiration)
                                      .AddMinutes(minutesBeforeExpiration)
                                      .AddSeconds(secondeBeforeExpiration)
                                      .AddMilliseconds(milisecondeBeforeExpiration);

        // Issue at (or iat in jwt)
        DateTime iat = DateTime.UtcNow;

        // Not valide Before (or nbf in jwt)
        DateTime nbf = DateTime.UtcNow;

        var token = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            //IssuedAt = iat,
            Expires = exp,
            NotBefore = nbf,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(byteKey), SecurityAlgorithms.HmacSha512Signature),
        });
        return handler.WriteToken(token);
    }

    /// <summary>
    ///   Take a token and return corresponding Claim if valide.
    /// </summary>
    /// <remarks>
    ///   Claim data can be acces uisng <c>jwt.ValidateToken(token).First(x => x.Type == "id").Value</c>
    /// </remarks>
    /// <param name="token"></param>
    /// <returns>If null, token is not valide</returns>
    public IEnumerable<Claim>? ValidateToken(string token, bool enableSecurityTokenArgumentException = false)
    {
        if (String.IsNullOrEmpty(token)) return null;
        try
        {
            ClaimsPrincipal result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(byteKey),
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var now = DateTime.UtcNow;
            bool isValid = validatedToken.ValidTo > now && validatedToken.ValidFrom < now;

            if (isValid) return result.Claims;
            else return null;
        }
        catch (SecurityTokenException)
        {
            if (enableSecurityTokenArgumentException) throw;
            return null;
        }
    }





}
