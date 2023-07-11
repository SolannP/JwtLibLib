using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;

namespace JwtLibLib
{
    public class CustomJwtMiddleware : IMiddleware
    {
        private readonly JwtFactory jwt;
        private readonly ILogger _logger;

        public CustomJwtMiddleware(IConfigurationSection config, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<CustomJwtMiddleware>();
            var jwtConfSection = config.GetSection("JwtLibLib");
            if (jwtConfSection.Exists() is false || string.IsNullOrWhiteSpace(jwtConfSection.Value))
            {
                jwt = new();
                _logger.LogInformation("JWT key generated randomly");
            }
            else
            {
                jwt = new(jwtConfSection.Value);
                _logger.LogInformation("JWT key have been set using data in section JwtLibLib from configuration file");
            }
        }
        public Task InvokeAsync(HttpContext context, RequestDelegate next)
        {

            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var claims = jwt.ValidateToken(token);
            if (claims is null) return Task.Delay(0);
            return next.Invoke(context);
        }
    }

    public class NotValideJWT : Exception
    {
        
    }
}
