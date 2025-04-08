using DotnetJWTAuth.Models.Dtos;

public interface ICookieService
{
    void SetAuthCookies(HttpResponse response, AuthResponse result);
}

public class CookieService : ICookieService
{
    public void SetAuthCookies(HttpResponse response, AuthResponse result)
    {
        var accessTokenOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = result.Expiration,
        };

        var refreshTokenOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(2),
        };

        response.Cookies.Append("accessToken", result.Token, accessTokenOptions);
        response.Cookies.Append("refreshToken", result.RefreshToken, refreshTokenOptions);
    }
}
