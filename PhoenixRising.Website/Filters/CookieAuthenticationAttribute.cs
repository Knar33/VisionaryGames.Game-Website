using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Filters;
using System.Configuration;
using PhoenixRising.InternalAPI.Authentication;
using System.Web.Routing;
using System.Security.Claims;
using System.Linq;

namespace PhoenixRising.Website.Filters
{
    public class CookieAuthenticationAttribute : ActionFilterAttribute, IAuthenticationFilter
    {
        public void OnAuthentication(AuthenticationContext filterContext)
        {
            var user = filterContext.HttpContext.User as ClaimsPrincipal;
            var identity = new ClaimsIdentity(user.Identity);

            if (user != null && user.Identity.IsAuthenticated)
            {
                DateTime expiresTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(user.Claims.FirstOrDefault(x => x.Type == "ExpiresTime").Value)).LocalDateTime;

                if (expiresTime < DateTime.Now)
                {
                    string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                    string refreshToken = user.Claims.FirstOrDefault(x => x.Type == "RefreshToken").Value;
                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        identity.RemoveClaim(identity.FindFirst("AccessToken"));
                        identity.RemoveClaim(identity.FindFirst("ExpiresTime"));
                        identity.RemoveClaim(identity.FindFirst(ClaimTypes.Name));
                        identity.AddClaim(new Claim("AccessToken", refreshResponse.access_token));
                        identity.AddClaim(new Claim("ExpiresTime", refreshResponse.expireTime));
                        identity.AddClaim(new Claim(ClaimTypes.Name, refreshResponse.user_nick));
                    }
                }
            }
            else
            {
                filterContext.Result = new RedirectToRouteResult(new RouteValueDictionary{{ "controller", "Account" }, { "action", "Login" }});
            }
        }

        public void OnAuthenticationChallenge(AuthenticationChallengeContext filterContext)
        {

        }
    }
}