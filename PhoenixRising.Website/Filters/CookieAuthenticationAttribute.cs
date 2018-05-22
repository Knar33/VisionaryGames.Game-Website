using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Filters;
using System.Configuration;
using PhoenixRising.InternalAPI.Authentication;
using System.Web.Routing;
using System.Security.Claims;
using System.Linq;
using Microsoft.Owin.Security;
using PhoenixRising.InternalAPI.Account.Account;

namespace PhoenixRising.Website.Filters
{
    public class CookieAuthenticationAttribute : ActionFilterAttribute, IAuthenticationFilter
    {
        public void OnAuthentication(AuthenticationContext filterContext)
        {
            //Get current user
            ClaimsPrincipal user = filterContext.HttpContext.User as ClaimsPrincipal;
            ClaimsIdentity identity = new ClaimsIdentity(user.Identity);

            if (user != null && identity.IsAuthenticated)
            {
                DateTime expiresTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(identity.FindFirst(ClaimTypes.Expiration).Value)).LocalDateTime;

                if (expiresTime < DateTime.Now)
                {
                    string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                    string refreshToken = identity.FindFirst("RefreshToken").Value;

                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    GetUserDetailsRequest userDetailRequest = new GetUserDetailsRequest(connection, refreshResponse.access_token, new Guid(refreshResponse.user_id));
                    GetUserDetailsResponse userDetailResponse = userDetailRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK && userDetailResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        //Update the user's claims
                        identity.RemoveClaim(identity.FindFirst("AccessToken"));
                        identity.RemoveClaim(identity.FindFirst(ClaimTypes.Expiration));
                        identity.RemoveClaim(identity.FindFirst(ClaimTypes.Name));
                        identity.RemoveClaim(identity.FindFirst(ClaimTypes.NameIdentifier));
                        identity.AddClaim(new Claim("AccessToken", refreshResponse.access_token));
                        identity.AddClaim(new Claim(ClaimTypes.Expiration, refreshResponse.expireTime));
                        identity.AddClaim(new Claim(ClaimTypes.Name, refreshResponse.user_nick));
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, refreshResponse.user_id));

                        var roleClaims = identity.FindAll(ClaimTypes.Role);
                        foreach (Claim role in roleClaims)
                        {
                            identity.RemoveClaim(role);
                        }

                        if (userDetailResponse.PERMISSIONS.Administrator)
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Role, "Administrator"));
                        }
                        if (userDetailResponse.PERMISSIONS.Developer)
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Role, "Developer"));
                        }
                        
                        var authenticationManager = filterContext.HttpContext.GetOwinContext().Authentication;
                        authenticationManager.SignOut();

                        AuthenticationProperties properties = new AuthenticationProperties { IsPersistent = Convert.ToBoolean(identity.FindFirst(ClaimTypes.IsPersistent).Value) };
                        authenticationManager.SignIn(properties, identity);

                        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
                        filterContext.HttpContext.User = claimsPrincipal;
                    }
                    else
                    {
                        var authenticationManager = filterContext.HttpContext.GetOwinContext().Authentication;
                        authenticationManager.SignOut();
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