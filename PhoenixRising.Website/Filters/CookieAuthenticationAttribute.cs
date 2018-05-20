using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Filters;
using System.Configuration;
using PhoenixRising.InternalAPI.Authentication;
using System.Web.Routing;

namespace PhoenixRising.Website.Filters
{
    public class CookieAuthenticationAttribute : ActionFilterAttribute, IAuthenticationFilter
    {
        public void OnAuthentication(AuthenticationContext filterContext)
        {
            bool authenticated = false;
            string accessToken = "";
            string refreshToken = "";
            Guid userID = new Guid();
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            
            HttpCookie accessTokenCookie = filterContext.HttpContext.Request.Cookies.Get("AccessToken");
            if (accessTokenCookie != null)
            {
                accessToken = accessTokenCookie.Value;
                userID = new Guid(filterContext.HttpContext.Request.Cookies.Get("UserID").Value);
                authenticated = true;
            }
            else
            {
                HttpCookie refreshTokenCookie = filterContext.HttpContext.Request.Cookies.Get("RefreshToken");

                if (refreshTokenCookie != null)
                {
                    refreshToken = refreshTokenCookie.Value;
                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        filterContext.HttpContext.Response.Cookies.Add(new HttpCookie("AccessToken")
                        {
                            Value = refreshResponse.access_token,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        filterContext.HttpContext.Response.Cookies.Add(new HttpCookie("UserName")
                        {
                            Value = refreshResponse.user_nick,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        filterContext.HttpContext.Response.Cookies.Add(new HttpCookie("UserID")
                        {
                            Value = refreshResponse.user_id,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        accessToken = refreshResponse.access_token;
                        userID = new Guid(refreshResponse.user_id);
                        authenticated = true;
                    }
                }
            }

            if (!authenticated)
            {
                filterContext.Result = new RedirectToRouteResult(new RouteValueDictionary{
                    { "controller", "Account" },
                    { "action", "Login" }
                });
            }
        }

        public void OnAuthenticationChallenge(AuthenticationChallengeContext filterContext)
        {

        }
    }
}