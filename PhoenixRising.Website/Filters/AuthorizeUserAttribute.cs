using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using PhoenixRising.InternalAPI.Account.Account;
using System.Configuration;

namespace PhoenixRising.Website.Filters
{
    public class AuthorizeUserAttribute : AuthorizeAttribute
    {
        public string AccessLevel { get; set; }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            var request = filterContext.HttpContext.Request;
            var url = new UrlHelper(filterContext.RequestContext);
            var accessDeniedUrl = url.Action("Index", "Home");

            string accessToken = filterContext.HttpContext.Request.Cookies.Get("AccessToken").Value;
            Guid userID = new Guid(filterContext.HttpContext.Request.Cookies.Get("UserID").Value);
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];

            GetUserDetailsRequest userDetailRequest = new GetUserDetailsRequest(connection, accessToken, userID);
            GetUserDetailsResponse userDetailResponse = userDetailRequest.Send();

            List<string> privilegeLevels = new List<string>();
            if (userDetailResponse.PERMISSIONS.Administrator)
            {
                privilegeLevels.Add("Administrator");
            }
            if (userDetailResponse.PERMISSIONS.Banned)
            {
                privilegeLevels.Add("Banned");
            }
            if (userDetailResponse.PERMISSIONS.Developer)
            {
                privilegeLevels.Add("Developer");
            }

            if (!privilegeLevels.Contains(AccessLevel))
            {
                filterContext.Result = new RedirectResult(accessDeniedUrl);
            }
        }
    }
}