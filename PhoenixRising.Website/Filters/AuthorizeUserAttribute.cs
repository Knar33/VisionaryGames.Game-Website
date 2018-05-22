using System;
using System.Collections.Generic;
using System.Web.Mvc;
using PhoenixRising.InternalAPI.Account.Account;
using System.Configuration;
using PhoenixRising.Website;
using System.Security.Claims;
using System.Web.Routing;

namespace PhoenixRising.Website.Filters
{
    public class AuthorizeUserAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            var user = filterContext.HttpContext.User as ClaimsPrincipal;
            if (user != null && user.HasClaim(ClaimTypes.Role, Roles))
            {
                base.OnAuthorization(filterContext);
            }
            else
            {
                filterContext.Result = new RedirectToRouteResult(new RouteValueDictionary{{ "controller", "Account" },{ "action", "Index" }});
            }
        }
    }
}