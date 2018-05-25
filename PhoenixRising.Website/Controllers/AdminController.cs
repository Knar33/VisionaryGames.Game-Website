using System;
using System.Web;
using System.Web.Mvc;
using System.Configuration;
using PhoenixRising.Website.Models;
using PhoenixRising.InternalAPI.Website;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using PhoenixRising.InternalAPI.Authentication;
using PhoenixRising.InternalAPI.Account.Account;
using PhoenixRising.InternalAPI.Administration.AccountAdmin;
using PhoenixRising.Website.Filters;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin.Security;

namespace PhoenixRising.Website.Controllers
{
    public class AdminController : Controller
    {
        [AuthorizeUser(Roles = "Administrator")]
        public ActionResult Index()
        {
            return View();
        }

        [AuthorizeUser(Roles = "Administrator")]
        public ActionResult UpdatePermissions()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AuthorizeUser(Roles = "Administrator")]
        public ActionResult UpdatePermissions(UpdatePermissions model)
        {
            if (ModelState.IsValid)
            {
                //Create user request
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                var ctx = Request.GetOwinContext();
                ClaimsPrincipal user = ctx.Authentication.User;
                string accessToken = user.Claims.FirstOrDefault(x => x.Type == "AccessToken").Value;

                FindRequest findRequest = new FindRequest(connection, model.UserName);
                FindResponse findResponse = findRequest.Send();

                if (findResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    UpdateUserPermissionsRequest updateUserRequest = new UpdateUserPermissionsRequest(connection, accessToken, new Guid(findResponse.USER_ID));
                    updateUserRequest.Administrator = model.Administrator ? 1 : 0;
                    updateUserRequest.Developer = model.Developer ? 1 : 0;
                    updateUserRequest.Banned = model.Banned ? 1 : 0;
                    updateUserRequest.Banned = model.CommunityManager ? 1 : 0;
                    UpdateUserPermissionsResponse updateUserResponse = updateUserRequest.Send();

                    if (updateUserResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        TempData["Success"] = "You have successfully updated the user's permissions!";
                        return View(model);
                    }
                    else
                    {
                        TempData["Errors"] = "There was an error updating the user's permissions.";
                        return View(model);
                    }
                }
                else
                {
                    TempData["Errors"] = "There was an error finding that user.";
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }
    }
}