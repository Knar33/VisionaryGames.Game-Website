using System;
using System.Web;
using System.Web.Mvc;
using System.Configuration;
using PhoenixRising.Website.Models;
using PhoenixRising.InternalAPI.App.DownloadURL;
using PhoenixRising.Website.Filters;
using Microsoft.Owin.Security;

namespace PhoenixRising.Website.Controllers
{
    public class DownloadController : Controller
    {
        //Game download
        [CookieAuthentication]
        [AuthorizeUser(Roles = "Developer")]
        public ActionResult GameClient(PasswordReset model)
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

            DownloadClientRequest downloadGameRequest = new DownloadClientRequest(connection, appAccessToken);
            DownloadClientResponse downloadGameResponse = downloadGameRequest.Send();

            if (downloadGameResponse.StatusCode == System.Net.HttpStatusCode.OK)
            {
                return Redirect(downloadGameResponse.Content);
            }
            else
            {
                TempData["Errors"] = "There was an error processing your request";
                return RedirectToAction("Index", "Account");
            }
        }

        //Game download
        [CookieAuthentication]
        [AuthorizeUser(Roles = "Administrator")]
        public ActionResult GameServer(PasswordReset model)
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

            DownloadServerRequest downloadServerRequest = new DownloadServerRequest(connection, appAccessToken);
            DownloadServerResponse downloadServerResponse = downloadServerRequest.Send();

            if (downloadServerResponse.StatusCode == System.Net.HttpStatusCode.OK)
            {
                return Redirect(downloadServerResponse.Content);
            }
            else
            {
                TempData["Errors"] = "There was an error processing your request";
                return RedirectToAction("Index", "Account");
            }
        }
    }
}