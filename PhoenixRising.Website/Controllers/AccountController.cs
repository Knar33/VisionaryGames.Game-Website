using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Configuration;
using PhoenixRising.Website.Models;
using PhoenixRising.InternalAPI.Website;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using PhoenixRising.InternalAPI.Authentication;
using PhoenixRising.InternalAPI;

namespace PhoenixRising.Website.Controllers
{
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
            HttpCookie username = Request.Cookies.Get("Username");
            if (username != null)
            {
                ViewBag.Username = username.Value;

                return View();
            }
            else
            {
                return RedirectToAction("Login", "Account");
            }
        }
        
        // GET: Account
        public ActionResult PasswordReset()
        {
            return View();
        }

        // POST: Account
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult PasswordReset(PasswordReset model)
        {
            return View();
        }

        // GET: Account
        public ActionResult Register()
        {
            return View();
        }

        // POST: Account
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(Register model)
        {
            if (ModelState.IsValid)
            {
                //Create user request
                APIConnection connection = new APIConnection(ConfigurationManager.AppSettings["InternalAPIURL"]);
                KeyVaultClient KeyVault;
                try
                {
                    var azureServiceTokenProvider = new AzureServiceTokenProvider();
                    var _token = azureServiceTokenProvider.GetAccessTokenAsync("https://vault.azure.net").Result;
                    KeyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                }
                catch (Exception e)
                {
                    throw e;
                }
                var bundle = KeyVault.GetSecretAsync(ConfigurationManager.AppSettings["AzureVaultURL"]).Result;
                
                CreateUserRequest request = new CreateUserRequest(connection);
                request.Email = model.Email;
                request.FirstName = model.FirstName;
                request.LastName = model.LastName;
                request.Nicknane = model.Nicknane;
                request.Password = model.password1;
                request.AppAccessToken = bundle.Value;

                CreateUserResponse response = request.Send();
                
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    //make login request
                    LoginRequest loginRequest = new LoginRequest(connection, model.Email, model.password1);
                    LoginResponse loginResponse = loginRequest.Send();

                    if (loginResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        //Create login cookies
                        Response.Cookies.Add(new HttpCookie("AccessToken")
                        {
                            Value = loginResponse.access_token,
                            HttpOnly = true
                        });
                        Response.Cookies.Add(new HttpCookie("UserID")
                        {
                            Value = loginResponse.user_id,
                            HttpOnly = true
                        });
                        Response.Cookies.Add(new HttpCookie("AccessTokenExpiration")
                        {
                            Value = loginResponse.expireTime,
                            HttpOnly = true
                        });
                        Response.Cookies.Add(new HttpCookie("RefreshToken")
                        {
                            Value = loginResponse.refresh_token,
                            HttpOnly = true
                        });

                        //redirect to register success, login success
                        TempData["Success"] = "You have successfully registered an account, and have automatically been signed in.";
                        return RedirectToAction("Index", "Account");
                    }
                    else
                    {
                        TempData["Success"] = "You have successfully registered an account. You can now sign in below.";
                        return RedirectToAction("Login", "Account");
                    }
                }
                else
                {
                    //add tempdata errors
                    if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
                    {
                        TempData["Errors"] = "Bad request";
                    }
                    else
                    {
                        TempData["Errors"] = "There was an error processing your request. Please try again.";
                    }

                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }

        // GET: Account
        public ActionResult Login()
        {
            return View();
        }

        // POST: Account
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login model)
        {
            return View();
        }
    }
}