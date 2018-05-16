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
        public ActionResult Index()
        {
            //TODO: Make a filter for this auth shiz
            HttpCookie accessToken = Request.Cookies.Get("AccessToken");
            if (accessToken != null)
            {
                HttpCookie username = Request.Cookies.Get("UserName");
                ViewBag.userName = username.Value;
                return View();
            }
            else
            {
                HttpCookie refreshToken = Request.Cookies.Get("RefreshToken");
                if (refreshToken != null)
                {
                    AuthenticationStore auth = new AuthenticationStore()
                    {
                        RefreshToken = refreshToken.Value
                    };
                    APIConnection connection = new APIConnection(ConfigurationManager.AppSettings["InternalAPIURL"]);
                    RefreshRequest refreshRequest = new RefreshRequest(auth, connection);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        return View();
                    }
                }
                return RedirectToAction("Login", "Account");
            }
        }
        
        public ActionResult PasswordReset()
        {
            return View();
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult PasswordReset(PasswordReset model)
        {
            if (ModelState.IsValid)
            {
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
                RequestResetPasswordRequest resetRequest = new RequestResetPasswordRequest(connection, model.Email);
                resetRequest.AppAccessToken = bundle.Value;
                RequestResetPasswordResponse resetResponse = resetRequest.Send();

                //always act like success - don't want people fishing for email addresses
                TempData["Success"] = "An email was sent to the email address provided. Please follow the instructions to reset your password.";
                return RedirectToAction("Login", "Account");
            }
            else
            {
                return View(model);
            }
        }
        
        public ActionResult Password(string token)
        {
            Password model = new Password();
            model.token = token;
            return View(model);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Password(Password model)
        {
            if (ModelState.IsValid)
            {
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
                ResetPasswordRequest resetRequest = new ResetPasswordRequest(connection, model.token, model.password);
                resetRequest.AppAccessToken = bundle.Value;
                ResetPasswordResponse resetResponse = resetRequest.Send();

                if (resetResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    TempData["Success"] = "Your password was changed!";
                    return RedirectToAction("Login", "Account");
                }
                else
                {
                    TempData["Errors"] = "There was an error processing your request";
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }
        
        public ActionResult Register()
        {
            //if logged in, go to account page
            HttpCookie accessToken = Request.Cookies.Get("AccessToken");
            if (accessToken != null)
            {
                return RedirectToAction("Index", "Account");
            }
            else
            {
                HttpCookie refreshToken = Request.Cookies.Get("RefreshToken");
                if (refreshToken != null)
                {
                    AuthenticationStore auth = new AuthenticationStore()
                    {
                        RefreshToken = refreshToken.Value
                    };
                    APIConnection connection = new APIConnection(ConfigurationManager.AppSettings["InternalAPIURL"]);
                    RefreshRequest refreshRequest = new RefreshRequest(auth, connection);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        return RedirectToAction("Index", "Account");
                    }
                }
                return View();
            }
        }
        
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
                    TempData["Success"] = "You have successfully registered an account. You can now sign in below.";
                    return RedirectToAction("Login", "Account");
                }
                else
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
                    {
                        //TODO: Parse the actual response error
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
        
        public ActionResult Login()
        {
            //if logged in, go to account page
            HttpCookie accessToken = Request.Cookies.Get("AccessToken");
            if (accessToken != null)
            {
                return RedirectToAction("Index", "Account");
            }
            else
            {
                HttpCookie refreshToken = Request.Cookies.Get("RefreshToken");
                if (refreshToken != null)
                {
                    AuthenticationStore auth = new AuthenticationStore()
                    {
                        RefreshToken = refreshToken.Value
                    };
                    APIConnection connection = new APIConnection(ConfigurationManager.AppSettings["InternalAPIURL"]);
                    RefreshRequest refreshRequest = new RefreshRequest(auth, connection);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        return RedirectToAction("Index", "Account");
                    }
                }
                return View();
            }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login model)
        {
            if (ModelState.IsValid)
            {
                //make login request
                APIConnection connection = new APIConnection(ConfigurationManager.AppSettings["InternalAPIURL"]);

                LoginRequest loginRequest = new LoginRequest(connection, model.Email, model.password);
                LoginResponse loginResponse = loginRequest.Send();

                if (loginResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    Response.Cookies.Add(new HttpCookie("AccessToken")
                    {
                        Value = loginResponse.access_token,
                        HttpOnly = true,
                        Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(loginResponse.expireTime)).LocalDateTime
                    });

                    Response.Cookies.Add(new HttpCookie("UserName")
                    {
                        Value = loginResponse.user_nick,
                        HttpOnly = true,
                        Expires = DateTime.Now.AddYears(100)
                    });

                    Response.Cookies.Add(new HttpCookie("UserID")
                    {
                        Value = loginResponse.user_id,
                        HttpOnly = true,
                        Expires = DateTime.Now.AddYears(100)
                    });

                    //only store refresh token if remember me is checked
                    if (model.RememberMe)
                    {
                        Response.Cookies.Add(new HttpCookie("RefreshToken")
                        {
                            Value = loginResponse.refresh_token,
                            HttpOnly = true,
                            Expires = DateTime.Now.AddDays(60)
                        });
                    }

                    //redirect to register success, login success
                    TempData["Success"] = "You have successfully signed in!";
                    return RedirectToAction("Index", "Account");
                }
                else
                {
                    if (loginResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        TempData["Errors"] = "Your email and password do not match. Please try again.";
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
        
        public ActionResult Logout()
        {
            HttpCookie accessToken = Request.Cookies.Get("AccessToken");
            if (accessToken != null)
            {
                //delete cookies
                accessToken = new HttpCookie("AccessToken");
                accessToken.Expires = DateTime.Now.AddDays(-1d);
                Response.Cookies.Add(accessToken);
                TempData["Success"] = "You have logged out!";
            }

            HttpCookie userName = Request.Cookies.Get("UserName");
            if (userName != null)
            {
                //delete cookies
                userName = new HttpCookie("UserName");
                userName.Expires = DateTime.Now.AddDays(-1d);
                Response.Cookies.Add(userName);
            }

            HttpCookie userID = Request.Cookies.Get("UserID");
            if (userID != null)
            {
                //delete cookies
                userID = new HttpCookie("UserID");
                userID.Expires = DateTime.Now.AddDays(-1d);
                Response.Cookies.Add(userID);
            }

            HttpCookie refreshToken = Request.Cookies.Get("RefreshToken");
            if (refreshToken != null)
            {
                //delete cookies
                refreshToken = new HttpCookie("RefreshToken");
                refreshToken.Expires = DateTime.Now.AddDays(-1d);
                Response.Cookies.Add(refreshToken);
            }

            return RedirectToAction("Login", "Account");
        }
    }
}