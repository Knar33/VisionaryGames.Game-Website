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
using PhoenixRising.InternalAPI;
using PhoenixRising.InternalAPI.Authentication;
using PhoenixRising.InternalAPI.Account.Account;

namespace PhoenixRising.Website.Controllers
{
    public class AccountController : Controller
    {
        //Index
        public ActionResult Index()
        {
            bool authenticated = false;
            string accessToken = "";
            string refreshToken = "";
            Guid userID = new Guid();
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];

            //TODO: Make a filter for this auth shiz
            HttpCookie accessTokenCookie = Request.Cookies.Get("AccessToken");
            if (accessTokenCookie != null)
            {
                accessToken = accessTokenCookie.Value;
                userID = new Guid(Request.Cookies.Get("UserID").Value);
                authenticated = true;
            }
            else
            {
                HttpCookie refreshTokenCookie = Request.Cookies.Get("RefreshToken");

                if (refreshTokenCookie != null)
                {
                    refreshToken = refreshTokenCookie.Value;
                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        Response.Cookies.Add(new HttpCookie("AccessToken")
                        {
                            Value = refreshResponse.access_token,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserName")
                        {
                            Value = refreshResponse.user_nick,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserID")
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

            if (authenticated)
            {
                GetUserDetailsRequest detailRequest = new GetUserDetailsRequest(connection, accessToken, userID);
                GetUserDetailsResponse model = detailRequest.Send();

                if (model.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    return View(model);
                }
                else
                {
                    TempData["Errors"] = "There was an error processing your request";
                    return View();
                }
            }
            else
            {
                return RedirectToAction("Login", "Account");
            }
        }
        
        //Password Reset
        public ActionResult PasswordReset()
        {
            return View();
        }
        
        //Password Reset POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult PasswordReset(PasswordReset model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
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
                var appAccessToken = KeyVault.GetSecretAsync(ConfigurationManager.AppSettings["AzureVaultURL"]).Result.Value;

                RequestResetPasswordRequest resetRequest = new RequestResetPasswordRequest(connection, appAccessToken, model.Email);
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
        
        //Password 
        public ActionResult Password(string token)
        {
            Password model = new Password();
            model.token = token;
            return View(model);
        }
        
        //Password POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Password(Password model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
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
                string appAccessKey = KeyVault.GetSecretAsync(ConfigurationManager.AppSettings["AzureVaultURL"]).Result.Value;

                ResetPasswordRequest resetRequest = new ResetPasswordRequest(connection, appAccessKey, model.token, model.password1);
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
        
        //Register
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
                HttpCookie refreshTokenCookie = Request.Cookies.Get("RefreshToken");
                if (refreshTokenCookie != null)
                {
                    string refreshToken = refreshTokenCookie.Value;
                    string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                    
                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        Response.Cookies.Add(new HttpCookie("AccessToken")
                        {
                            Value = refreshResponse.access_token,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserName")
                        {
                            Value = refreshResponse.user_nick,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserID")
                        {
                            Value = refreshResponse.user_id,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });
                        return RedirectToAction("Index", "Account");
                    }
                }
                return View();
            }
        }
        
        //Register POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(Register model)
        {
            if (ModelState.IsValid)
            {
                //Create user request
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
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
                string appAccessKey = KeyVault.GetSecretAsync(ConfigurationManager.AppSettings["AzureVaultURL"]).Result.Value;
                
                CreateUserRequest request = new CreateUserRequest(connection, appAccessKey);
                request.Email = model.Email;
                request.FirstName = model.FirstName;
                request.LastName = model.LastName;
                request.Nicknane = model.Nicknane;
                request.Password = model.password1;

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
        
        //Login
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
                HttpCookie refreshTokenCookie = Request.Cookies.Get("RefreshToken");
                if (refreshTokenCookie != null)
                {
                    string refreshToken = refreshTokenCookie.Value;
                    string connection = ConfigurationManager.AppSettings["InternalAPIURL"];

                    RefreshRequest refreshRequest = new RefreshRequest(connection, refreshToken);
                    RefreshResponse refreshResponse = refreshRequest.Send();

                    if (refreshResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        Response.Cookies.Add(new HttpCookie("AccessToken")
                        {
                            Value = refreshResponse.access_token,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserName")
                        {
                            Value = refreshResponse.user_nick,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });

                        Response.Cookies.Add(new HttpCookie("UserID")
                        {
                            Value = refreshResponse.user_id,
                            HttpOnly = true,
                            Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(refreshResponse.expireTime)).LocalDateTime
                        });
                        return RedirectToAction("Index", "Account");
                    }
                }
                return View();
            }
        }
        
        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login model)
        {
            if (ModelState.IsValid)
            {
                //make login request
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];

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
                        Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(loginResponse.expireTime)).LocalDateTime
                    });

                    Response.Cookies.Add(new HttpCookie("UserID")
                    {
                        Value = loginResponse.user_id,
                        HttpOnly = true,
                        Expires = DateTimeOffset.FromUnixTimeSeconds(long.Parse(loginResponse.expireTime)).LocalDateTime
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
        
        //Logout
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