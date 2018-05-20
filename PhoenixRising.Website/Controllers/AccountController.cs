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
using PhoenixRising.Website.Filters;

namespace PhoenixRising.Website.Controllers
{
    public class AccountController : Controller
    {
        //Index
        [CookieAuthentication]
        [AuthorizeUser(AccessLevel="Unbanned")]
        public ActionResult Index()
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];

            GetUserDetailsRequest detailRequest = new GetUserDetailsRequest(connection, Request.Cookies.Get("AccessToken").Value, new Guid(Request.Cookies.Get("UserID").Value));
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
                var appAccessToken = WebUtils.GetAppAccessToken();

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

        //Verify email 
        public ActionResult Verify(string token)
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var appAccessToken = WebUtils.GetAppAccessToken();

            VerifyUserRequest verifyRequest = new VerifyUserRequest(connection, appAccessToken, token);
            VerifyUserResponse verifyResponse = verifyRequest.Send();

            if (verifyResponse.StatusCode == System.Net.HttpStatusCode.OK)
            {
                TempData["Success"] = "You have successfully verified your email address. You can now login below.";
            }
            else
            {
                TempData["Errors"] = "There was an error processing your request.";
            }

            return RedirectToAction("Login", "Account");
        }

        //Password POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Password(Password model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                var appAccessToken = WebUtils.GetAppAccessToken();

                ResetPasswordRequest resetRequest = new ResetPasswordRequest(connection, appAccessToken, model.token, model.password1);
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
            return View();
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
                var appAccessToken = WebUtils.GetAppAccessToken();

                CreateUserRequest request = new CreateUserRequest(connection, appAccessToken);
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
            return View();
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
                    else if (loginResponse.StatusCode == System.Net.HttpStatusCode.NotAcceptable)
                    {
                        //todo: add the link here
                        TempData["Errors"] = "Your email is pending verification. Please check your email, or click [insert link here] to resend.";
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