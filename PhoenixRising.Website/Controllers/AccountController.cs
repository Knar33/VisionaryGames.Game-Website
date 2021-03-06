﻿using System;
using System.Web;
using System.Web.Mvc;
using System.Configuration;
using PhoenixRising.Website.Models;
using PhoenixRising.InternalAPI.Website;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using PhoenixRising.InternalAPI.Authentication;
using PhoenixRising.InternalAPI.Account.Account;
using PhoenixRising.InternalAPI.App.DownloadURL;
using PhoenixRising.Website.Filters;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin.Security;

namespace PhoenixRising.Website.Controllers
{
    public class AccountController : Controller
    {
        [CookieAuthentication]
        public ActionResult Index()
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            ClaimsIdentity identity = new ClaimsIdentity(Request.GetOwinContext().Authentication.User.Identity);
            string accessToken = identity.FindFirst("AccessToken").Value;
            string userID = identity.FindFirst(ClaimTypes.NameIdentifier).Value;

            GetUserDetailsRequest detailRequest = new GetUserDetailsRequest(connection, accessToken, new Guid(userID));
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
                var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

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
                var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

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

        //Verify email 
        public ActionResult Verify(string token)
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

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
                var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

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
                    string accessToken = loginResponse.access_token;
                    Guid userID = new Guid(loginResponse.user_id);

                    GetUserDetailsRequest userDetailRequest = new GetUserDetailsRequest(connection, accessToken, userID);
                    GetUserDetailsResponse userDetailResponse = userDetailRequest.Send();
                    if (userDetailResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        List<Claim> claims = new List<Claim>();
                        claims.Add(new Claim("AccessToken", loginResponse.access_token));
                        claims.Add(new Claim("RefreshToken", loginResponse.refresh_token));
                        claims.Add(new Claim(ClaimTypes.Name, loginResponse.user_nick));
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, loginResponse.user_id));
                        claims.Add(new Claim(ClaimTypes.Expiration, loginResponse.expireTime));
                        claims.Add(new Claim(ClaimTypes.IsPersistent, model.RememberMe.ToString()));
                        if (userDetailResponse.PERMISSIONS.Administrator)
                        {
                            claims.Add(new Claim(ClaimTypes.Role, "Administrator"));
                        }
                        if (userDetailResponse.PERMISSIONS.Developer)
                        {
                            claims.Add(new Claim(ClaimTypes.Role, "Developer"));
                        }

                        ClaimsIdentity id = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
                        var authenticationManager = Request.GetOwinContext().Authentication;

                        AuthenticationProperties properties = new AuthenticationProperties { IsPersistent = model.RememberMe };
                        authenticationManager.SignIn(properties, id);

                        //redirect to register success, login success
                        TempData["Success"] = "You have successfully signed in!";
                        return RedirectToAction("Index", "Account");
                    }    
                    else
                    {
                        TempData["Errors"] = "There was an error processing your request.";
                        return View(model);
                    }
                }
                else
                {
                    if (loginResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        TempData["Errors"] = "Your email and password do not match. Please try again.";
                    }
                    else if (loginResponse.StatusCode == System.Net.HttpStatusCode.NotAcceptable)
                    {
                        TempData["Resend"] = model.Email;
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
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            authenticationManager.SignOut();

            return RedirectToAction("Login", "Account");
        }
        
        //Edit Info
        [CookieAuthentication]
        public ActionResult EditInfo()
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var ctx = Request.GetOwinContext();
            ClaimsPrincipal user = ctx.Authentication.User;
            string accessToken = user.Claims.FirstOrDefault(x => x.Type == "AccessToken").Value;
            string userID = user.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;

            GetUserDetailsRequest userDetailRequest = new GetUserDetailsRequest(connection, accessToken, new Guid(userID));
            GetUserDetailsResponse userDetailResponse = userDetailRequest.Send();

            EditInfo model = new EditInfo()
            {
                Nicknane = userDetailResponse.NICKNAME,
                FirstName = userDetailResponse.FIRST_NAME,
                LastName = userDetailResponse.LAST_NAME,
            };
            return View(model);
        }

        //Edit Info POST
        [HttpPost]
        [CookieAuthentication]
        [ValidateAntiForgeryToken]
        public ActionResult EditInfo(EditInfo model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                var ctx = Request.GetOwinContext();
                ClaimsIdentity identity = new ClaimsIdentity(Request.GetOwinContext().Authentication.User.Identity);
                string accessToken = identity.FindFirst("AccessToken").Value;
                Guid userID = new Guid(identity.FindFirst(ClaimTypes.NameIdentifier).Value);
                string currentUserName = identity.FindFirst(ClaimTypes.Name).Value;

                EditUserRequest request = new EditUserRequest(connection, accessToken, userID);
                request.FirstName = model.FirstName;
                request.LastName = model.LastName;
                request.Nicknane = model.Nicknane;

                EditUserResponse response = request.Send();

                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    //TODO: If Nickname is changed, change it in the user claim
                    if (request.Nicknane != currentUserName)
                    {
                        identity.RemoveClaim(identity.FindFirst(ClaimTypes.Name));
                        identity.AddClaim(new Claim(ClaimTypes.Name, request.Nicknane));

                        var authenticationManager = HttpContext.GetOwinContext().Authentication;
                        authenticationManager.SignOut();

                        AuthenticationProperties properties = new AuthenticationProperties { IsPersistent = Convert.ToBoolean(identity.FindFirst(ClaimTypes.IsPersistent).Value) };
                        authenticationManager.SignIn(properties, identity);

                        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
                        HttpContext.User = claimsPrincipal;
                    }

                    TempData["Success"] = "You have successfully updated your info";
                    return RedirectToAction("Index", "Account");
                }
                else
                {
                    TempData["Errors"] = "There was an error processing your request. Please try again.";
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }

        //Edit Info
        public ActionResult ChangeEmail()
        {
            return View();
        }

        //Edit Info POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangeEmail(ChangeEmail model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                var ctx = Request.GetOwinContext();
                ClaimsPrincipal user = ctx.Authentication.User;
                string accessToken = user.Claims.FirstOrDefault(x => x.Type == "AccessToken").Value;
                Guid userID = new Guid(user.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value);

                EditUserRequest request = new EditUserRequest(connection, accessToken, userID);
                request.Email = model.Email;
                request.Password = model.password1;

                EditUserResponse response = request.Send();

                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    TempData["Success"] = "You have successfully updated your email. An email has been sent to the new address with instructions on how to verify the address change.";
                    return RedirectToAction("Index", "Account");
                }
                else
                {
                    TempData["Errors"] = "There was an error processing your request. Please try again.";
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
        }

        //Change Password
        [CookieAuthentication]
        public ActionResult ChangePassword()
        {
            return View();
        }

        //Change Password POST
        [HttpPost]
        [CookieAuthentication]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePassword model)
        {
            if (ModelState.IsValid)
            {
                string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
                var ctx = Request.GetOwinContext();
                ClaimsPrincipal user = ctx.Authentication.User;
                string accessToken = user.Claims.FirstOrDefault(x => x.Type == "AccessToken").Value;
                Guid userID = new Guid(user.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value);

                ChangePasswordRequest resetRequest = new ChangePasswordRequest(connection, accessToken, userID, model.OldPassword, model.Password1);
                ChangePasswordResponse resetResponse = resetRequest.Send();

                if (resetResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    TempData["Success"] = "Your password was changed!";
                    return RedirectToAction("Index", "Account");
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

        //Resend Email Validation
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResendValidation(Resend model)
        {
            string connection = ConfigurationManager.AppSettings["InternalAPIURL"];
            var appAccessToken = WebUtils.GetVaultSecret("AppConnectionKey");

            ResendVerificationRequest resendRequest = new ResendVerificationRequest(connection, appAccessToken, model.EmailResend);
            ResendVerificationResponse resendResponse = resendRequest.Send();

            if (resendResponse.StatusCode == System.Net.HttpStatusCode.OK)
            {
                TempData["Success"] = "Another verification email was sent.";
                return RedirectToAction("Index", "Account");
            }
            else
            {
                TempData["Errors"] = "There was an error processing your request";
                return RedirectToAction("Index", "Account");
            }
        }
    }
}