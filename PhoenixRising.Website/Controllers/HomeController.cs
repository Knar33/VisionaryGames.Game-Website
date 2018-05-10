using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace PhoenixRising.Website.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            Response.Cookies.Add(new HttpCookie("AuthToken")
            {
                Value = "123456",
                HttpOnly = true,
                Expires = DateTime.Now.AddMinutes(1)
            });
            
            return View();
        }

        public ActionResult About()
        {
            HttpCookie cookie = Request.Cookies.Get("AuthToken");
            ViewBag.Message = cookie.Value;

            return View();
        }
    }
}