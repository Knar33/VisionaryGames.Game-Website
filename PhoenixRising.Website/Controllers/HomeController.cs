using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using PhoenixRising.InternalAPI;

namespace PhoenixRising.Website.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View("Index", "~/Views/Shared/_Homepage.cshtml");
        }
    }
}