using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Web;
using System.Web.Configuration;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace PhoenixRising.Website
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimsIdentity.DefaultNameClaimType;

            //var mksType = typeof(MachineKeySection);
            //var mksSection = ConfigurationManager.GetSection("system.web/machineKey") as MachineKeySection;
            //var resetMethod = mksType.GetMethod("Reset", BindingFlags.NonPublic | BindingFlags.Instance);

            //var keySection = new MachineKeySection();
            //keySection.ApplicationName = mksSection.ApplicationName;
            //keySection.CompatibilityMode = mksSection.CompatibilityMode;
            //keySection.DataProtectorType = mksSection.DataProtectorType;
            //keySection.Validation = mksSection.Validation;

            //keySection.ValidationKey = WebUtils.GetAppAccessToken("MK_ValidationKey");
            //keySection.DecryptionKey = WebUtils.GetAppAccessToken("MK_DecryptionKey");
            //keySection.Decryption = "AES";
            //keySection.ValidationAlgorithm = "SHA1";

            //resetMethod.Invoke(mksSection, new object[] { keySection });
        }
    }
}
