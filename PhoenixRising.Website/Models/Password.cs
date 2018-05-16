using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class Password
    {
        public string token { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "New Password")]
        public string password { get; set; }
    }
}