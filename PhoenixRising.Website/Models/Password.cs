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
        public string password1 { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Re-Type Password")]
        [System.ComponentModel.DataAnnotations.Compare("password1")]
        public string password2 { get; set; }
    }
}