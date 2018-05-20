using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class ChangeEmail
    {
        [Required]
        [EmailAddress]
        [Display(Name = "New Email Address")]
        public string Email { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Password")]
        public string password1 { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Re-Type Password")]
        [Compare("password1")]
        public string password2 { get; set; }
    }
}