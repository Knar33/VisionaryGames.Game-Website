using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class ChangePassword
    {
        [Required]
        [MinLength(4)]
        [Display(Name = "Old Password")]
        public string OldPassword { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "New Password")]
        public string Password1 { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Re-Type New Password")]
        [Compare("Password1")]
        public string Password2 { get; set; }
    }
}