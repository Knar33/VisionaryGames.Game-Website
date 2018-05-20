using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class Resend
    {
        [Required]
        public string EmailResend { get; set; }
    }
}