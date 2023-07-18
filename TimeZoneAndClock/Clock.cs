using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TimeZoneAndClock
{
    public class Clock
    {
        //No need to change anything just we have to set Registry for this Settings

        /* 
            "Computer\HKEY_CURRENT_USER\Control Panel\TimeDate\AdditionalClocks\1"
            "Computer\HKEY_CURRENT_USER\Control Panel\TimeDate\AdditionalClocks\2"

            from above registry path we need to set 3 things from code
            1) DisplayName = ""
            2) Enable = 0-1
            3) TzRegKeyname - "Pacific Standard Time"
        */
    }
}
