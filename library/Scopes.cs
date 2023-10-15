using System;
using System.Collections.Generic;
using System.Text;

namespace TeslaAuth
{

    public static class Scopes
    {
        public static string UserData = "user_data";
        public static string VechicleDeviceData = "vehicle_device_data";
        public static string VehicleCommands = "vehicle_commands";
        public static string VehicleChargingCommands = "vehicla_charging_commands";
        public static string EnergyDeviceData = "energy_device_data";
        public static string EnergyCommands = "energy_cmds";

        public static string GetScopeString(params string[] scopes)
        {
            var sb = new StringBuilder();
            sb.Append("openid offline_access ");
            foreach (var scope in scopes)
            {
                sb.Append(scope);
                sb.Append(" ");
            }
            return sb.ToString();
        }
    }
}
