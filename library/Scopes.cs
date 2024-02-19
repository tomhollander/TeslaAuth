using System;
using System.Collections.Generic;
using System.Text;

namespace TeslaAuth
{
    /// <summary>
    /// Helper class that makes it easy to generate a scope string when authenticating to the Fleet API
    /// </summary>
    public static class Scopes
    {
        public static string UserData = "user_data";
        public static string VehicleDeviceData = "vehicle_device_data";
        public static string VehicleCommands = "vehicle_commands";
        public static string VehicleChargingCommands = "vehicle_charging_commands";
        public static string EnergyDeviceData = "energy_device_data";
        public static string EnergyCommands = "energy_cmds";

        /// <summary>
        /// Generates a single string including the requested scopes, along with the mandatory oauth scopes.
        /// </summary>
        /// <param name="scopes">A list of scopes, which can include the constants in this calss</param>
        /// <returns>A single scope string that can be used when initialising the TeslaAuthHelper</returns>
        public static string BuildScopeString(IEnumerable<string> scopes)
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
