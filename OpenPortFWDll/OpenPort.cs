using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OpenPortFWDll
{
    public enum OpenPortProtocolType
    {
        TCP, UDP
    }

    public enum OpenPortResult
    {
        OK, Faild, AccessDenied
    }

    public enum OpenPortDirection
    {
        IN, OUT
    }

    /// <summary>
    /// About this file
    /// </summary>
    public static class OpenPortFWInfo
    {
        public const string Description = "*This file can open specific port so that firewall allows data transfer via this port, and close it also.";
        public const string Developer = "Morteza Mahmoudi";
        public const string EMail = "morteza5054+dll@gmail.com";
    }

    /// <summary>
    /// This class can open specific port so that firewall allows data transfer via this port, and close it also
    /// </summary>
    public class AllowFirewall
    {
        /// <summary>
        /// This function can open specific port so that firewall allows data transfer via this port.
        /// </summary>
        /// <param name="port">Port number that you want to open it</param>
        /// <param name="protocol">Protocol that is used</param>
        /// <param name="in_out_dir">IN_bound or OUT_bound</param>
        /// <returns>Return OpenPortResult</returns>
        public static OpenPortResult OpenPort(int port, OpenPortProtocolType protocol, OpenPortDirection in_out_dir = OpenPortDirection.IN)
        {
            try
            {
                INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FWRule"));
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                firewallRule.Description = "Open " + protocol.ToString() + " port " + port.ToString();
                if(in_out_dir == OpenPortDirection.IN)
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                else
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                firewallRule.Enabled = true;
                firewallRule.InterfaceTypes = "All";
                firewallRule.Name = protocol.ToString() + port.ToString() + "EnableByMorteza5054Gmail";
                if (protocol == OpenPortProtocolType.TCP)
                    firewallRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                else
                    firewallRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                firewallRule.LocalPorts = port.ToString(); ;

                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(
                    Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(firewallRule);
                return OpenPortResult.OK;
            }
            catch (UnauthorizedAccessException ex)
            { return OpenPortResult.AccessDenied; }
            catch { return OpenPortResult.Faild; }
        }

        /// <summary>
        /// This function closes opened port by 'OpenPort' function.
        /// </summary>
        /// <param name="port">Port number</param>
        /// <param name="protocol">Protocol that is used</param>
        /// <returns>Return OpenPortResult</returns>
        public static OpenPortResult CloseOpenedPort(int port, OpenPortProtocolType protocol)
        {
            try
            {
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(
                    Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                string rName = protocol.ToString() + port.ToString() + "EnableByMorteza5054Gmail";
                while (true)
                {
                    try
                    {
                        if (firewallPolicy.Rules.Item(rName) != null)
                            firewallPolicy.Rules.Remove(rName);
                        else
                            break;
                    }
                    catch (UnauthorizedAccessException ex)
                    { return OpenPortResult.AccessDenied; }
                    catch { break; }
                }
                return OpenPortResult.OK;
            }
            catch { return OpenPortResult.Faild; }
        }
    }
}
