using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SharpPcap;

namespace TCP_TRACKING
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices.Count < 1)
                {
                    _logger.LogError("Not decices Found");
                    return;
                }
                int i=0;
                int timeout = 1000;

                foreach (var device in devices)
                {
                    device.Open(DeviceMode.Promiscuous,timeout);
                    _logger.LogInformation($"{i}) {device?.MacAddress?.ToString() ??"none"} {device?.Description ??"none"}");
                    i++;
                    device.Close();
                }

                var dev = devices[3];
                dev.Open(DeviceMode.Promiscuous, timeout);
            
                while (!stoppingToken.IsCancellationRequested)
                {
                    RawCapture rawPacket = dev.GetNextPacket();
                    if (rawPacket == null)
                    {
                        await Task.Delay(1000, stoppingToken);
                        continue;
                    }
                    var frame = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    if (frame is PacketDotNet.EthernetPacket eth)
                    {
                        var ip = frame.Extract<PacketDotNet.IPPacket>();
                        if (ip != null)
                        {
                            var tcp = frame.Extract<PacketDotNet.TcpPacket>();
                            if (tcp != null)
                            {
                                if (tcp.Synchronize && !tcp.Acknowledgment)
                                {
                                    _logger.LogInformation($"Open {ip.SourceAddress}:{tcp.SourcePort} ==> {ip.DestinationAddress}:{tcp.DestinationPort}");
                                }
                                if (tcp.Finished)
                                {
                                    _logger.LogInformation($"Closing {ip.SourceAddress}:{tcp.SourcePort} ==> {ip.DestinationAddress}:{tcp.DestinationPort}");
                                }
                            }
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                _logger.LogError($"EXCEPTIONS: {ex.Message} Stack: {ex.StackTrace}");
            }
        }
    }
}
