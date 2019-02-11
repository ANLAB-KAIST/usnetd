use smoltcp::phy::{Device, TxToken};
use smoltcp::time::Instant;
use smoltcp::Error;
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(feature = "netmap")]
use usnet_devices::{Netmap, NetmapRxToken, NetmapTxToken};

use usnet_devices::{
    TapInterface, TapInterfaceRxToken, TapInterfaceTxToken, UnixDomainSocket,
    UnixDomainSocketRxToken, UnixDomainSocketTxToken,
};

#[derive(Debug)]
pub enum EndpointDevice {
    #[cfg(feature = "netmap")]
    HostRing(Netmap, String),
    #[cfg(feature = "netmap")]
    NicNetmap(Netmap, String, Vec<u16>),
    #[cfg(feature = "netmap")]
    UserNetmap(Netmap, u16),
    UserUnixDomainSocket(UnixDomainSocket),
    NicMacVtap(TapInterface, String),
    HostTap(TapInterface, String),
}

// workaround for same-type limitation in fn … -> Option<(impl RxToken, impl TxToken)>
pub enum ReceiveTokenImpl {
    #[cfg(feature = "netmap")]
    Netmap((NetmapRxToken, NetmapTxToken)),
    UnixDomainSocket((UnixDomainSocketRxToken, UnixDomainSocketTxToken)),
    Tap((TapInterfaceRxToken, TapInterfaceTxToken)),
}

#[cfg(feature = "netmap")]
pub fn all_pipes() -> Vec<u16> {
    (0..4095_u16).collect()
}

impl EndpointDevice {
    pub fn is_netmap(&self) -> bool {
        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::HostRing(_, _)
            | EndpointDevice::NicNetmap(_, _, _)
            | EndpointDevice::UserNetmap(_, _) => true,
            EndpointDevice::UserUnixDomainSocket(_)
            | EndpointDevice::NicMacVtap(_, _)
            | EndpointDevice::HostTap(_, _) => false,
        }
    }
    #[cfg(not(feature = "netmap"))]
    pub fn zc_forward(&mut self, _from: &mut EndpointDevice) -> Result<(), Error> {
        panic!("no netmap support")
    }
    #[cfg(feature = "netmap")]
    pub fn zc_forward(&mut self, from: &mut EndpointDevice) -> Result<(), Error> {
        match self {
            EndpointDevice::HostRing(target_dev, _)
            | EndpointDevice::NicNetmap(target_dev, _, _)
            | EndpointDevice::UserNetmap(target_dev, _) => match from {
                EndpointDevice::HostRing(from_dev, _)
                | EndpointDevice::NicNetmap(from_dev, _, _)
                | EndpointDevice::UserNetmap(from_dev, _) => target_dev.zc_forward(from_dev),
                EndpointDevice::UserUnixDomainSocket(_)
                | EndpointDevice::NicMacVtap(_, _)
                | EndpointDevice::HostTap(_, _) => Err(Error::Illegal),
            },
            EndpointDevice::UserUnixDomainSocket(_)
            | EndpointDevice::NicMacVtap(_, _)
            | EndpointDevice::HostTap(_, _) => Err(Error::Illegal),
        }
    }
    pub fn get_nic<'a>(&'a self) -> Option<&'a str> {
        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::HostRing(_, _) | EndpointDevice::UserNetmap(_, _) => None,
            EndpointDevice::HostTap(_, _) | EndpointDevice::UserUnixDomainSocket(_) => None,
            #[cfg(feature = "netmap")]
            EndpointDevice::NicNetmap(_, iface, _) => Some(iface.as_ref()),
            EndpointDevice::NicMacVtap(_, iface) => Some(iface.as_ref()),
        }
    }
    pub fn get_host_ring<'a>(&'a self) -> Option<&'a str> {
        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::HostRing(_, iface) => Some(iface.as_ref()),
            EndpointDevice::HostTap(_, iface) => Some(iface.as_ref()),
            #[cfg(feature = "netmap")]
            EndpointDevice::NicNetmap(_, _, _) | EndpointDevice::UserNetmap(_, _) => None,
            EndpointDevice::UserUnixDomainSocket(_) => None,
            EndpointDevice::NicMacVtap(_, _) => None,
        }
    }
    #[cfg(feature = "netmap")]
    pub fn free_pipe_ids<'a>(&'a mut self) -> &'a mut Vec<u16> {
        match self {
            EndpointDevice::HostRing(_, _)
            | EndpointDevice::UserNetmap(_, _)
            | EndpointDevice::UserUnixDomainSocket(_)
            | EndpointDevice::HostTap(_, _)
            | EndpointDevice::NicMacVtap(_, _) => panic!("wrong call"),
            EndpointDevice::NicNetmap(_, _, free_ids) => free_ids,
        }
    }
    pub fn get_device_receive(&mut self) -> Option<ReceiveTokenImpl> {
        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::NicNetmap(device, _, _)
            | EndpointDevice::HostRing(device, _)
            | EndpointDevice::UserNetmap(device, _) => device
                .receive()
                .map(|inner| ReceiveTokenImpl::Netmap(inner)),
            EndpointDevice::UserUnixDomainSocket(device) => device
                .receive()
                .map(|inner| ReceiveTokenImpl::UnixDomainSocket(inner)),
            EndpointDevice::NicMacVtap(device, _) | EndpointDevice::HostTap(device, _) => {
                device.receive().map(|inner| ReceiveTokenImpl::Tap(inner))
            }
        }
    }
    pub fn as_raw_fd(&self) -> RawFd {
        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::NicNetmap(device, _, _)
            | EndpointDevice::HostRing(device, _)
            | EndpointDevice::UserNetmap(device, _) => device.as_raw_fd(),
            EndpointDevice::UserUnixDomainSocket(device) => device.as_raw_fd(),
            EndpointDevice::NicMacVtap(device, _) | EndpointDevice::HostTap(device, _) => {
                device.as_raw_fd()
            }
        }
    }
    pub fn write(&mut self, read_buffer: &[u8]) -> Result<(), Error> {
        // workaround for same-type limitation in fn … -> impl Device
        fn write_helper<'a>(dev: &'a mut impl Device<'a>, read_buffer: &[u8]) -> Result<(), Error> {
            if let Some(tx_host) = dev.transmit() {
                tx_host.consume(Instant::from_millis(0), read_buffer.len(), |send_buffer| {
                    send_buffer[..].copy_from_slice(read_buffer);
                    Ok(())
                })
            } else {
                Err(Error::Dropped)
            }
        }

        match self {
            #[cfg(feature = "netmap")]
            EndpointDevice::NicNetmap(device, _, _)
            | EndpointDevice::HostRing(device, _)
            | EndpointDevice::UserNetmap(device, _) => write_helper(device, read_buffer),
            EndpointDevice::UserUnixDomainSocket(device) => write_helper(device, read_buffer),
            EndpointDevice::NicMacVtap(device, _) | EndpointDevice::HostTap(device, _) => {
                write_helper(device, read_buffer)
            }
        }
    }
}
