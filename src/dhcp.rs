use std::collections::HashMap;
use anyhow::Result;
use crate::log;

/// Milliseconds on lwip's clock. std::time::Instant panics on
/// wasm32-unknown-unknown, so leases use this instead.
fn now_ms() -> u64 {
    unsafe { crate::performance_now() as u64 }
}

pub const DHCP_MAC: [u8; 6] = [0x06, 0x6E, 0x69, 0x67, 0x68, 0x74];

pub struct DhcpService {
    pub subnet_mask: [u8; 4],
    pub gateway_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub dns_ip: [u8; 4],
    pub leasetime: u32, // secs
    pub offer_timeout: u64, // millis
    pub taken: u64,
    pub leases: [Option<Lease>; 64],
    pub mac_map: HashMap<[u8; 6], u8>,
}

pub struct DhcpFrame {
    pub op: u8,
    pub xid: [u8; 4],
    pub flags: [u8; 2],
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub chaddr: [u8; 16], // we're only gonna use the first 6 bytes

    pub msg_type: u8,// technically a dhcp option but its really not optional
    pub leasetime: Option<u32>,
    pub server_to: Option<[u8; 4]>,
    pub requested_ip: Option<[u8; 4]>,
    pub subnet_mask: Option<[u8; 4]>,
    pub gateway: Option<[u8; 4]>,
    pub dns_ip: Option<[u8; 4]>,
}

pub struct Lease {
    pub mac: [u8; 6],
    pub state: u8, // 0 is unallocated, 1 is offered, 2 is assigned
    pub expires: u64, // now_ms() deadline
}

impl DhcpFrame {
    pub fn construct_reply(frame: &DhcpFrame, assigned_ip: [u8; 4], server: &DhcpService, reply_type: u8,) -> Self {
        let mut reply = DhcpFrame {
            op: 2,
            xid: frame.xid,
            flags: frame.flags,
            ciaddr: [0u8; 4],
            yiaddr: [0u8; 4],
            chaddr: frame.chaddr,
            msg_type: reply_type,
            requested_ip: None,
            subnet_mask: None,
            gateway: None,
            dns_ip: None,
            leasetime: None,
            server_to: None,
        };

        // RFC 2131 4.3.1: a NAK must still carry the server identifier
        reply.server_to = Some(server.server_ip);

        // weve set up the frame to be a nak already above
        if reply_type == 6 {
            return reply;
        }

        if reply_type == 5 && frame.msg_type == 3 {
            reply.ciaddr = frame.ciaddr;
        }

        reply.subnet_mask = Some(server.subnet_mask);
        reply.gateway = Some(server.gateway_ip);
        reply.dns_ip = Some(server.dns_ip);
        reply.leasetime = Some(server.leasetime);
        reply.yiaddr = assigned_ip;
        reply.server_to = Some(server.server_ip);
        
        reply
    }
    
    // this function ONLY works for packets sent by clients, youll notice we dont care about options normal clients wouldnt send here
    pub fn from_client_bytes(frame: &[u8]) -> Option<Self> {
        let pkt_len = frame.len();
        if pkt_len < 241 { return None; } // malformed
        if frame[236..240] != [0x63, 0x82, 0x53, 0x63] { return None; }

        let mut msg_type: u8 = 0;
        let mut requested_ip: Option<[u8; 4]> = None;
        let mut server_to: Option<[u8; 4]> = None;

        //parse tlv
        let mut offset: usize = 240;

        while offset < pkt_len {
            let opt_type = frame[offset];
            if opt_type == 0 {
                offset += 1;
                continue;
            }
            if opt_type == 255 {
                break;
            }

            let data_len: usize = *(frame.get(offset + 1)?) as usize;
            let data = frame.get(offset + 2..offset + 2 + data_len)?;

            match opt_type {
                53 => msg_type = *data.first()?,
                50 => requested_ip = Some(data.get(0..4)?.try_into().ok()?),
                54 => server_to = Some(data.get(0..4)?.try_into().ok()?),
                _ => (),
            }
            offset += 2 + data_len;
        }

        if msg_type == 0 { return None; }

        Some(DhcpFrame {
            op: frame[0],
            xid: frame[4..8].try_into().ok()?,
            flags: frame[10..12].try_into().ok()?,
            ciaddr: frame[12..16].try_into().ok()?,
            yiaddr: frame[16..20].try_into().ok()?,
            chaddr: frame[28..44].try_into().ok()?,
            msg_type,
            requested_ip,
            server_to,
            subnet_mask: None,
            gateway: None,
            dns_ip: None,
            leasetime: None,
        })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = Vec::new();

        // yeah im sorry
        packet.extend_from_slice(&[
            self.op,
            1u8, //htype
            6u8, //hlen
            0u8, //hops
            self.xid[0],
            self.xid[1],
            self.xid[2],
            self.xid[3],
            0u8, //secs
            0u8,
            self.flags[0],
            self.flags[1],

            self.ciaddr[0],
            self.ciaddr[1],
            self.ciaddr[2],
            self.ciaddr[3],

            self.yiaddr[0],
            self.yiaddr[1],
            self.yiaddr[2],
            self.yiaddr[3],
            //siaddr
            0u8,
            0u8,
            0u8,
            0u8,
            //giaddr
            0u8,
            0u8,
            0u8,
            0u8,
        ]);
        packet.extend_from_slice(&self.chaddr);
        packet.extend_from_slice(&[0u8; 192]); //sname and file
        packet.extend_from_slice(&0x63825363u32.to_be_bytes()); //magic

        // tlv, only the options that are set (a NAK must not carry lease info)
        packet.extend_from_slice(&[53u8, 1u8, self.msg_type]);
        let opts = [
            (50u8, self.requested_ip),
            (1, self.subnet_mask),
            (3, self.gateway),
            (6, self.dns_ip),
            (51, self.leasetime.map(u32::to_be_bytes)),
            (54, self.server_to),
        ];
        for (code, value) in opts {
            if let Some(v) = value {
                packet.extend_from_slice(&[code, 4]);
                packet.extend_from_slice(&v);
            }
        }
        packet.push(255);

        // some BOOTP-era clients drop messages shorter than 300 bytes
        if packet.len() < 300 { packet.resize(300, 0); }
        packet
    }
}

impl DhcpService {
    pub fn new(gateway: &[u8], ip: &[u8], netmask: &[u8], leasetime: u32, offer_timeout: u64) -> Result<DhcpService> {
        Ok(DhcpService {
            subnet_mask: netmask.try_into()?,
            gateway_ip: gateway.try_into()?,
            server_ip: ip.try_into()?,
            dns_ip: [1, 1, 1, 1],
            leasetime,
            offer_timeout,
            taken: 0,
            leases: [const { None }; 64],
            mac_map: HashMap::new(),
        })
    }

    pub fn handle_packet(&mut self, frame: &[u8]) -> Option<([u8; 6], [u8; 4], Vec<u8>)> {
        let msg = DhcpFrame::from_client_bytes(frame)?;

        let mac: [u8; 6] = msg.chaddr[0..6].try_into().ok()?;
        let dst_mac = if msg.flags[0] & 0x80 != 0 { [255u8; 6] } else { msg.chaddr[0..6].try_into().ok()? };
        
        match msg.msg_type {
            1 => { //discover
                // lazy offer cleanup, taken being 0 takes precedence over anything in ip map or mac map
                if let Some(ip) = self.mac_map.get(&mac) { self.taken &= !(1 << ip); }

                if let Some(mut ip) = msg.requested_ip {
                    ip[3] = client_ip_check(ip[3]);
                    // 255 = outside our range; clean_timer(255) would index past leases
                    if ip[3] != 255 { self.clean_timer(ip[3]); }

                    if ip[0..3] == self.gateway_ip[0..3] && ip[3] != 255 && ((self.taken >> ip[3]) & 1) == 0 {
                        self.taken |= 1 << ip[3];
                        self.leases[ip[3] as usize] = Some(Lease { mac: mac, state: 1, expires: now_ms() + self.offer_timeout });
                        self.mac_map.insert(mac, ip[3]);

                        ip[3] += 100;
                        return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, ip, &self, 2).to_bytes()))
                    }
                }

                let addr = self.find_first_available();

                self.taken |= 1 << addr;
                self.leases[addr as usize] = Some(Lease { mac: mac, state: 1, expires: now_ms() + self.offer_timeout });
                self.mac_map.insert(mac, addr);
                return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [self.gateway_ip[0], self.gateway_ip[1], self.gateway_ip[2], addr + 100], &self, 2).to_bytes()))

            }
            3 => { //request
                // either normal dora or init reboot
                if let Some(mut ip) = msg.requested_ip {
                    if ip[0..3] != self.gateway_ip[0..3] {
                        return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [0u8; 4], &self, 6).to_bytes()))
                    }
                    ip[3] = match client_ip_check(ip[3]) {
                        255 => return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [0u8; 4], &self, 6).to_bytes())),
                        addr => addr,
                    };
                    self.clean_timer(ip[3]);

                    if ((self.taken >> ip[3]) & 1) == 1 {
                        if let Some(ref mut lease) = self.leases[ip[3] as usize] {
                            if lease.mac != mac { return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [0u8; 4], &self, 6).to_bytes())) }
                            else {
                                lease.state = 2;
                                lease.expires = now_ms() + self.leasetime as u64 * 1000;
                                return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [self.gateway_ip[0], self.gateway_ip[1], self.gateway_ip[2], ip[3] + 100], &self, 5).to_bytes()))
                            }
                        }
                        // this should never happen but just in case
                        log!("[MOONBEAM] the thing that should never happen happened");
                        self.taken &= !(1 << ip[3]);
                    }
                    return None;
                }
                // renew/rebind    
                if msg.ciaddr[0..3] != self.gateway_ip[0..3] {
                    return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [0u8; 4], &self, 6).to_bytes()))
                }
                let ip = match client_ip_check(msg.ciaddr[3]) { 255 => return None , addr => addr};
                self.clean_timer(ip);

                if ((self.taken >> ip) & 1) == 1 {
                    if let Some(ref mut lease) = self.leases[ip as usize] {
                        if lease.state != 2 { return None; }
                        if lease.mac != mac { return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [0u8; 4], &self, 6).to_bytes())) }
                        else { 
                            lease.expires = now_ms() + self.leasetime as u64 * 1000;
                            return Some((dst_mac, [0,0,0,0], DhcpFrame::construct_reply(&msg, [self.gateway_ip[0], self.gateway_ip[1], self.gateway_ip[2], ip + 100], &self, 5).to_bytes()))
                        }
                    }
                    log!("[MOONBEAM] the thing that should never happen happened");
                    self.taken &= !(1 << ip);
                }
                return None;
            }
            4 => { //decline
                log!("[MOONBEAM] client {} sent DHCPDECLINE", hex::encode(mac));
                return None;
            }
            7 => { //release
                let ip = match client_ip_check(msg.ciaddr[3]) { 255 => return None, addr => addr};
                if let Some(ref mut lease) = self.leases[ip as usize] {
                    if lease.mac == mac { self.taken &= !(1 << ip); }
                }
                return None;
            }
            _ => None,
        }
    }

    pub fn find_first_available(&self) -> u8 {
        let index = (!self.taken).trailing_zeros();
        if index < 64 { index as u8 } else { 0 }
    }

    pub fn clean_timer(&mut self, ip: u8) {
        if let Some(ref mut lease) = self.leases[ip as usize] {
            if lease.expires < now_ms() {
                self.leases[ip as usize] = None;
                self.taken &= !(1 << ip);
            }
        }
    }
}

const ETH_HDR: usize = 14;
const IP_HDR: usize = 20;
const UDP_HDR: usize = 8;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

// try to extract dhcp message
pub fn dhcp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.get(12..14)? != [0x08, 0x00] { return None; }
    let ip = frame.get(ETH_HDR..)?;
    let ihl = (*ip.first()? & 0x0f) as usize * 4;
    if ip[0] >> 4 != 4 || ihl < IP_HDR || *ip.get(9)? != 17 { return None; }
    if u16::from_be_bytes(ip.get(6..8)?.try_into().ok()?) & 0x3fff != 0 { return None; }
    let ip_len = (u16::from_be_bytes(ip.get(2..4)?.try_into().ok()?) as usize).min(ip.len());
    let udp = ip.get(ihl..ip_len)?;
    if u16::from_be_bytes(udp.get(2..4)?.try_into().ok()?) != DHCP_SERVER_PORT { return None; }
    let udp_len = u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?) as usize;
    udp.get(UDP_HDR..udp_len.min(udp.len()))
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

// frames our reply
pub fn frame_reply(src_mac: [u8; 6], src_ip: [u8; 4], dst_mac: [u8; 6], dst_ip: [u8; 4], dhcp: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HDR + dhcp.len();
    let ip_len = IP_HDR + udp_len;
    let mut f = Vec::with_capacity(ETH_HDR + ip_len);

    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);

    let ip_start = f.len();
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&(ip_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0]); // id 0, don't fragment
    f.extend_from_slice(&[64, 17, 0, 0]); // ttl, udp, checksum placeholder
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    let csum = ip_checksum(&f[ip_start..ip_start + IP_HDR]);
    f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());

    f.extend_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    f.extend_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(dhcp);
    f
}

impl DhcpService {
    pub fn handle_frame(&mut self, frame: &[u8], server_mac: [u8; 6]) -> Option<Option<Vec<u8>>> {
        let payload = dhcp_payload(frame)?;
        if payload.first() != Some(&1) { return Some(None); } // no bootrequest

        let Some((mut dst_mac, _, reply)) = self.handle_packet(payload) else { return Some(None) };
        if reply.get(242) == Some(&6) { dst_mac = [0xff; 6]; }
        let dst_ip = if dst_mac == [0xff; 6] {
            [255; 4]
        } else {
            // unicast to the address being handed out (or ciaddr on renew),
            let yiaddr: [u8; 4] = reply[16..20].try_into().unwrap();
            let ciaddr: [u8; 4] = reply[12..16].try_into().unwrap();
            if ciaddr != [0; 4] { ciaddr } else if yiaddr != [0; 4] { yiaddr } else { [255; 4] }
        };
        Some(Some(frame_reply(server_mac, self.server_ip, dst_mac, dst_ip, &reply)))
    }
}

pub fn arp_reply_for(frame: &[u8], mac: [u8; 6], ip: [u8; 4]) -> Option<Vec<u8>> {
    if frame.get(12..14)? != [0x08, 0x06] { return None; }
    let arp = frame.get(ETH_HDR..ETH_HDR + 28)?;

    if arp[0..8] != [0, 1, 8, 0, 6, 4, 0, 1] || arp[24..28] != ip { return None; }
    let (sender_mac, sender_ip) = (&arp[8..14], &arp[14..18]);

    let mut f = Vec::with_capacity(ETH_HDR + 28);
    f.extend_from_slice(sender_mac);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 2]);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&ip);
    f.extend_from_slice(sender_mac);
    f.extend_from_slice(sender_ip);
    Some(f)
}

pub fn client_ip_check(ip: u8) -> u8 {
        match ip.checked_sub(100) { 
            Some(addr) => {
                if addr > 63 { return 255 }
                addr
            }
            None => 255
        }
    }
