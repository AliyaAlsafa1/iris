use iris_datatypes::DnsTransaction;
use iris_core::protocols::stream::dns::Data;
use serde::Serialize;
use std::net::IpAddr;
use crate::hash_utils::hash_ip;

#[derive(Clone, Debug, Serialize)]
pub struct DnsFeatures {
    pub client_ip_hash:               u64,  // hash of querying client IP
    pub resolved_ip_hash_a:           u64,  // hash of first A record answer IP, 0 if none
    pub resolved_ip_hash_aaaa:        u64,  // hash of first AAAA record answer IP, 0 if none

    pub query_num_questions:          u16,  // number of questions in query section (typically 1)
    pub query_recursion_desired:      u8,   // RD bit set in query (0/1)
    pub has_query:                    u8,   // 1 if a query was observed, 0 if response-only

    pub has_response:                 u8,   // 1 if a response was observed, 0 if query-only
    pub response_code:                u8,   // RCODE: 0=NoError 1=FormErr 2=ServFail 3=NXDomain 4=NotImp 5=Refused
    pub response_authoritative:       u8,   // AA bit set in response (0/1)
    pub response_recursion_available: u8,   // RA bit set in response (0/1)
    pub response_num_answers:         u16,  // record count in Answer section
    pub response_num_nameservers:     u16,  // record count in Authority section
    pub response_num_additional:      u16,  // record count in Additional section

    pub answer_num_a:                 u16,  // A (IPv4) records in Answer
    pub answer_num_aaaa:              u16,  // AAAA (IPv6) records in Answer
    pub answer_num_cname:             u16,  // CNAME records in Answer
    pub answer_num_mx:                u16,  // MX records in Answer
    pub answer_num_ns:                u16,  // NS records in Answer
    pub answer_num_ptr:               u16,  // PTR records in Answer
    pub answer_num_soa:               u16,  // SOA records in Answer
    pub answer_num_srv:               u16,  // SRV records in Answer
    pub answer_num_txt:               u16,  // TXT records in Answer
    pub answer_num_unknown:           u16,  // Unknown-type records in Answer

    pub ns_num_ns:                    u16,  // NS records in Authority section
    pub ns_num_soa:                   u16,  // SOA records in Authority section (present on NXDOMAIN)
    pub ns_num_other:                 u16,  // other record types in Authority section

    pub additional_num_a:             u16,  // A records in Additional section
    pub additional_num_aaaa:          u16,  // AAAA records in Additional section
    pub additional_num_other:         u16,  // other record types in Additional section
}


impl DnsFeatures {
    pub fn from_dns(dns: &DnsTransaction, client_ip: IpAddr) -> Option<Self> {
        if dns.query.is_none() && dns.response.is_none() {
            return None;
        }

        let client_ip_hash = hash_ip(client_ip);

        // Extract first A and AAAA answer for join key
        let mut resolved_ip_hash_a    = 0u64;
        let mut resolved_ip_hash_aaaa = 0u64;
        if let Some(resp) = &dns.response {
            for rec in &resp.answers {
                match &rec.data {
                    Data::A(a) if resolved_ip_hash_a == 0 => {
                        resolved_ip_hash_a = hash_ip(IpAddr::V4(a.0));
                    }
                    Data::Aaaa(a) if resolved_ip_hash_aaaa == 0 => {
                        resolved_ip_hash_aaaa = hash_ip(IpAddr::V6(a.0));
                    }
                    _ => {}
                }
            }
        }

        let (query_num_questions, query_recursion_desired, has_query) =
            if let Some(q) = &dns.query {
                (q.num_questions, q.recursion_desired as u8, 1u8)
            } else {
                (0, 0, 0u8)
            };

        let (has_response, response_code, response_authoritative,
             response_recursion_available, response_num_answers,
             response_num_nameservers, response_num_additional) =
            if let Some(r) = &dns.response {
                (1u8,
                 match format!("{:?}", r.response_code).as_str() {
                     "NoError"        => 0u8,
                     "FormatError"    => 1,
                     "ServerFailure"  => 2,
                     "NameError"      => 3,
                     "NotImplemented" => 4,
                     "Refused"        => 5,
                     _                => 255,
                 },
                 r.authoritative as u8,
                 r.recursion_available as u8,
                 r.num_answers,
                 r.num_nameservers,
                 r.num_additional)
            } else {
                (0u8, 0, 0, 0, 0, 0, 0)
            };

        let mut answer_num_a       = 0u16;
        let mut answer_num_aaaa    = 0u16;
        let mut answer_num_cname   = 0u16;
        let mut answer_num_mx      = 0u16;
        let mut answer_num_ns      = 0u16;
        let mut answer_num_ptr     = 0u16;
        let mut answer_num_soa     = 0u16;
        let mut answer_num_srv     = 0u16;
        let mut answer_num_txt     = 0u16;
        let mut answer_num_unknown = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.answers {
                match &rec.data {
                    Data::A(_)     => answer_num_a       += 1,
                    Data::Aaaa(_)  => answer_num_aaaa    += 1,
                    Data::Cname(_) => answer_num_cname   += 1,
                    Data::Mx(_)    => answer_num_mx      += 1,
                    Data::Ns(_)    => answer_num_ns      += 1,
                    Data::Ptr(_)   => answer_num_ptr     += 1,
                    Data::Soa(_)   => answer_num_soa     += 1,
                    Data::Srv(_)   => answer_num_srv     += 1,
                    Data::Txt(_)   => answer_num_txt     += 1,
                    Data::Unknown  => answer_num_unknown += 1,
                }
            }
        }

        let mut ns_num_ns    = 0u16;
        let mut ns_num_soa   = 0u16;
        let mut ns_num_other = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.nameservers {
                match &rec.data {
                    Data::Ns(_)  => ns_num_ns  += 1,
                    Data::Soa(_) => ns_num_soa += 1,
                    _            => ns_num_other += 1,
                }
            }
        }

        let mut additional_num_a     = 0u16;
        let mut additional_num_aaaa  = 0u16;
        let mut additional_num_other = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.additionals {
                match &rec.data {
                    Data::A(_)    => additional_num_a    += 1,
                    Data::Aaaa(_) => additional_num_aaaa += 1,
                    _             => additional_num_other += 1,
                }
            }
        }

        Some(Self {
            client_ip_hash,
            resolved_ip_hash_a,
            resolved_ip_hash_aaaa,
            query_num_questions,
            query_recursion_desired,
            has_query,
            has_response,
            response_code,
            response_authoritative,
            response_recursion_available,
            response_num_answers,
            response_num_nameservers,
            response_num_additional,
            answer_num_a,
            answer_num_aaaa,
            answer_num_cname,
            answer_num_mx,
            answer_num_ns,
            answer_num_ptr,
            answer_num_soa,
            answer_num_srv,
            answer_num_txt,
            answer_num_unknown,
            ns_num_ns,
            ns_num_soa,
            ns_num_other,
            additional_num_a,
            additional_num_aaaa,
            additional_num_other,
        })
    }
}
