use const_format::concatcp;

pub const CONN_HEADER: &str =
    "first_seen_ts,src_ip_hash,dst_ip_hash,\
     src_ip_subn,dst_ip_subn,src_port,dst_port,protocol,\
     duration_ms,max_inactivity_ms,time_to_second_pkt_ms,\
     hist_syn,hist_synack,hist_ack,hist_data,hist_fin,hist_rst,\
     hist_syn_r,hist_synack_r,hist_ack_r,hist_data_r,hist_fin_r,hist_rst_r,\
     orig_nb_pkts,orig_nb_malformed_pkts,orig_nb_late_start_pkts,\
     orig_nb_pkt_bytes,orig_nb_payload_bytes,\
     orig_max_simult_gaps,orig_content_gaps,orig_missed_bytes,\
     orig_mean_pkts_to_fill,orig_median_pkts_to_fill,\
     resp_nb_pkts,resp_nb_malformed_pkts,resp_nb_late_start_pkts,\
     resp_nb_pkt_bytes,resp_nb_payload_bytes,\
     resp_max_simult_gaps,resp_content_gaps,resp_missed_bytes,\
     resp_mean_pkts_to_fill,resp_median_pkts_to_fill,\
     orig_iat_mean,orig_iat_median,orig_iat_min,orig_iat_max,orig_iat_std,\
     resp_iat_mean,resp_iat_median,resp_iat_min,resp_iat_max,resp_iat_std,\
     final_total_payload_bytes,final_duration_ms,final_total_pkts";

pub const DNS_HEADER: &str =
    "client_ip_hash,resolved_ip_hash_a,resolved_ip_hash_aaaa,\
     query_num_questions,query_recursion_desired,has_query,\
     has_response,response_code,response_authoritative,response_recursion_available,\
     response_num_answers,response_num_nameservers,response_num_additional,\
     answer_num_a,answer_num_aaaa,answer_num_cname,answer_num_mx,answer_num_ns,\
     answer_num_ptr,answer_num_soa,answer_num_srv,answer_num_txt,answer_num_unknown,\
     ns_num_ns,ns_num_soa,ns_num_other,\
     additional_num_a,additional_num_aaaa,additional_num_other";

pub const TLS_HEADER: &str =
    "has_client_hello,client_version,\
     client_num_supported_groups,client_num_sig_algs,client_num_alpn_protocols,\
     client_num_key_shares,client_num_supported_vers,\
     client_has_sni,client_sni_hash,client_sni_len,client_has_session_id,client_session_id_len,\
     client_has_compression,client_has_alpn,client_has_key_share,client_has_supported_vers,\
     has_server_hello,server_version,server_cipher_suite,\
     server_compression_alg,\
     server_has_alpn,server_has_key_share,server_has_selected_vers,\
     num_server_certs,num_client_certs,server_cert0_len,server_cert1_len,\
     has_server_kex,has_client_kex,kex_type";

pub const DNS_CONN_HEADER: &str = concatcp!(CONN_HEADER, ",", DNS_HEADER, "\n");
pub const TLS_CONN_HEADER: &str = concatcp!(CONN_HEADER, ",", TLS_HEADER, "\n");
pub const CONN_ONLY_HEADER: &str = concatcp!(CONN_HEADER, "\n");