use crate::conn_features::ConnFeatures;
use crate::dns_features::DnsFeatures;
use crate::tls_features::TlsFeatures;
use crate::headers::{CONN_ONLY_HEADER, TLS_CONN_HEADER, DNS_CONN_HEADER};
use array_init::array_init;
use csv::Writer;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;
use iris_core::CoreId;

const NUM_CORES: usize = 32;
const ARR_LEN: usize = NUM_CORES + 1;

fn serialize_pair<A, B>(
    writer: &mut Writer<BufWriter<File>>,
    a: &A,
    b: &B,
) -> csv::Result<()>
where
    A: Serialize,
    B: Serialize,
{
    let row_a = struct_to_record(a)?;
    let row_b = struct_to_record(b)?;
    let combined: csv::StringRecord = row_a.iter().chain(row_b.iter()).collect();
    writer.write_record(&combined)
}

fn struct_to_record<T: Serialize>(val: &T) -> csv::Result<csv::StringRecord> {
    let mut buf = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(vec![]);
    buf.serialize(val)?;
    let data = buf.into_inner().map_err(|e| {
        csv::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    })?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(data.as_slice());
    rdr.records()
        .next()
        .unwrap_or_else(|| Ok(csv::StringRecord::new()))
}

struct CSVWriters {
    prefix: &'static str,
    header: &'static str,
    writers: OnceLock<[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN]>,
}

impl CSVWriters {
    const fn new(prefix: &'static str, header: &'static str) -> Self {
        Self { prefix, header, writers: OnceLock::new() }
    }

    fn init(&self) -> &[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN] {
        self.writers.get_or_init(|| {
            let ptrs: Vec<_> = (0..ARR_LEN)
                .map(|core| {
                    let path = format!("{}{}.csv", self.prefix, core);
                    let file = File::create(&path).unwrap();
                    let w = csv::WriterBuilder::new()
                        .has_headers(false)
                        .from_writer(BufWriter::new(file));
                    Box::into_raw(Box::new(w))
                })
                .collect();
            array_init(|i| AtomicPtr::new(ptrs[i]))
        })
    }

    fn writer_for(&self, core: &CoreId) -> &mut Writer<BufWriter<File>> {
        let ptr = self.init()[core.raw() as usize].load(Ordering::Relaxed);
        unsafe { &mut *ptr }
    }

    fn write_row<T: Serialize>(&self, row: &T, core: &CoreId) {
        self.writer_for(core).serialize(row).unwrap();
    }

    fn write_pair<A, B>(&self, a: &A, b: &B, core: &CoreId)
    where
        A: Serialize,
        B: Serialize,
    {
        serialize_pair(self.writer_for(core), a, b).unwrap();
    }

    fn flush_and_combine(&self, outfile: &str) {
        println!("Combining results from {} cores into {}...", ARR_LEN, outfile);
        let mut out = BufWriter::new(File::create(outfile).unwrap());
        out.write_all(self.header.as_bytes()).unwrap();

        let writers = self.init();
        for core in 0..ARR_LEN {
            let ptr = writers[core].load(Ordering::Relaxed);
            let writer = unsafe { &mut *ptr };
            writer.flush().unwrap();

            let path = format!("{}{}.csv", self.prefix, core);
            std::io::copy(&mut File::open(&path).unwrap(), &mut out).unwrap();
            std::fs::remove_file(&path).unwrap();
        }

        println!("Done. Written to {}", outfile);
    }
}

static REGULAR: CSVWriters = CSVWriters::new("flow_features_",     CONN_ONLY_HEADER);
static TLS:     CSVWriters = CSVWriters::new("flow_features_tls_", TLS_CONN_HEADER);
static DNS:     CSVWriters = CSVWriters::new("flow_features_dns_", DNS_CONN_HEADER);

/// Public API
pub fn write(features: &ConnFeatures, core: &CoreId) {
    REGULAR.write_row(features, core);
}

pub fn write_tls(conn: &ConnFeatures, tls: &TlsFeatures, core: &CoreId) {
    TLS.write_pair(conn, tls, core);
}

pub fn write_dns(conn: &ConnFeatures, dns: &DnsFeatures, core: &CoreId) {
    DNS.write_pair(conn, dns, core);
}

pub fn combine() {
    REGULAR.flush_and_combine("flow_features.csv");
    TLS.flush_and_combine("flow_features_tls.csv");
    DNS.flush_and_combine("flow_features_dns.csv");
}
