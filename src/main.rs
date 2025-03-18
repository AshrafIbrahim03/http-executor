use std::time::Duration;

use http_executor::{
    HTTPCodeFeedback, HTTPExecutor, HTTPExitKind, HasHashMap, HashMapState, StatusLogic,
};
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    generators::RandBytesGenerator,
    inputs::{BytesInput, ValueInput},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    nonzero,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use reqwest::blocking::{Client, Response};
const TIMEOUT: u64 = 1000;

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_millis(TIMEOUT))
        .build()
        .expect("Could not build client ");
    let target_url = "http://scanme.nmap.org";
    let mut harness =
        |input: &BytesInput| -> Option<Response> { client.get(target_url).send().ok() };

    let mut feedback = HTTPCodeFeedback::new("feedback", [404, 200]);
    let state = StdState::new(
        StdRand::with_seed(1),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new("./crashes").expect("could not create crashes directory"),
        &mut feedback,
        &mut (),
    )
    .expect("could not make state");
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, (), ());

    let status_logic = StatusLogic::new([404]);
    let mut executor = HTTPExecutor::new(
        &mut harness,
        tuple_list!(),
        status_logic,
        HashMapState::new(),
    );

    let mut generator = RandBytesGenerator::new(nonzero!(1));
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Could not create initial inputs");

    let input = BytesInput::new(Vec::from("abc"));
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 10);
}
