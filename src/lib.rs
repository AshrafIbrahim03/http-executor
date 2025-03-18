use std::{
    borrow::BorrowMut,
    cell::RefCell,
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    sync::Mutex,
};

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{hooks::ExecutorHooksTuple, Executor, ExitKind, HasObservers},
    feedbacks::{Feedback, StateInitializer},
    inputs::{Input, UsesInput},
    observers::{self, ObserversTuple},
    state::{HasExecutions, State, UsesState},
    HasMetadata, HasNamedMetadata, HasObjective, SerdeAny,
};
use libafl_bolts::{serdeany::SerdeAny, tuples::RefIndexable, Named};
use reqwest::{blocking::Response, header::HeaderValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum HTTPVerb {
    GET,
    POST,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    PUT,
    PATCH,
    CONNECT,
}
#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct HTTPExitKind {
    pub exitkind: ExitKind,
    pub method: HTTPVerb,
    pub body: String,
    pub host: Option<String>,
    pub useragent: Option<String>,
    pub content_type: Option<String>,
    pub response_code: u16,
}

#[derive(Debug)]
pub enum ComponentError {
    ParseError,
}

impl Display for ComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentError::ParseError => f.write_str("parse-error"),
        }
    }
}
impl Error for ComponentError {}

pub trait EKLogic {
    /// This function takes in a response and maps it to an ExitKind
    fn define_exitkind(&self, response: &Option<Response>) -> ExitKind;
}

pub struct StatusLogic {
    status_of_interest: Vec<u16>,
}
impl StatusLogic {
    pub fn new<T>(inp: T) -> Self
    where
        T: IntoIterator<Item = u16>,
    {
        Self {
            status_of_interest: inp.into_iter().collect(),
        }
    }
}
impl EKLogic for StatusLogic {
    fn define_exitkind(&self, response: &Option<Response>) -> ExitKind {
        if let Some(r) = response {
            if self
                .status_of_interest
                .iter()
                .any(|s| *s == r.status().as_u16())
            {
                return ExitKind::Crash;
            }
        }
        ExitKind::Ok
    }
}

pub struct HTTPExecutor<H, HB, OT, S, EKL, HM>
where
    H: FnMut(&S::Input) -> Option<Response> + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasMetadata + HasExecutions,
    EKL: EKLogic,
    HM: HasHashMap<u64, Box<Option<Response>>>,
{
    harness_fn: HB,
    observers: OT,
    eklogic: EKL,
    run_map: HM,

    phantom: PhantomData<(*const H, HB, S, EKL)>,
}

impl<H, HB, OT, S, EKL, HM> HasObservers for HTTPExecutor<H, HB, OT, S, EKL, HM>
where
    H: FnMut(&S::Input) -> Option<Response> + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasMetadata + HasExecutions,
    EKL: EKLogic,
    HM: HasHashMap<u64, Box<Option<Response>>>,
{
    type Observers = OT;

    fn observers(&self) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(
        &mut self,
    ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<H, HB, OT, S, EKL, HM> HTTPExecutor<H, HB, OT, S, EKL, HM>
where
    H: FnMut(&S::Input) -> Option<Response> + Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasMetadata + HasExecutions,
    EKL: EKLogic,
    HM: HasHashMap<u64, Box<Option<Response>>>,
{
    pub fn new<EM, OF, Z>(harness: HB, observers: OT, eklogic: EKL, hash_state: HM) -> Self
    where
        EM: EventFirer<State = S> + EventRestarter,
        Self: Executor<EM, Z, State = S> + HasObservers,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF>,
    {
        Self {
            harness_fn: harness,
            observers,
            eklogic,
            phantom: PhantomData,
            run_map: hash_state,
        }
    }
}

impl<H, HB, OT, S, EKL, HM> UsesState for HTTPExecutor<H, HB, OT, S, EKL, HM>
where
    H: FnMut(&S::Input) -> Option<Response> + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasMetadata + HasExecutions,
    EKL: EKLogic,
    HM: HasHashMap<u64, std::boxed::Box<Option<Response>>>,
{
    type State = S;
}

impl<EM, H, HB, OT, S, Z, EKL, HM> Executor<EM, Z> for HTTPExecutor<H, HB, OT, S, EKL, HM>
where
    H: FnMut(&S::Input) -> Option<Response> + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasExecutions + HasNamedMetadata + HasMetadata,
    EM: UsesState<State = S>,
    EKL: EKLogic,
    HM: HasHashMap<u64, std::boxed::Box<Option<Response>>>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;
        //unsafe {
        //let executor_ptr = ptr::from_ref(self) as *const c_void;
        //           self.inner
        //              .enter_target(fuzzer, state, mgr, input, executor_ptr);
        //}
        //     self.inner.hooks.pre_exec_all(state, input);
        self.observers.pre_exec_all(state, input)?;

        let ret: Option<Response> = self.harness_fn.borrow_mut()(input);
        let ek = self.eklogic.define_exitkind(&ret);
        let response = Box::new(ret);
        let _ = self.run_map.add_entry(*state.executions(), response);
        state.add_named_metadata(&state.executions().to_string(), ek);

        self.observers.post_exec_all(state, input, &ek)?;

        //    self.inner.hooks.post_exec_all(state, input);
        //   self.inner.leave_target(fuzzer, state, mgr, input);
        Ok(ek)
    }
}
#[derive(Debug)]
pub enum HashMapStateError<U>
where
    U: Eq + Hash,
{
    /// This error is used when adding an entry, it returns the key that was input to indicate
    /// which key was already present
    KeyAlreadyPresent(U),
    /// This error happens when something happens that makes it so that the program can't access
    /// the mutex lock. This should be uncommon
    CouldNotAcquireMap,
    /// This error happens when remove an entry. If a key is not present, then it can't be removed
    /// therefore this error
    KeyNotPresent,
}

impl<U> std::fmt::Display for HashMapStateError<U>
where
    U: Eq + Hash + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashMapStateError::KeyAlreadyPresent(k) => write!(f, "KeyAlreadyPresent({})", k),
            HashMapStateError::CouldNotAcquireMap => f.write_str("CouldNotAcquireMap"),
            HashMapStateError::KeyNotPresent => f.write_str("KeyNotPresent"),
        }
    }
}
impl<U> Error for HashMapStateError<U> where U: Eq + Hash + Display + Debug {}
pub trait HasHashMap<U, T>
where
    U: Eq + Hash,
{
    fn new() -> Self;
    fn add_entry(&self, key: U, value: T) -> Result<(), HashMapStateError<U>>;
    fn remove_entry(&self, key: U) -> Result<(U, T), HashMapStateError<U>>;
}

pub struct HashMapState<U, T>
where
    U: Eq + Hash + Debug,
{
    map: Mutex<std::collections::HashMap<U, T>>,
}

impl<U, T> HasHashMap<U, T> for HashMapState<U, T>
where
    U: Eq + Hash + Debug + Copy,
{
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
    fn add_entry(&self, key: U, value: T) -> Result<(), HashMapStateError<U>> {
        if let Ok(mut m) = self.map.lock() {
            let ret: Option<T> = m.insert(key, value);
            return match ret {
                Some(_) => Err(HashMapStateError::KeyAlreadyPresent(key)),
                None => Ok(()),
            };
        }
        Err(HashMapStateError::CouldNotAcquireMap)
    }

    fn remove_entry(&self, key: U) -> Result<(U, T), HashMapStateError<U>> {
        if let Ok(mut m) = self.map.lock() {
            let ret: Option<(U, T)> = m.remove_entry(&key);
            return match ret {
                Some(success) => Ok(success),
                None => Err(HashMapStateError::KeyNotPresent),
            };
        }
        Err(HashMapStateError::CouldNotAcquireMap)
    }
}

pub struct HTTPCodeFeedback {
    name: std::borrow::Cow<'static, str>,
    codes: Vec<u16>,
}
impl HTTPCodeFeedback {
    pub fn new<St, V>(name: St, codes: V) -> Self
    where
        St: ToString,
        V: Into<Vec<u16>>,
    {
        HTTPCodeFeedback {
            name: name.to_string().into(),
            codes: codes.into(),
        }
    }
}
impl Named for HTTPCodeFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for HTTPCodeFeedback {}
impl<EM, I, OT, S> Feedback<EM, I, OT, S> for HTTPCodeFeedback
where
    S: State + HasNamedMetadata + HasMetadata + HasExecutions,
    EM: UsesState<State = S>,
    I: Input,
    OT: ObserversTuple<S::Input, S>,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        let run = _state.executions().to_string();
        let http_info: &HTTPExitKind = _state.named_metadata(run.as_str())?;
        let is_interesting = self
            .codes
            .iter()
            .any(|code| *code == http_info.response_code);
        Ok(is_interesting)
    }
}
