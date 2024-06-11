#[macro_use]
extern crate serde;
use std::cell::Cell;

use agreement::Agreement;
use candid::Principal;
use chrono::prelude::*;
use helpers::ToUser;
use ic_cdk::api::time;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BTreeMap, Cell as StableCell, DefaultMemoryImpl, Vec as VecStructure,
};
use lamport::{hash, verify};
use user::{Agree, CreateAgreement, User};

mod agreement;
mod helpers;
mod lamport;
mod signature;
mod user;

// Memory implementations
type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = StableCell<u64, Memory>;

thread_local! {
    static MEMORY_MANAGER: MemoryManager<DefaultMemoryImpl> = 
        MemoryManager::init(DefaultMemoryImpl::default());

    static USERS: BTreeMap<u64, User, Memory> = BTreeMap::init(
        MEMORY_MANAGER.with(|m| m.get(MemoryId::new(0))),
    );

    static AGREEMENTS: BTreeMap<u64, Agreement, Memory> = BTreeMap::init(
        MEMORY_MANAGER.with(|m| m.get(MemoryId::new(1))),
    );

    static USER_ID_COUNTER: IdCell = IdCell::init(
        MEMORY_MANAGER.with(|m| m.get(MemoryId::new(2))), 0
    ).expect("Cannot create a User counter");

    static AGREEMENT_ID_COUNTER: IdCell = IdCell::init(
        MEMORY_MANAGER.with(|m| m.get(MemoryId::new(3))), 0
    ).expect("Cannot create an Agreements counter");
}

impl ToUser for Principal {
    fn principal_to_user(principal: Principal) -> User {
        User { identity: principal.to_string() }
    }
}

fn create_new_agreement(
    terms: Vec<String>,
    with_user: String,
    id: u64,
    by_user: String,
) -> Agreement {
    let creator = Principal::principal_to_user(Principal::from_text("aMSCHEL").unwrap());
    let agreement = creator.new_agreement(
        terms,
        time().to_string(),
        Principal::principal_to_user(Principal::from_text(with_user).unwrap()),
        Principal::principal_to_user(Principal::from_text(by_user).unwrap()),
        id,
    );
    creator.automatic_agreement(agreement)
}

fn agree_to_agreement(user: String, agreement: Agreement) -> Agreement {
    let agreeing_party = Principal::principal_to_user(Principal::from_text(user).unwrap());
    agreeing_party.agree(agreement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreement_btwn_god_and_man() {
        let terms = vec![
            "I am the Lord thy God".to_string(),
            "Thou shalt have no other gods before me".to_string(),
            "Thou shalt not make unto thee any graven image".to_string(),
            "Thou shalt not take the name of the Lord thy God in vain".to_string(),
            "Remember the sabbath day, to keep it holy".to_string(),
            "Honour thy father and thy mother".to_string(),
            "Thou shalt not kill".to_string(),
            "Thou shalt not commit adultery".to_string(),
            "Thou shalt not steal".to_string(),
            "Thou shalt not bear false witness against thy neighbour".to_string(),
            "Thou shalt not covet thy neighbour's house".to_string(),
            "Thou shalt not covet thy neighbour's wife, nor his manservant, nor his maidservant, nor his ox, nor his ass, nor any thing that is thy neighbour's".to_string(),
        ];
        let agreement = create_new_agreement(terms, "God".to_string(), 1, "the heck".to_string());
        let amschel_agrees = agree_to_agreement("God".to_string(), agreement);
        dbg!(amschel_agrees.proof_of_agreement.unwrap().0.unwrap().value);
    }

    #[test]
    fn agree_to_agreement_works() {
        // Implement test
    }
}

#[ic_cdk::query]
fn check_status() -> String {
    "We are live".to_string()
}

#[ic_cdk::update]
fn initiate_agreement(terms: Vec<String>, with_user: String) -> Result<Agreement, Error> {
    let id = AGREEMENT_ID_COUNTER.with(|counter| {
        let counter_value = *counter.get();
        counter.set(counter_value + 1).unwrap();
        counter_value
    });

    let agreement = create_new_agreement(terms, with_user, id, ic_cdk::caller().to_string());

    match AGREEMENTS.with(|db| db.insert(id, agreement.clone())) {
        Some(_) | None => Ok(agreement),
    }
}

#[ic_cdk::update]
fn signup_user() -> String {
    let id = USER_ID_COUNTER.with(|counter| {
        let counter_value = *counter.get();
        counter.set(counter_value + 1).unwrap();
        counter_value
    });

    let user = User {
        identity: ic_cdk::caller().to_string(),
    };

    USERS.with(|db| {
        db.insert(id, user.clone());
    });

    format!("User {} created", user.identity)
}

#[ic_cdk::update]
fn agree_to(agreement_id: u64) -> Result<Agreement, Error> {
    let initial_agreement = AGREEMENTS.with(|storage| storage.get(&agreement_id).cloned());

    match initial_agreement {
        Some(agreement) => {
            let signed_agreement = agree_to_agreement(ic_cdk::caller().to_string(), agreement);

            AGREEMENTS.with(|storage| {
                storage.insert(agreement.id, signed_agreement.clone());
            });

            Ok(signed_agreement)
        }
        None => Err(Error::NotFound {
            msg: "That agreement was not found".to_string(),
        }),
    }
}

#[ic_cdk::update]
fn verify_signatures(agreement_id: u64) -> Result<bool, Error> {
    let agreement = AGREEMENTS.with(|storage| storage.get(&agreement_id).cloned());

    match agreement {
        Some(agreement) => {
            let message: String = agreement.terms.join("");

            if let (Some(sig1), Some(sig2), Some((key1, key2))) = (
                agreement.proof_of_agreement.as_ref().map(|p| p.0.as_ref().map(|s| s.value.clone())),
                agreement.proof_of_agreement.as_ref().map(|p| p.1.as_ref().map(|s| s.value.clone())),
                agreement.public_keys.as_ref().map(|k| (k.0.clone().unwrap(), k.1.clone().unwrap())),
            ) {
                let sig1_is_valid = verify(hash(&message), &sig1, &key1);
                let sig2_is_valid = verify(hash(&message), &sig2, &key2);

                Ok(sig1_is_valid && sig2_is_valid)
            } else {
                Err(Error::NotFound {
                    msg: "The agreement has incomplete signatures".to_string(),
                })
            }
        }
        None => Err(Error::NotFound {
            msg: "That agreement was not found".to_string(),
        }),
    }
}

#[ic_cdk::query]
fn get_my_agreements(user_id: u64) -> Result<Vec<Agreement>, Error> {
    let user = USERS.with(|storage| storage.get(&user_id).cloned());

    match user {
        Some(user) => {
            let all_agreements = AGREEMENTS.with(|storage| {
                storage.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()
            });

            let my_agreements: Vec<Agreement> = all_agreements
                .into_iter()
                .filter(|agreement| {
                    agreement.with_user.identity == user.identity
                        || agreement.by_user.identity == user.identity
                })
                .collect();

            Ok(my_agreements)
        }
        None => Err(Error::NotFound {
            msg: "User not found".to_string(),
        }),
    }
}

#[ic_cdk::query]
fn get_single_agreement(agreement_id: u64) -> Result<Agreement, Error> {
    let agreement = AGREEMENTS.with(|storage| storage.get(&agreement_id).cloned());

    match agreement {
        Some(agreement) => Ok(agreement),
        None => Err(Error::NotFound {
            msg: "Agreement not found".to_string(),
        }),
    }
}

#[derive(candid::CandidType, Deserialize, Serialize, Debug)]
enum Error {
    NotFound { msg: String },
}

ic_cdk::export_candid!();
