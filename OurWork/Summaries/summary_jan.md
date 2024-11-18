# Nimble: Rollback Protection for Confidential Cloud Services
est
Authors: Sebastian Angel, Microsoft Research; Aditya Basu, Penn State University;
         Weidong Cui, Microsoft Research; Trent Jaeger, Penn State University;
         Stella Lau, MIT CSAIL; Srinath Setty, Microsoft Research;
         Sudheesh Singanamalla, University of Washington

## What is the problem?
Trusted Execution Environments (TEEs) allow a client's code to be executed in the cloud with guarantees that noone can see what is running of modify it without the client finding out.
The issue is that TEEs have no permanent storage and while signing your data to ensure it is unmodified is simple, there is no preventing that old data could be sent to you when requesting it (roll-back attack)
Nimble offers a solution to prove the TEE is receiving the most recent data.

## How does Nimble solve it?
Nimble runs a number of trusted endorsers in TEEs that keep track of the most recent state and sign it.
Whenever a client requests data, it sends that request to an coordinator, which then contacts the endorsers and from multiple endorser responses can assemble a receipt to prove that the majority of (trusted) endorsers agree on the most recent state.
The state is stored in untrusted storage (existing solution, not part of Nimble) in the form of an append-only ledger, meaning old data can not be removed or changed.
To ensure that no old endorser messages can be replayed, the client provides a nonce that has to be included in the endorser's responses
When appending data, the client sets the index in the blockchain and includes that information in its signature of the data, therefore an attacker cannot send old data and pass it off as newer than it is, because the index of the latest entry to the ledger is included in the (trusted) signature of the endorser. Every node also includes a hash of the previous node, therefore insuring that no data can be inserted illegaly.
Because a valid receipt has to include a quorum of endorsers that includes at least a majority, there is always a single valid state and order of nodes.

## Reconfiguration
One key feature of Nimble is the ability to change the running endorsers without breaking the safety guarantees, allowing for planned maintenance and unplanned crashes to occur without interrupting service.
To do it, there are three main functions. First the coordinator must bootstrap any new endorsers needed. Then the old endorsers are required to finalize, this means, that they have to sign off on the current state, the id of the ledger, as well as the current and future group of endorsers. Afterwards they delete their key. If the endorsers lag behind, the coordinator can append the neccessary blocks first. Because the information in the blocks is both, signed by the client and includes its own index, neither the content of the blocks, nor their order can be changed and also no new blocks appended by the coordinator.
Because the finalized endorsers delete their private keys, no new blocks can be appended by them.
To activate the new endorsers, the coordinator must provide the receipt that proves that a quorum of old endorsers agreed on a final state and signed off on this endorser being part of the new active group.

## Liveness
If some endorsers cannot be reached, then the read requests are cached and will be processed at a later date.
If an endorser is behind the rest in appends, the coodinator can append the missing blocks to make it catch up. The blocks must be the correct ones, because every block includes a hash of the previous one,
therefore if any data were to be changed by the coordinator, then the tail will change.

## Implementation
The Coordinator is implemented in Rust. One endorser implementation with all features is also written in Rust and one without reconfiguration capability is written in C++.
There is also an endpoint written in Rust that implements all the verfication logic required from the client. Therefore both the endorser and endpoint have to run in a TEE and be trusted.

## Limitations
Nimble is always limited by the speed of the untrusted storage service it runs on. Also if the majority of endorsers crash, the ledger can never be modified again.


## Comparison to other solutions
There are other solutions to this problem, but most either do not offer the same features, or require a much larger Trusted Compute Base, making auditing it much more difficult.
Nimbles core protocol was even proven to be safe.
