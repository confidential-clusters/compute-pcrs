// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
/*
 * We're receiving two event vectors that we don't know which PCR they
 * belong to.
 *
 * We need to combine events from vec "A" and "B" based on event groups.
 *
 * Let's say that vec A and B contain event ID "e1". e1 belongs to
 * groups g1 and g2.
 *   If the value of e1 doesn't change from A to B, it doesn't matter.
 *   If the value of e1 is different in A and B, then combinations must
 *   respect groups.
 *   That is, if e1 from A is chosen, all events "ei" that are from groups
 *   g1 or g2 must be chosen from A.
 *   Same applies for B.
 *   And all combinations must be calculated.
 *
 * Note that this kind of looks like an event tree at this point.
 * Each existing branch will be a possible solution to the problem.
 *
 * TODO:
 * - PROBLEM:
 *   Imagine that event "Ej" is the product of artifacts a1 and a2.
 *   The event tracking a1 belongs to g1 and a2 to g2.
 *   Ej belongs to g1 and g2.
 *   Choose g1 from event vec A and g2 from event vec B.
 *   How can you compute Ej? There's a conflict.
 *     If g1 and g2 are from A, then Ej is from A.
 *     If g1 and g2 are from B, then Ej is from B.
 *     If g1 is from A and g2 from B, Ej needs to be recomputed.
 *   PROBLEM
 *   Analysis:
 *     Only PCR7 contains multigroup events.
 *     They are combinations of sb variables, bootloader, and mokvars.
 *     It would require upgrading the bootloader while updating secureboot
 *     variables to hit this issue.
 *     Could it be possible, in that case, that a weird mix happens?
 *
 *  Solutions:
 *    - Raise an error that the operator knows. Enter into "recovery".
 *      - Operator asks for the events that need to be recomputed.
 *        - If each event could be computed separately, this would be easier.
 *        - If each event computation fn would take the same arguments as
 *          the rest, it would make it way more easier.
 *    - We could just insert some information about missing events in the tree.
 *      - For example: image_A groups mask + image_B groups mask + value =
 *        "MISSINGEVENTDUETOCONFLICT" or something like that.
 *      - We could even wrap the solution into a struct containing a vector of
 *        missing pieces, e.g. a vector of tuples containing
 *        [(solution_0, missing_event_0),(solution_1, missing_event_1),...,(solution_N, missing_event_N)]
 *        together with the vector of tpmevent vectors.
 *      - Operator would then need to check possible solutions,
 *        look for missing pieces and if there are, mount the images and take
 *        needed actions.
 *      - This would need another library interface such as
 *        compute_event(event_id: TPMEventID, path_A: &str, path_B: &str) -> TPMEvent
 *
 *
 *
 *
 * That means that if vec A and B contain event "i", and
 * We would split the whole problem into sub-problems per PCR number.
 * However, groups being applied can be cross-PCR. In other words, there are some event groups
 * First,
 *  - We need to know which PCRs we are dealing with.
*/
use std::collections::HashMap;

use super::*;
use crate::pcrs::Pcr;

#[cfg(test)]
mod tests;

pub fn combine(this: &[TPMEvent], that: &[TPMEvent]) -> Vec<Pcr> {
    let map_this = tpm_event_id_hashmap(this);
    let map_that = tpm_event_id_hashmap(that);

    let event = TPMEventID::PcrRootNodeEvent.next().unwrap();
    match event_subtree(&event, &map_this, &map_that, 0, 0) {
        Some(st) => st
            .iter()
            .flat_map(|t| t.branches())
            .map(|e| Pcr::compile_from(&e))
            .collect(),
        None => vec![],
    }
}

fn event_subtree(
    event_id: &TPMEventID,
    map_this: &HashMap<TPMEventID, TPMEvent>,
    map_that: &HashMap<TPMEventID, TPMEvent>,
    group_this: u32,
    group_that: u32,
) -> Option<Vec<tree::EventNode<TPMEvent>>> {
    // Groups can't overlap
    assert_eq!(group_this & group_that, 0);
    let opt_this = map_this.get(event_id);
    let opt_that = map_that.get(event_id);
    // Divergences contains tuples with events, and this/that masked groups
    let mut divs: Vec<(&TPMEvent, u32, u32)> = vec![];
    let mut nodes: Vec<tree::EventNode<TPMEvent>> = vec![];

    if let Some(event_this) = opt_this
        && let Some(event_that) = opt_that
    {
        if event_this == event_that {
            divs.push((event_this, group_this, group_that));
        } else {
            divs.push((event_this, group_this | event_id.groups(), group_that));
            divs.push((event_that, group_this, group_that | event_id.groups()));
        }
    } else if let Some(event_this) = opt_this {
        divs.push((event_this, group_this | event_id.groups(), group_that));
    } else if let Some(event_that) = opt_that {
        divs.push((event_that, group_this, group_that | event_id.groups()));
    }

    if divs.is_empty() {
        return event_subtree(
            &event_id.next()?,
            map_this,
            map_that,
            group_this,
            group_that,
        );
    }

    for (event, g_this, g_that) in divs {
        let mut node = tree::EventNode::<TPMEvent>::new(event.clone());
        if let Some(children) = event_subtree(&event_id.next()?, map_this, map_that, g_this, g_that)
        {
            for c in children {
                node.add_child(c);
            }
        }
        nodes.push(node);
    }

    Some(nodes)
}

fn tpm_event_id_hashmap(events: &[TPMEvent]) -> HashMap<TPMEventID, TPMEvent> {
    events.iter().map(|e| (e.id.clone(), e.clone())).collect()
}
