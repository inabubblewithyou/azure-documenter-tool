import json
import logging

def load_audit_data(filepath):
    """Loads audit data from a JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Successfully loaded data from {filepath}")
        return data
    except FileNotFoundError:
        logging.error(f"Audit file not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {filepath}: {e}")
        return None
    except Exception as e:
        logging.error(f"Failed to load audit file {filepath}: {e}")
        return None

def compare_lists_by_id(list1, list2, id_key='id', name_key='name'):
    """Compares two lists of dictionaries based on a unique ID key.

    Identifies added, removed, and potentially modified items.
    Modification check is basic: checks if the dictionaries are identical.
    Assumes items in the list have the specified id_key.
    """
    dict1 = {item.get(id_key): item for item in list1 if item.get(id_key)}
    dict2 = {item.get(id_key): item for item in list2 if item.get(id_key)}

    added_ids = set(dict2.keys()) - set(dict1.keys())
    removed_ids = set(dict1.keys()) - set(dict2.keys())
    common_ids = set(dict1.keys()) & set(dict2.keys())

    added = [dict2[id] for id in added_ids]
    removed = [dict1[id] for id in removed_ids]
    modified = [] # List of tuples: (item_before, item_after)
    unchanged = []

    for id in common_ids:
        item1 = dict1[id]
        item2 = dict2[id]
        # Basic modification check: compare entire dictionaries
        # TODO: Implement more granular checks (e.g., specific fields like tags, location)
        if item1 != item2:
            modified.append({"id": id, "name": item1.get(name_key, id), "before": item1, "after": item2})
        else:
             unchanged.append(item1)

    logging.debug(f"Comparison results: Added={len(added)}, Removed={len(removed)}, Modified={len(modified)}, Unchanged={len(unchanged)}")
    return {"added": added, "removed": removed, "modified": modified, "unchanged": unchanged}

def analyze_delta(data1, data2):
    """Analyzes the differences between two audit data sets."""
    delta = {
        "subscriptions": {
            "added": [],
            "removed": [],
            "details": {}
        }
    }

    subs1 = set(data1.keys())
    subs2 = set(data2.keys())

    added_subs = subs2 - subs1
    removed_subs = subs1 - subs2
    common_subs = subs1 & subs2

    delta["subscriptions"]["added"] = [data2[sub_id].get("subscription_info", {"id": sub_id}) for sub_id in added_subs]
    delta["subscriptions"]["removed"] = [data1[sub_id].get("subscription_info", {"id": sub_id}) for sub_id in removed_subs]

    logging.info(f"Subscription Changes: Added={len(added_subs)}, Removed={len(removed_subs)}, Common={len(common_subs)}")

    for sub_id in common_subs:
        logging.info(f"Analyzing delta for subscription: {sub_id}")
        sub_delta = {}
        sub_data1 = data1[sub_id]
        sub_data2 = data2[sub_id]

        # Handle cases where one of the subs might have errored out previously
        if "error" in sub_data1 or "error" in sub_data2:
             logging.warning(f"Skipping detailed delta for {sub_id} due to error in one of the audits.")
             sub_delta["error"] = "Error present in one of the audits."
             delta["subscriptions"]["details"][sub_id] = sub_delta
             continue

        # Compare Resources
        resources1 = sub_data1.get("resources", [])
        resources2 = sub_data2.get("resources", [])
        sub_delta["resources"] = compare_lists_by_id(resources1, resources2)
        logging.info(f"  Resources Delta: +{len(sub_delta['resources']['added'])}, -{len(sub_delta['resources']['removed'])}, ~{len(sub_delta['resources']['modified'])}")

        # Compare Networking (VNets, Subnets, Peerings, NSGs)
        net1 = sub_data1.get("networking", {})
        net2 = sub_data2.get("networking", {})
        sub_delta["networking"] = {}
        sub_delta["networking"]["vnets"] = compare_lists_by_id(net1.get("vnets", []), net2.get("vnets", []))
        sub_delta["networking"]["subnets"] = compare_lists_by_id(net1.get("subnets", []), net2.get("subnets", []))
        sub_delta["networking"]["peerings"] = compare_lists_by_id(net1.get("peerings", []), net2.get("peerings", []))
        sub_delta["networking"]["nsgs"] = compare_lists_by_id(net1.get("nsgs", []), net2.get("nsgs", []))
        logging.info(f"  VNets Delta: +{len(sub_delta['networking']['vnets']['added'])}, -{len(sub_delta['networking']['vnets']['removed'])}, ~{len(sub_delta['networking']['vnets']['modified'])}")
        # Add logging for other network elements if needed

        # TODO: Compare Security (RBAC, Score)
        # RBAC comparison is complex due to potential scope changes and principal resolution

        # TODO: Compare Costs (might not be meaningful for delta unless comparing specific dates)

        # TODO: Compare Governance (Policy States, Advisor Recs)
        gov1 = sub_data1.get("governance", {})
        gov2 = sub_data2.get("governance", {})
        sub_delta["governance"] = {}
        # Policy state comparison needs careful handling - using resource_id + policy_definition_id? Or policy_state ID?
        # Let's try resource_id + policy_definition_id as a composite key for comparison
        def get_policy_key(state): return f"{state.get('resource_id')}_{state.get('policy_definition_id')}"
        policy_states1 = [{**item, 'comparison_key': get_policy_key(item)} for item in gov1.get("policy_states", [])]
        policy_states2 = [{**item, 'comparison_key': get_policy_key(item)} for item in gov2.get("policy_states", [])]
        sub_delta["governance"]["policy_states"] = compare_lists_by_id(policy_states1, policy_states2, id_key='comparison_key', name_key='policy_definition_name')

        # Advisor recommendations comparison - use recommendation ID?
        recs1 = gov1.get("advisor_recommendations", [])
        recs2 = gov2.get("advisor_recommendations", [])
        sub_delta["governance"]["advisor_recommendations"] = compare_lists_by_id(recs1, recs2, id_key='id', name_key='short_description')
        logging.info(f"  Policy Delta: +{len(sub_delta['governance']['policy_states']['added'])}, -{len(sub_delta['governance']['policy_states']['removed'])}, ~{len(sub_delta['governance']['policy_states']['modified'])}")
        logging.info(f"  Advisor Delta: +{len(sub_delta['governance']['advisor_recommendations']['added'])}, -{len(sub_delta['governance']['advisor_recommendations']['removed'])}, ~{len(sub_delta['governance']['advisor_recommendations']['modified'])}")


        delta["subscriptions"]["details"][sub_id] = sub_delta

    logging.info("Delta analysis complete.")
    return delta
