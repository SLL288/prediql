import json
import yaml


def flatten_type(type_obj):
    """
    Recursively flatten GraphQL type to SDL style notation.
    Handles NON_NULL, LIST, and base types.
    """
    if not type_obj:
        return ""
    kind = type_obj.get("kind")
    if kind == "NON_NULL":
        return f"{flatten_type(type_obj['ofType'])}!"
    if kind == "LIST":
        return f"[{flatten_type(type_obj['ofType'])}]"
    name = type_obj.get("name")
    return name or ""


def parse_operations(type_obj):
    """
    Extracts all operations (queries/mutations), producing:
    {
        operationName: {
            inputs: { paramName: Type! },
            output: Type!
        },
        ...
    }
    """
    results = {}
    fields = type_obj.get("fields") or []
    for field in fields:
        operation_name = field["name"]
        entry = {}

        # Inputs
        inputs = {}
        for arg in field.get("args", []):
            arg_name = arg["name"]
            arg_type = flatten_type(arg["type"])
            inputs[arg_name] = arg_type
        entry["inputs"] = inputs

        # Output
        output_type = flatten_type(field.get("type"))
        entry["output"] = output_type

        results[operation_name] = entry
    return results


def parse_object_types(all_types):
    """
    Extracts all INPUT_OBJECT and OBJECT types with their fields.
    {
        TypeName: {
            kind: OBJECT or INPUT_OBJECT,
            fields: [
                { name: fieldName, type: Type! },
                ...
            ]
        },
        ...
    }
    """
    objects = {}
    for t in all_types:
        kind = t.get("kind")
        name = t.get("name")
        if not name or kind not in ("OBJECT", "INPUT_OBJECT"):
            continue

        # Ignore internal GraphQL introspection types like __Type
        if name.startswith("__"):
            continue

        entry = {"kind": kind}
        fields = t.get("inputFields") if kind == "INPUT_OBJECT" else t.get("fields")
        if fields:
            entry["fields"] = []
            for field in fields:
                field_name = field["name"]
                field_type = flatten_type(field["type"])
                entry["fields"].append({
                    "name": field_name,
                    "type": field_type
                })
        objects[name] = entry
    return objects


def get_lists():
    # 1️⃣ Load Introspection JSON
    with open("introspection_result.json", encoding="utf-8") as f:
        introspection = json.load(f)
    schema = introspection["data"]["__schema"]
    all_types = schema["types"]

    # 2️⃣ Build name → type map
    type_map = {t["name"]: t for t in all_types if "name" in t}

    # 3️⃣ Identify Query/Mutation types safely
    query_type = schema.get("queryType")
    mutation_type = schema.get("mutationType")

    query_name = query_type.get("name") if query_type else None
    mutation_name = mutation_type.get("name") if mutation_type else None

    query_parameters = {}
    mutation_parameters = {}

    if query_name and query_name in type_map:
        query_parameters = parse_operations(type_map[query_name])

    if mutation_name and mutation_name in type_map:
        mutation_parameters = parse_operations(type_map[mutation_name])

    # 4️⃣ Extract all objects/input objects
    object_list = parse_object_types(all_types)

    # 5️⃣ Save to YAML
    with open("load_introspection/query_parameter_list.yml", "w", encoding="utf-8") as f:
        yaml.dump(query_parameters, f, sort_keys=False, allow_unicode=True)
    print("✅ Saved query_parameter_list.yml")

    if mutation_parameters:
        with open("load_introspection/mutation_parameter_list.yml", "w", encoding="utf-8") as f:
            yaml.dump(mutation_parameters, f, sort_keys=False, allow_unicode=True)
        print("✅ Saved mutation_parameter_list.yml")
    else:
        with open("load_introspection/mutation_parameter_list.yml", "w", encoding="utf-8") as f:
            f.write("# No mutations defined in schema\n{}\n")
        print("ℹ️ No mutations found. Wrote empty mutation_parameter_list.yml")

    with open("load_introspection/object_list.yml", "w", encoding="utf-8") as f:
        yaml.dump(object_list, f, sort_keys=False, allow_unicode=True)
    print("✅ Saved object_list.yml")
    return query_name, mutation_name, object_list


if __name__ == "__main__":
    get_lists()
