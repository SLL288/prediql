import yaml
import os

class GraphQLPromptBuilder:
    def __init__(self,
                 parameter_file_path="load_introspection/query_parameter_list.yml",
                 object_file_path="load_introspection/object_list.yml"):
        """
        Load parameter and object definition files once.
        """
        self.parameter_data = self._load_yaml(parameter_file_path)
        self.all_objects_data = self._load_yaml(object_file_path)
        print(f"✅ Loaded {len(self.parameter_data)} endpoints from parameters file.")
        print(f"✅ Loaded {len(self.all_objects_data)} object types from objects file.")

    def _load_yaml(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"YAML file not found: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _strip_wrappers(type_string):
        if not type_string:
            return None
        return (
            type_string
            .replace('[', '')
            .replace(']', '')
            .replace('!', '')
            .strip()
        )

    def _collect_relevant_objects(self, param_types):
        """
        Recursively collect all relevant input objects.
        """
        relevant = {}

        def collect(type_name):
            type_name = self._strip_wrappers(type_name)
            if not type_name or type_name in relevant:
                return
            definition = self.all_objects_data.get(type_name)
            if not definition:
                return
            relevant[type_name] = definition
            fields = definition.get("inputFields") or definition.get("fields") or []
            for field in fields:
                field_type = field.get("type")
                collect(field_type)

        for t in param_types:
            collect(t)

        return relevant

    def _format_input_objects(self, objects_dict):
        """
        Format input objects as GraphQL SDL.
        """
        lines = []
        for type_name, definition in objects_dict.items():
            kind = definition.get('kind', '').upper()
            if kind != "INPUT_OBJECT":
                continue
            lines.append(f"input {type_name} {{")
            fields = definition.get("inputFields", [])
            for field in fields:
                fname = field.get("name")
                ftype = field.get("type")
                lines.append(f"  {fname}: {ftype}")
            lines.append("}\n")
        return "\n".join(lines)

    def _format_parameters(self, parameters):
        """
        Format parameters for the prompt.
        """
        if not parameters:
            return "(No parameters)"
        lines = [f"{name}: {details.get('type')}" for name, details in parameters.items()]
        return "\n".join(lines)

    def get_prompt_for_node(self, node_name):
        """
        Returns a complete LLM prompt for the given node.
        """
        parameters = self.parameter_data.get(node_name) or {}
        if not parameters:
            return f"⚠️ No parameters found for endpoint '{node_name}'. Cannot generate prompt."

        param_types = [details.get('type') for details in parameters.values()]
        relevant_objects = self._collect_relevant_objects(param_types)
        prompt_objects_block = self._format_input_objects(relevant_objects)
        prompt_parameters_block = self._format_parameters(parameters)

        final_prompt = f"""
You are testing the GraphQL endpoint **{node_name}**.

***Parameters:***
{prompt_parameters_block}

***Input Object Definitions:***
{prompt_objects_block}

Please generate valid GraphQL queries that conform strictly to these definitions and use realistic concrete values.
"""
        # return final_prompt
        return prompt_parameters_block, prompt_objects_block


if __name__ == "__main__":
    builder = GraphQLPromptBuilder()
    parameters, object = builder.get_prompt_for_node("contact")

    print(f"parameters: {parameters}")
    print(f"objects: {object}")
