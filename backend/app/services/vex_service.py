import subprocess
from typing import Any
from datetime import datetime
from json import dumps
from bson import ObjectId

from .dbs.databases import get_collection


async def create_vex(vex: dict[str, Any]) -> str:
    vexs_collection = get_collection("vexs")
    result = await vexs_collection.replace_one({"owner": vex["owner"], "name": vex["name"], "sbom_path": vex["sbom_path"]}, vex, upsert=True)
    return result.upserted_id


async def read_vex_by_id(vex_id: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"_id": ObjectId(vex_id)})

async def read_vex_moment_by_owner_name_sbom_path(owner: str, name: str, sbom_path: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    return await vexs_collection.find_one({"owner": owner, "name": name, "sbom_path": sbom_path})

async def ingest_vex(vex_id: str) -> dict[str, Any]:
    vexs_collection = get_collection("vexs")
    vex = await vexs_collection.find_one({"_id": ObjectId(vex_id)})
    extended_vex = vex["extended_vex"]
    with open("extended_vex_pre.json", "w") as f:
        f.write(dumps(extended_vex, indent=2))
    parsed_vex = parse_vex(extended_vex)
    save_vex(parsed_vex)
    call_guac()
    return parsed_vex

def save_vex(parsed_vex):
    with open("extended_vex.json", "w") as f:
        f.write(dumps(parsed_vex, indent=2))

def call_guac():
    # Show extended_vex.json
    """
    with open("extended_vex.json", "r") as f:
        print(f.read())
    """
    subprocess.run(["./guacone", "collect", "files", "./extended_vex.json", "--gql-addr", "http://guac-graphql:8080/query"])

def parse_vex(vex_json):
    vex = vex_json

    # Parsear las fechas del inicio del documento
    try:
        vex['timestamp'] = parse_and_format_time(vex['timestamp'])
        vex['last_updated'] = parse_and_format_time(vex['last_updated'])
    except Exception as e:
        raise RuntimeError(f"Error al formatear timestamps principales: {e}")


    # Parseo de cada statement
    for statement in vex.get("extended_statements", []):

        # Parsear las fechas del statement
        try:
            statement['timestamp'] = parse_and_format_time(statement['timestamp'])
            statement['last_updated'] = parse_and_format_time(statement['last_updated'])
        except Exception as e:
            raise RuntimeError(f"Error al formatear timestamps en statement {i}: {e}")


        # Añadir el campo affected_component_manager si no existe
        if "supplier" in statement:
            statement["affected_component_manager"] = statement["supplier"]
            del statement["supplier"]
        else:
            statement["affected_component_manager"] = "Unknown"

        status = ["fixed", "not affected", "affected", "under_investigation"]

        if statement["status"] not in status:
            statement["status"] = "under_investigation"

        if "cwes" in statement["vulnerability"]:
            for cwe in statement["vulnerability"]["cwes"]:
                if "consequences" in cwe:
                    if isinstance(cwe["consequences"], list):
                        cwe["consequences"] = [normalize_scope_and_impact(consequence) for consequence in cwe["consequences"]]
                    else:
                        cwe["consequences"] = [normalize_scope_and_impact(cwe["consequences"])]


                if "detection_methods" in cwe:

                    if isinstance(cwe["detection_methods"], dict):
                        cwe["detection_methods"] = [cwe["detection_methods"]]

                    for detection_method in cwe["detection_methods"]:
                        if "Description" in detection_method:
                            description = detection_method["Description"]
                            if isinstance(description, (dict)):  
                                detection_method["Description"] = remove_xhtml(description)
                                
                if "demonstrative_examples" in cwe:
                    cwe["demonstrative_examples"] = parse_demonstrative_exmaples(cwe["demonstrative_examples"])

                if "potential_mitigations" in cwe:

                    if isinstance(cwe["potential_mitigations"], dict):
                        cwe["potential_mitigations"] = [cwe["potential_mitigations"]]

                    for mitigation in cwe["potential_mitigations"]:
                        if "Description" in mitigation:
                            description = mitigation["Description"]
                            if isinstance(description, (dict)):  
                                mitigation["Description"] = remove_xhtml(description)

                        if "Effectiveness" not in mitigation:
                            mitigation["Effectiveness"] = "Unknown"

                        if "Phase" in mitigation and isinstance(mitigation["Phase"], list):
                            mitigation["Phase"] = ', '.join(mitigation["Phase"])

                        if "Effectiveness_Notes" in mitigation:
                            effectiveness_notes = mitigation["Effectiveness_Notes"]
                            if isinstance(effectiveness_notes, (dict)):  
                                mitigation["Effectiveness_Notes"] = remove_xhtml(effectiveness_notes)

                if "description" in cwe:
                    cwe["description"] = ""
        # Parsear exploits

        if "exploits" in statement:
            for exploit in statement["exploits"]:
                if "payload" in exploit:
                        exploit["payload"] = remove_xhtml(exploit["payload"])
    return vex


def extract_text(description):
    def recursive_extract(value):
        if isinstance(value, dict):
            return ' '.join(recursive_extract(v) for v in value.values())
        elif isinstance(value, list):
            return ' '.join(recursive_extract(item) for item in value)
        elif isinstance(value, str):
            return value
        return ''

    return recursive_extract(description).strip()


def normalize_scope_and_impact(consequence):
    if isinstance(consequence["Scope"], str):
        consequence["Scope"] = [consequence["Scope"]]
    if isinstance(consequence["Impact"], str):
        consequence["Impact"] = [consequence["Impact"]]
    return consequence


def parse_and_format_time(original):
    try:
        dt = datetime.strptime(original, "%Y-%m-%d %H:%M:%S.%f")
        rfc3339 = dt.astimezone().isoformat(timespec='microseconds')
        if rfc3339.endswith("+00:00"):
            rfc3339 = rfc3339.replace("+00:00", "Z")
        return rfc3339
    except ValueError as e:
        raise ValueError(f"Error al parsear la fecha '{original}': {e}")
    
def parse_demonstrative_exmaples(ejemplos):
    nuevos_ejemplos = []

    for ejemplo in ejemplos:
        if isinstance(ejemplo, dict):
            valores_concatenados = ' '.join(str(v) for v in ejemplo.values())
            nuevos_ejemplos.append(valores_concatenados)
        else:
            nuevos_ejemplos.append(str(ejemplo))  # Por si acaso hay algo que no sea dict

    return nuevos_ejemplos


def remove_xhtml(data):
    if isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            if key.startswith("xhtml:"):
                # Extraemos el texto plano de este campo XHTML
                extracted = extract_text(value)
                if extracted.strip():
                    return extracted.strip()
            else:
                new_data[key] = remove_xhtml(value)
        return new_data

    elif isinstance(data, list):
        return [remove_xhtml(item) for item in data]

    elif isinstance(data, str):
        return data

    return ''
