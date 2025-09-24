import argparse
import os 
import  json

from tabulate import tabulate




def get_negative_coverage(prediql_output):

    base_path = prediql_output
    total_nodes = 0 
    neg_cov = 0
    table = {}

    for folder_name in os.listdir(base_path):        
        folder_path = os.path.join(base_path, folder_name)
        if not os.path.isdir(folder_path):
            continue
        # print(folder_name)
        elif folder_name != "faiss_index":
            try:
                with open(os.path.join(folder_path,"llama_queries.json"), "r") as f:
                    # print(folder_name)
                    total_nodes +=1
                    table[folder_name] = "-"
                    # print(total_nodes)
                    payloads = json.load(f)
                    # print(payloads)
            except json.JSONDecodeError as e:
                print(f"❌ Error reading JSON: {e}")
                return False, 0
            
            for i, payload in enumerate(payloads, start=1):
                body = payload.get("response_body")
                if payload.get("response_status") == 200:
                    if payload.get("success") == False:
                        # print(payload.get("response_status"))
                        # print("negative count!!")
                        neg_cov +=1
                        table[folder_name] = True
                        break

    return neg_cov, total_nodes, table

        



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="prediql output folder path")
    parser.add_argument("--prediql_output", type= str, help="prediql output folder path")
    args = parser.parse_args()
    prediql_output = args.prediql_output
    neg_cov, total_nodes, table = get_negative_coverage(prediql_output)
    print("Negative Coverage:", neg_cov,"/",total_nodes)
    print(table)

    rows = []
    for node in table:
        rows.append([
            node,
            table[node]
        ])

        table_str = tabulate(
            rows,
            headers = ["Node", "Negative coverage"],
            tablefmt = "grid"
        )

    output_file = prediql_output + "/Negative_coverage.txt"
    summary_txt = "\nNegative Coverage Summary: " + str(neg_cov) + "/" + str(total_nodes) +"\nRules: Https Response == 200 && success == False"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(table_str)
        f.write(summary_txt)

    print(f"\n✅ Table written to {output_file}")