# .replace("tblnm", "")
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I stop here, result not perfect but I think I can improve it later tonight!!!!
# I think I can restart a conversation just to convert the where clause itself.




import pandas as pd
import re

# Load data from Excel
df = pd.read_excel('all cdp_production tables and columns.xlsx')

# Read Scala file
with open('scala.txt', 'r') as file:
    scala_content = file.readlines()

# Extract DataFrame name and corresponding table name
df_info = {}
for line in scala_content:
    match = re.search(r'val (.*): DataFrame = spark\.table\(.*inputTblsConfig\.getString\("(.*?)"\)', line)
    if match:
        table_name = match.group(2).replace("_TBL", "").replace("TblNm", "")
        df_info[match.group(1)] = table_name.lower()  # assuming table names in excel are all lower case

# Generate output
output_lines = []
for df_name, table_name in df_info.items():
    columns = df[df['tableName'] == table_name]['columnName'].tolist()
    columns_string = ", ".join(columns)

    # Check for conditions in the Scala code lines
    condition_match = re.search(f'{df_name}.*\.where\((.*?)\)', "\n".join(scala_content))
    # print(condition_match)
    if condition_match:
        # Splitting the conditions string by "and"
        conditions = condition_match.group(1).split(" and ")
        print(conditions)

        # Prepare the list to store formatted conditions
        formatted_conditions = []

        # Loop over conditions
        for condition in conditions:
            condition = condition.replace('F.col(', '').replace(')', '').replace('===', '=').replace('"', '')
            print(condition)
            formatted_conditions.append(condition)

        condition_str = " and ".join(formatted_conditions)
        condition = f"WHERE {condition_str}"
    else:
        condition = ""

    output_lines.append(f"{df_name} AS (\n    SELECT {columns_string}\n    FROM {table_name} {condition}\n),\n")

# Write output to file
with open('output.txt', 'w') as file:
    file.writelines(output_lines)
