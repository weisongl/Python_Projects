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

# Read the scala.txt file
with open('scala.txt', 'r') as f:
    scala_lines = f.readlines()

# Read the xlsx file into a DataFrame
df = pd.read_excel('all cdp_production tables and columns.xlsx')

output_lines = []
for line in scala_lines:
    # Extract table name and condition from scala code
    match = re.search(r'spark.table\(s"\$inputDBName\.\${inputTblsConfig\.getString\("(.+?)"\)}"\)\.where\((.+)\)', line)# .replace("tblnm", "")
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

# Read the scala.txt file
with open('scala.txt', 'r') as f:
    scala_lines = f.readlines()

# Read the xlsx file into a DataFrame
df = pd.read_excel('all cdp_production tables and columns.xlsx')

output_lines = []
for line in scala_lines:
    # Extract table name and condition from scala code
    # match = re.search(r'spark.table\(s"\$inputDBName\.\${inputTblsConfig\.getString\("(.+?)"\)}"\)\.where\((.+)\)', line)
    match = re.search(r'spark\.table\(s"\$inputDBName\.\${inputTblsConfig\.getString\("(.+?)"\)}"\)(?:\.where\((.+)\))?', line)
    if match:
        groups = match.groups()
        print(match.groups())
        # table_name = groups[0].replace('_TBL"', '"').replace('_TBLNm"', '"').replace('TblNm"', '"').replace('Tblnm"', '"').lower()
        table_name = groups[0].lower().replace('_tbl"', '"').replace('_tblnm"', '"').replace('tblnm"', '"')

        condition = groups[1] if len(groups) > 1 else None
        if condition is not None:
            condition = condition.replace("F.col(\"", "").replace("\")", "").replace("===", "=")
        # condition = condition.replace("F.col(\"", "").replace("\")", "").replace("===", "=")
        # print(match.groups())
        print(table_name, condition)

        columns = df[df['tableName'] == table_name]['columnName'].tolist()

        # Format output line
        if condition:
            output_line = f"{table_name}_DF AS (\n     select {', '.join(columns)}\n from  {table_name} where {condition}\n  ),"
        else:
            output_line = f"{table_name}_DF AS (\n     select {', '.join(columns)}\n from  {table_name}\n  ),"

        output_lines.append(output_line)

# Write the output to a new file
with open('output.txt', 'w') as f:
    f.write('\n'.join(output_lines))

