def col_query_gen(table, col,dim, template):
    return template.formate(table= table, col = col, dim = dim, metric = col)

def table_gen(table, template):
    return 'union'.join([col_query_gen(table.name,col, table.dim,template)]for col in table.metrics)

def query_gen(json, template):
    return 'union'.join([table_gen(table,template) for table in json.tables] )


# --large streaming
def get_data(input_filename, delimiter = ','):
    with open(input_filename, 'r+b') as f:  # change the b to jason, text accordingly
        for record in f:                 # traverse sequentially through the file
            x = record.split(delimiter)  # parsing logic goes here (binary, text, JSON, markup, etc)
            yield x                      # emit a stream of things
                                         #  (e.g., words in the line of a text file,
                                         #   or fields in the row of a CSV file)