from datetime import datetime, timedelta


def insert_query(file):
    query = f"""
        INSERT INTO FILESTORAGE_META 
        (FILENAME, UPLOADED_AT, SIZE, FILE_LOCATION, TYPE, UPLOADED_FILENAME, 
        DATA_SOURCE, DELETE_TIMESTAMP, DELETED_BY, IS_DELETED) 
        VALUES 
        ('{file['FILENAME']}', '{file['UPLOADED_AT']}', {file['SIZE']}, 
        '{file['FILE_LOCATION']}', '{file['TYPE']}', '{file['UPLOADED_FILENAME']}', 
        '{file['DATA_SOURCE']}', NULL, NULL, FALSE )
    """
    return query


def insert_multiple_filemeta(value_sets):
    insert_multiple_query = f"""
            INSERT INTO FILESTORAGE_META 
            (FILENAME, UPLOADED_AT, SIZE, FILE_LOCATION, TYPE, UPLOADED_FILENAME, 
            DATA_SOURCE, DELETE_TIMESTAMP, DELETED_BY, IS_DELETED) 
            VALUES 
            {', '.join(value_sets)}
        """
    return insert_multiple_query


select_non_deleted_files = "SELECT * FROM FILESTORAGE_META WHERE IS_DELETED = 0"


def select_logs_by_limit(limit):
    query = f"""SELECT * FROM LOGS ORDER BY TIMESTAMP DESC LIMIT {limit}"""
    return query


def select_days_query(days):
    # Calculate the date 'days' days ago from the current date
    target_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    print(target_date)

    select_query = (
        f"""SELECT * FROM FILESTORAGE_META WHERE UPLOADED_AT >= "{target_date}" """
    )
    return select_query


# Example query definition in file_meta_object


def select_meta_query(data_kind, days):
    # Calculate the date 'days' days ago from the current date
    target_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    query = f"""SELECT * FROM FILESTORAGE_META WHERE DATA_SOURCE = "{data_kind}" AND UPLOADED_AT >= "{target_date}" """
    return query


insert_log = """
        INSERT INTO LOGS 
        (TIMESTAMP, EVENT_TYPE, MSG_USER_FRIENDLY, RESULT, DESCRIPTION) 
        VALUES 
        (%s, %s, %s, %s, %s)
    """

# Update the DELETED_BY, IS_DELETED, and DELETE_TIMESTAMP fields
delete_meta = """
    UPDATE FILESTORAGE_META
    SET DELETED_BY = %s,
        IS_DELETED = %s,
        DELETE_TIMESTAMP = %s
    WHERE ID = %s
    """


def select_get_kind_from_id(id):
    return f"""
        SELECT DATA_SOURCE FROM `FILESTORAGE_META` WHERE ID={str(id)}
    """


def delete_data(id, data_source):
    return f"""
        DELETE FROM {data_source}
        WHERE FILENAME = {str(id)};
    """


def get_data_by_filters(data_source, filters, offset, limit):
    query = f"""
        SELECT * FROM {data_source}"""
    tc = f"""SELECT COUNT(*) FROM {data_source}"""

    if len(filters) > 0:
        query += " WHERE "
        tc += " WHERE "
        range_filters = []  # To store range filter conditions
        for key, value in filters.items():
            if isinstance(value, dict) and "min" in value and "max" in value:
                min_value = value["min"]
                max_value = value["max"]
                range_filters.append(
                    f"""{key} >= "{min_value}" AND {key} <= "{max_value}" """
                )

        if range_filters:
            query += " AND ".join(range_filters)
            tc += " AND ".join(range_filters)

    query += f" LIMIT {limit} OFFSET {offset*limit};"
    return query, tc


def get_total_data_by_filter_export(data_source, filters):
    query = f"""
        SELECT * FROM {data_source}"""

    if len(filters) > 0:
        query += " WHERE "
        range_filters = []  # To store range filter conditions
        for key, value in filters.items():
            if isinstance(value, dict) and "min" in value and "max" in value:
                min_value = value["min"]
                max_value = value["max"]
                range_filters.append(
                    f"""{key} >= "{min_value}" AND {key} <= "{max_value}" """
                )

        if range_filters:
            query += " AND ".join(range_filters)

    return query


def edit_total_data_by_filter(data_source, filters, column, from_replace, to_replace):
    query = f"""
        UPDATE {data_source} SET {column}={to_replace} WHERE {column}={from_replace}"""

    if len(filters) > 0:
        range_filters = []  # To store range filter conditions
        for key, value in filters.items():
            if isinstance(value, dict) and "min" in value and "max" in value:
                min_value = value["min"]
                max_value = value["max"]
                range_filters.append(
                    f"""{key} >= "{min_value}" AND {key} <= "{max_value}" """
                )

        if range_filters:
            sm = " AND ".join(range_filters)
            query += f" AND {sm}"

    print(query)
    return query


def insert_inlet_query(header_string, value_sets):
    """(Iteration, CPUTime, PhysTime, Travels, Value, AvValue, Min_Value,
    Max_Value, Delta, Criteria, PrevAvRefValue, Progress, CriteriaType,
    CriteriaVarType, CriteriaPercentage, FILENAME)"""
    insert_in_query = f"""
            INSERT INTO INLET
            {header_string}
            VALUES
            {', '.join(value_sets)}
        """
    return insert_in_query


def insert_outlet_query(header_string, value_sets):
    """(Iteration, CPUTime, PhysTime, Travels, Value, AvValue, Min_Value,
    Max_Value, Delta, Criteria, PrevAvRefValue, Progress, CriteriaType,
    CriteriaVarType, CriteriaPercentage, FILENAME)"""
    insert_out_query = f"""
            INSERT INTO OUTLET
            {header_string}
            VALUES
            {', '.join(value_sets)}
        """
    return insert_out_query


def insert_pump_query(header_string, value_strings):
    """(W, V, A, Flow, R_sec, Temp_C, FILENAME)"""
    insertion_query = f"INSERT INTO PUMP {header_string} VALUES "
    insertion_query += ", ".join(value_strings)

    return insertion_query


def find_id_by_name(filename):
    return f"""SELECT ID FROM `FILESTORAGE_META` WHERE FILENAME="{filename}"; """


def delete_file_meta(fileid):
    return f"""DELETE FROM `FILESTORAGE_META` WHERE ID={fileid}"""


insert_type_count_query = """
        INSERT INTO TYPE_TOTAL_COUNT 
        (TYPE, VALUE, DATETIME) 
        VALUES 
        (%s, %s, %s)
"""

select_latest_type_count_query = """
        SELECT VALUE
        FROM TYPE_TOTAL_COUNT
        WHERE TYPE = '%s'
        ORDER BY `DATETIME` DESC
        LIMIT 1;
"""


def selection_latest_count(type):
    return f"""
        SELECT VALUE
        FROM TYPE_TOTAL_COUNT
        WHERE TYPE = '{type}'
        ORDER BY `DATETIME` DESC
        LIMIT 1;
"""


def get_header_fields(datasource):
    return f"""
            SELECT *
            FROM `DB_FILE_MAP`
            WHERE TABLENAME = "{datasource}";
    """


def get_type_total_count_by_date(fromDate: str, toDate: str):
    return f"""
            SELECT TYPE, VALUE, DATETIME
            FROM TYPE_TOTAL_COUNT
            WHERE DATETIME BETWEEN "{fromDate}" and "{toDate}"
            ORDER BY `DATETIME` DESC;
    """
