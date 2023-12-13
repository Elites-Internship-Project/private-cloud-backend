from flask_mysqldb import MySQL
from datetime import datetime as dt
import jwt
import queries.users as user_query
import queries.file_meta as file_meta_object
import traceback
import sys
import bcrypt
import csv
import pandas as pd
from flask import current_app as app
import boto3
from dotenv.main import load_dotenv
import os

dir = os.path.dirname(__file__)

env_path = os.path.join(dir, ".env")
load_dotenv(dotenv_path=env_path)


def hash(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_hash(password: str, hash_password: bytes):
    return bcrypt.checkpw(password.encode(), hash_password)


def convert_to_json(records: tuple, cursor) -> list:
    row_headers = [x[0] for x in cursor.description]
    data_dict = {}
    json_data = []
    for result in records:
        data_dict = {}
        for index, row in enumerate(result):
            if "date" in row_headers[index]:
                data_dict[row_headers[index]] = row.strftime("%Y-%m-%d %H:%M:%S")
            else:
                data_dict[row_headers[index]] = row
                # print(row)
        json_data.append(data_dict)

    return json_data


def decode_token(token):
    try:
        data = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])

        if data is not None:
            return data["user"]

    except Exception as e:
        traceback.print_exception(*sys.exc_info())
        return -1


def sign_in_with_email_and_password(email, password, mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.select_by_email, [email])
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        # check hashed password
        # if :
        if len(json_data) > 0 and check_hash(
            password, (json_data[0]["Password"]).encode("utf-8")
        ):
            # get new JWT token
            status, token = get_new_token(json_data[0]["UserId"])
            if status:
                return json_data[0], token, 200, ""
            return None, None, 500, "Invalid credentials!"
        else:
            print("Login Failed")
            return None, None, 500, "Invalid credentials!"
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return None, None, 500, "Some error occured!"


def signup_user(user, mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(
            user_query.insert_user(user),
            (
                user["name"],
                user["email"],
                user["role"],
                user["password"],
                user["created_date"],
                user["is_active"],
            ),
        )
        print(user["password"])
        mysql.connection.commit()

        cur.close()

        return 200, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, e


def delete_user(email, mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.delete_by_email, [email])
        mysql.connection.commit()

        cur.close()

        return 200, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, e


def activate_user(email, mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.activate_by_email, [email])
        mysql.connection.commit()

        cur.close()

        return 200, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, "Some error occured!"


def get_all_users(mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.select_all)
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        return 200, json_data, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occurred!"


def get_all_active_users(mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.select_all_active)
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        return 200, json_data, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occurred!"


def get_non_deleted_files(mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(file_meta_object.select_non_deleted_files)
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        return 200, json_data, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occurred!"


def get_logs(mysql, limit):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(file_meta_object.select_logs_by_limit(limit))
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        return 200, json_data, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occurred!"


def get_type_total_count_by_days(mysql, fromDate: str, toDate: str):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(
            file_meta_object.get_type_total_count_by_date(fromDate, toDate)
        )
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        return 200, json_data, None
    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occurred!"


def update_user_by_id(user_id, new_user_data, mysql):
    try:
        cur = mysql.connection.cursor()

        res = cur.execute(user_query.update_by_id(user_id, new_user_data))

        mysql.connection.commit()

        cur.close()

        return 200, "User updated successfully!"

    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, "Some error occured!"


def get_user_by_id(user_id, mysql):
    try:
        cur = mysql.connection.cursor()
        res = cur.execute(user_query.select_by_id, [user_id])

        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        cur.close()

        if len(json_data) > 0:
            return 200, json_data, ""
        return 500, None, "User not found!"

    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, None, "Some error occured!"


def update_password(email, old_password, new_password, mysql):
    try:
        cur = mysql.connection.cursor()
        res = cur.execute(user_query.select_by_email, [email])
        result = cur.fetchall()
        json_data = convert_to_json(result, cur)

        if len(json_data) > 0:
            if check_hash(old_password, json_data[0]["Password"]):
                upd = cur.execute(
                    user_query.update_pass_by_email(email, hash(new_password))
                )
                mysql.connection.commit()
            else:
                return 200, "Wrong old password!"
        else:
            return 500, "Some error occured!"

        cur.close()

    except Exception as e:
        # print(e)
        traceback.print_exception(*sys.exc_info())
        return 500, "Some error occured!"


def get_new_token(userId):
    try:
        token = jwt.encode(
            {
                "user": userId,
                "pass": dt.timestamp(dt.utcnow()),
            },
            app.config["JWT_SECRET_KEY"],
        )
        return True, token
    except Exception as e:
        print(e)
        return False, ""


def insert_loggers(log, mysql):
    try:
        # Create a MySQL cursor
        cursor = mysql.connection.cursor()

        # Insert data into the database
        cursor.execute(
            file_meta_object.insert_log,
            (
                log["TIMESTAMP"],
                log["EVENT_TYPE"],
                log["MSG_USER_FRIENDLY"],
                log["RESULT"],
                log["DESCRIPTION"],
            ),
        )
        mysql.connection.commit()
        # Close the cursor
        cursor.close()

    except Exception as e:
        print(e)


def insert_type_total_count(type, count, timestamp, mysql):
    try:
        # Create a MySQL cursor
        cursor = mysql.connection.cursor()

        # Insert data into the database
        cursor.execute(
            file_meta_object.insert_type_count_query,
            (type, count, timestamp),
        )
        mysql.connection.commit()
        # Close the cursor
        cursor.close()

    except Exception as e:
        print(e)


def get_last_type_total_count(type, mysql):
    try:
        # Create a MySQL cursor
        cursor = mysql.connection.cursor()

        # Insert data into the database

        cursor.execute(
            file_meta_object.selection_latest_count(type),
        )

        rows = cursor.fetchall()

        total_count = int(rows[0][0])

        # Close the cursor
        cursor.close()

        return total_count

    except Exception as e:
        return -1
        print(e)


def xlsx_to_csv(xlsx_file, csv_file):
    """
    Convert an XLSX file to a CSV file.

    Args:
    xlsx_file (str): Path to the input XLSX file.
    csv_file (str): Path to the output CSV file.

    Returns:
    None
    """
    try:
        data = pd.read_excel(xlsx_file)
        data.to_csv(csv_file, index=False)
        print(f"{xlsx_file} has been converted to {csv_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


def get_header_fields_func(data_source, mysql):
    cursor = mysql.connection.cursor()

    cursor.execute(file_meta_object.get_header_fields(data_source))

    rows = cursor.fetchall()

    # Close the cursor
    cursor.close()
    return rows


def extract_inlet_csv(csv_file_path, fileid, mysql):
    # Initialize an empty list to store the data from the CSV
    data_to_insert = []
    cursor = mysql.connection.cursor()

    with open(csv_file_path, "r", encoding="utf-8") as csv_file:
        csv_reader = csv.reader(csv_file)

        # header = csv_reader[0]

        # Skip the header row if it exists
        header_row = next(csv_reader, None)
        # print(header_row)


        flow_flag=0

        for i in header_row:
            if "flow" in i:
                flow_flag=1
        
        print(flow_flag)

        if flow_flag==1:
            raise Exception("File is a Pump File!")

        # select * from DB_FILE_MAP where TABLENAME=INLET  ==> fields received
        # create a dictionary, where key is NAME_IN_FILE and value is NAME_IN_DB  ==> dict created
        # transverse the header, create a string using dict and header

        header_fields = get_header_fields_func("INLET", mysql)
        dict_file_to_db_fields = {}
        dict_file_to_index = {}

        for header in header_fields:
            dict_file_to_db_fields[header[1]] = header[2]

        print(dict_file_to_db_fields)

        for header in dict_file_to_db_fields.keys():
            for i in range(0, len(header_row)):
                if header_row[i] in header:
                    dict_file_to_index[header] = i

        header_list_string = ", ".join(dict_file_to_db_fields.values())
        header_string = f"({header_list_string}, FILENAME)"

        for row in csv_reader:
            if len(row) == 0:
                continue

            if len(row) != int(os.getenv("NO_OF_COLUMNS_IN_INLET")):
                delete_in_query = file_meta_object.delete_file_meta(fileid)
                cursor.execute(delete_in_query)
                mysql.connection.commit()
                raise Exception("Column MisMatch!")

            # fetch inlet field from db
            # for loop for checking inlet fields in sheet
            # if found map col with inlet fields
            # insertion by col name but row wise not index

            s = []
            for header in header_fields:
                s.append(row[dict_file_to_index[header[1]]])

            # print(s)
            s_string = ", ".join(s)
            row_string = f"({s_string}, {fileid})"

            # iteration = float(row[0])
            # cputime = float(row[1])
            # phystime = float(row[2])
            # travels = float(row[3])
            # value = float(row[4])
            # avvalue = float(row[5])
            # minvalue = float(row[6])
            # maxvalue = float(row[7])
            # delta = float(row[8])
            # criteria = float(row[9])
            # prevavrefvalue = float(row[10])
            # progress = float(row[11])
            # criteriatype = float(row[12])
            # criteriavartype = float(row[13])
            # criteriapercentage = float(row[14])

            # # Append the data as a string without a tuple to the list
            # data_to_insert.append(
            #     f"({iteration}, {cputime}, {phystime}, {travels}, {value}, {avvalue}, {minvalue}, {maxvalue}, {delta}, {criteria}, {prevavrefvalue}, {progress}, {criteriatype}, {criteriavartype}, {criteriapercentage}, {fileid})"
            # )
            data_to_insert.append(row_string)

    # Execute the INSERT query
    current_inserted_count = len(data_to_insert)
    insert_in_query = file_meta_object.insert_inlet_query(header_string, data_to_insert)
    cursor.execute(insert_in_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "INLET"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT INLET CSV",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull:  {csv_file_path}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {csv_file_path}",
    }
    insert_loggers(log, mysql)
    print(log)


def extract_inlet_xlsx(xlsx_file, fileid, mysql):
    # try:
    # Initialize a connection to the MySQL database
    cursor = mysql.connection.cursor()

    # Read the XLSX file into a DataFrame
    data = pd.read_excel(xlsx_file, engine="openpyxl")

    header_columns = data.columns

    flow_flag=0

    for i in header_columns:
        if "flow" in i:
            flow_flag=1
    
    print(flow_flag)

    if flow_flag==1:
        raise Exception("File is a Pump File!")
    
    # Initialize an empty list to store the data from the CSV
    header_fields = get_header_fields_func("INLET", mysql)
    dict_file_to_db_fields = {}
    dict_file_to_index = {}

    for header in header_fields:
        dict_file_to_db_fields[header[1]] = header[2]

    print(dict_file_to_db_fields)

    for header in dict_file_to_db_fields.keys():
        for i in range(0, len(header_columns)):
            if header_columns[i] in header:
                dict_file_to_index[header] = i

    header_list_string = ", ".join(dict_file_to_db_fields.values())
    header_string = f"({header_list_string}, FILENAME)"
    print(header_string)

    # Reset the index
    data = data.reset_index(drop=True)

    data_to_insert = []
    # print(data)
    error_log = []
    for index, row in data.iterrows():
        if len(row) == 0:
            continue

        if len(row) != int(os.getenv("NO_OF_COLUMNS_IN_INLET")):
            delete_in_query = file_meta_object.delete_file_meta(fileid)
            cursor.execute(delete_in_query)
            mysql.connection.commit()
            raise Exception("Column MisMatch!")

        # Check if every field in the row is NaN
        check_nan = row.isna().all()

        if check_nan:
            continue
        # # Convert the CSV data to the appropriate data types
        # iteration = float(row[0])
        # cputime = float(row[1])
        # phystime = float(row[2])
        # travels = float(row[3])
        # value = float(row[4])
        # avvalue = float(row[5])
        # minvalue = float(row[6])
        # maxvalue = float(row[7])
        # delta = float(row[8])
        # criteria = float(row[9])
        # prevavrefvalue = float(row[10])
        # progress = float(row[11])
        # criteriatype = float(row[12])
        # criteriavartype = float(row[13])
        # criteriapercentage = float(row[14])

        s = []
        for header in header_fields:
            print(header)
            s.append(row[dict_file_to_index[header[1]]])

        # print(s)

        s_string = ", ".join(map(str, s))
        print(s_string)
        row_string = f"({s_string}, {fileid})"

        # Append the data as a string without a tuple to the list
        # data_to_insert.append(
        #     f"({iteration}, {cputime}, {phystime}, {travels}, {value}, {avvalue}, {minvalue}, {maxvalue}, {delta}, {criteria}, {prevavrefvalue}, {progress}, {criteriatype}, {criteriavartype}, {criteriapercentage}, {fileid})"
        # )

        data_to_insert.append(row_string)

    # Execute the INSERT query
    current_inserted_count = len(data_to_insert)
    insert_in_query = file_meta_object.insert_inlet_query(header_string, data_to_insert)
    cursor.execute(insert_in_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "INLET"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT INLET XLSX",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull: {xlsx_file}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {xlsx_file}",
    }
    insert_loggers(log, mysql)
    print(log)


def extract_outlet_csv(csv_file_path, fileid, mysql):
    # Initialize an empty list to store the data from the CSV
    data_to_insert = []

    cursor = mysql.connection.cursor()

    with open(csv_file_path, "r", encoding="utf-8") as csv_file:
        csv_reader = csv.reader(csv_file)
        # Skip the header row if it exists

        header_row = next(csv_reader, None)

        flow_flag=0

        for i in header_row:
            if "flow" in i:
                flow_flag=1
        
        if flow_flag==1:
            raise Exception("File is a Pump File!")

        header_fields = get_header_fields_func("OUTLET", mysql)
        dict_file_to_db_fields = {}
        dict_file_to_index = {}

        for header in header_fields:
            dict_file_to_db_fields[header[1]] = header[2]

        print(dict_file_to_db_fields)

        for header in dict_file_to_db_fields.keys():
            for i in range(0, len(header_row)):
                if header_row[i] in header:
                    dict_file_to_index[header] = i

        header_list_string = ", ".join(dict_file_to_db_fields.values())
        header_string = f"({header_list_string}, FILENAME)"
        print(header_string)

        for row in csv_reader:
            if len(row) == 0:
                continue

            if len(row) != int(os.getenv("NO_OF_COLUMNS_IN_OUTLET")):
                delete_in_query = file_meta_object.delete_file_meta(fileid)
                cursor.execute(delete_in_query)
                mysql.connection.commit()
                raise Exception("Column MisMatch!")

            s = []
            for header in header_fields:
                s.append(row[dict_file_to_index[header[1]]])

            # print(s)
            s_string = ", ".join(s)
            row_string = f"({s_string}, {fileid})"

            # # print(row)
            # # Convert the CSV data to the appropriate data types
            # iteration = float(row[0])
            # cputime = float(row[1])
            # phystime = float(row[2])
            # travels = float(row[3])
            # value = float(row[4])
            # avvalue = float(row[5])
            # minvalue = float(row[6])
            # maxvalue = float(row[7])
            # delta = float(row[8])
            # criteria = float(row[9])
            # prevavrefvalue = float(row[10])
            # progress = float(row[11])
            # criteriatype = float(row[12])
            # criteriavartype = float(row[13])
            # criteriapercentage = float(row[14])

            # # Append the data as a string without a tuple to the list
            # data_to_insert.append(
            #     f"({iteration}, {cputime}, {phystime}, {travels}, {value}, {avvalue}, {minvalue}, {maxvalue}, {delta}, {criteria}, {prevavrefvalue}, {progress}, {criteriatype}, {criteriavartype}, {criteriapercentage}, {fileid})"
            # )

            data_to_insert.append(row_string)

    # Execute the INSERT query
    current_inserted_count = len(data_to_insert)
    insert_in_query = file_meta_object.insert_outlet_query(
        header_string, data_to_insert
    )
    cursor.execute(insert_in_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "OUTLET"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT OUTLET CSV",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull: {csv_file_path}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {csv_file_path}",
    }
    insert_loggers(log, mysql)
    print(log)


def extract_outlet_xlsx(xlsx_file, fileid, mysql):
    # Initialize a connection to the MySQL database
    cursor = mysql.connection.cursor()

    # Read the XLSX file into a DataFrame
    data = pd.read_excel(xlsx_file, engine="openpyxl")

    header_columns = data.columns

    
    flow_flag=0

    for i in header_columns:
        if "flow" in i:
            flow_flag=1
    
    if flow_flag==1:
        raise Exception("File is a Pump File!")
    
    # Initialize an empty list to store the data from the CSV
    header_fields = get_header_fields_func("OUTLET", mysql)
    dict_file_to_db_fields = {}
    dict_file_to_index = {}

    for header in header_fields:
        dict_file_to_db_fields[header[1]] = header[2]

    print(dict_file_to_db_fields)

    for header in dict_file_to_db_fields.keys():
        for i in range(0, len(header_columns)):
            if header_columns[i] in header:
                dict_file_to_index[header] = i

    header_list_string = ", ".join(dict_file_to_db_fields.values())
    header_string = f"({header_list_string}, FILENAME)"
    print(header_string)

    # Reset the index
    data = data.reset_index(drop=True)
    # Initialize an empty list to store the data from the CSV
    data_to_insert = []
    # print(data)
    for index, row in data.iterrows():
        if len(row) == 0:
            continue

        if len(row) != int(os.getenv("NO_OF_COLUMNS_IN_OUTLET")):
            delete_in_query = file_meta_object.delete_file_meta(fileid)
            cursor.execute(delete_in_query)
            mysql.connection.commit()
            raise Exception("Column MisMatch!")

        # Check if every field in the row is NaN
        check_nan = row.isna().all()

        if check_nan:
            continue
        # # Convert the CSV data to the appropriate data types
        # iteration = float(row[0])
        # cputime = float(row[1])
        # phystime = float(row[2])
        # travels = float(row[3])
        # value = float(row[4])
        # avvalue = float(row[5])
        # minvalue = float(row[6])
        # maxvalue = float(row[7])
        # delta = float(row[8])
        # criteria = float(row[9])
        # prevavrefvalue = float(row[10])
        # progress = float(row[11])
        # criteriatype = float(row[12])
        # criteriavartype = float(row[13])
        # criteriapercentage = float(row[14])

        # # Append the data as a string without a tuple to the list
        # data_to_insert.append(
        #     f"({iteration}, {cputime}, {phystime}, {travels}, {value}, {avvalue}, {minvalue}, {maxvalue}, {delta}, {criteria}, {prevavrefvalue}, {progress}, {criteriatype}, {criteriavartype}, {criteriapercentage}, {fileid})"
        # )

        s = []
        for header in header_fields:
            print(header)
            s.append(row[dict_file_to_index[header[1]]])

        # print(s)

        s_string = ", ".join(map(str, s))
        print(s_string)
        row_string = f"({s_string}, {fileid})"

        data_to_insert.append(row_string)

    # Execute the INSERT query
    current_inserted_count = len(data_to_insert)
    insert_in_query = file_meta_object.insert_outlet_query(
        header_string, data_to_insert
    )
    cursor.execute(insert_in_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "OUTLET"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT OUTLET XLSX",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull: {xlsx_file}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {xlsx_file}",
    }
    insert_loggers(log, mysql)
    print(log)


def convert_cubic_meter_per_second_to_liters_per_minute(cubic_meters_per_second):
    # 1 cubic meter is equal to 1000 liters
    conversion_factor = 1000

    # Convert cubic meters to liters
    liters_per_second = cubic_meters_per_second * conversion_factor

    # Convert liters per second to liters per minute
    liters_per_minute = liters_per_second * 60

    return liters_per_minute


def extract_pump_csv(csv_file_path, fileid, mysql):
    # Initialize an empty list to store the data from the CSV
    data_to_insert = []

    cursor = mysql.connection.cursor()

    with open(csv_file_path, "r", encoding="utf-8") as csv_file:
        csv_reader = csv.reader(csv_file)
        # Skip the header row if it exists

        header = next(csv_reader, None)

        flow_check_string=""
        flow_flag=0


        for i in header:
            if "flow" in i:
                flow_check_string=i
                flow_flag=1


        if flow_flag==0:
            raise Exception("File is not a Pump File!")


        flow_check_flag = 0
        # flow_check_string = header[3]

        if "L/min" not in flow_check_string:
            flow_check_flag = 1

        header_fields = get_header_fields_func("PUMP", mysql)
        
        dict_file_to_db_fields = {}
        dict_file_to_index = {}

        for header_i in header_fields:
            dict_file_to_db_fields[header_i[1]] = header_i[2]

        # print(dict_file_to_db_fields)

        for header_i in dict_file_to_db_fields.keys():
            for i in range(0, len(header)):
                if header_i in header[i]:
                    dict_file_to_index[header_i] = i

        header_list_string = ", ".join(dict_file_to_db_fields.values())
        header_string = f"({header_list_string}, FILENAME)"

        for row in csv_reader:
            v1 = os.getenv("NO_OF_COLUMNS_IN_PUMP")

            if len(row) != int(v1):
                delete_in_query = file_meta_object.delete_file_meta(fileid)
                cursor.execute(delete_in_query)
                mysql.connection.commit()
                raise Exception("Column MisMatch!")
            if len(row) == 0:
                continue
            # print(row)
            # Convert the CSV data to the appropriate data types
            f = 1
            for i in range(0, 6):
                if row[i] != "":
                    f = 0

            if f:
                continue

            # W = float(row[0])
            # V = float(row[1])
            # A = float(row[2])
            # flow = float(row[3])
            # R_sec = float(row[4])
            # temp_C = float(row[5])

            # if(flow_check_flag):
            #     flow = convert_cubic_meter_per_second_to_liters_per_minute(flow)

            # # Append the data as a string without a tuple to the list
            # data_to_insert.append(
            #     f"({W}, {V}, {A}, {flow}, {R_sec}, {temp_C}, {fileid})"
            # )
            
            s = []
            for header in header_fields:
                # print(header[1])
                if "flow" in header[1]:
                    if(flow_check_flag):
                        value = convert_cubic_meter_per_second_to_liters_per_minute(float(row[dict_file_to_index[header[1]]]))
                        s.append(value)
                    else:
                        s.append(row[dict_file_to_index[header[1]]])
                else:
                    s.append(row[dict_file_to_index[header[1]]])
                # print(row[dict_file_to_index[header[1]]])

            # print(s)

            s_string = ", ".join(map(str, s))
            row_string = f"({s_string}, {fileid})"
            data_to_insert.append(row_string)

    # Execute the INSERT query
    current_inserted_count = len(data_to_insert)
    insert_in_query = file_meta_object.insert_pump_query(header_string, data_to_insert)
    cursor.execute(insert_in_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "PUMP"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT PUMP CSV",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull: {csv_file_path}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {csv_file_path}",
    }
    insert_loggers(log, mysql)
    print(log)


def extract_pump_xlsx(xlsx_file, fileid, mysql):
    # Initialize a connection to the MySQL database
    cursor = mysql.connection.cursor()

    # Read the XLSX file into a DataFrame
    data = pd.read_excel(xlsx_file, engine="openpyxl")

    # Reset the index
    data = data.reset_index(drop=True)
    header = data.columns.tolist()

    flow_check_string=""
    flow_flag=0


    for i in header:
        if "flow" in i:
            flow_check_string=i
            flow_flag=1
    
    if flow_flag==0:
        raise Exception("File is not a Pump File!")
    
    flow_check_flag = 0
    # flow_check_string = header[3]

    if "L/min" not in flow_check_string:
        flow_check_flag = 1

    header_columns = data.columns
    # Initialize an empty list to store the data from the CSV
    header_fields = get_header_fields_func("PUMP", mysql)
    dict_file_to_db_fields = {}
    dict_file_to_index = {}

    for header in header_fields:
        dict_file_to_db_fields[header[1]] = header[2]

    print(dict_file_to_db_fields)

    for header in dict_file_to_db_fields.keys():
        for i in range(0, len(header_columns)):
            if header in header_columns[i]:
                dict_file_to_index[header] = i

    header_list_string = ", ".join(dict_file_to_db_fields.values())
    header_string = f"({header_list_string}, FILENAME)"
    print(header_string)

    # Iterate through the rows and build the VALUES part of the query
    value_strings = []
    for index, row in data.iterrows():
        v1 = int(os.getenv("NO_OF_COLUMNS_IN_PUMP"))
        if len(row) != v1:
            delete_in_query = file_meta_object.delete_file_meta(fileid)
            cursor.execute(delete_in_query)
            mysql.connection.commit()
            raise Exception("Column MisMatch!")
        # W, V, A, flow, r_sec, temp = row

        # if(flow_check_flag):
        #         flow = convert_cubic_meter_per_second_to_liters_per_minute(flow)

        # values = (W, V, A, flow, r_sec, temp, fileid)
        # value_string = f"({', '.join(map(str, values))})"
        # value_strings.append(value_string)

        s = []
        for header in header_fields:
            # print(header)
            # s.append(row[dict_file_to_index[header[1]]])

            if "flow" in header[1]:
                if(flow_check_flag):
                    value = convert_cubic_meter_per_second_to_liters_per_minute(float(row[dict_file_to_index[header[1]]]))
                    s.append(value)
                else:
                    s.append(row[dict_file_to_index[header[1]]])
            else:
                s.append(row[dict_file_to_index[header[1]]])

        # print(s)

        s_string = ", ".join(map(str, s))
        # print(s_string)
        row_string = f"({s_string}, {fileid})"

        value_strings.append(row_string)

    insertion_pump_query = file_meta_object.insert_pump_query(
        header_string, value_strings
    )

    current_inserted_count = len(value_strings)

    # Execute the INSERT query with the data
    cursor.execute(insertion_pump_query)

    # Commit the changes
    mysql.connection.commit()

    # insertion of total latest count in the TYPE_TOTAL_COUNT table
    insert_type = "PUMP"
    total_count = 0
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

    total_count = get_last_type_total_count(insert_type, mysql)

    if total_count == -1:
        raise Exception("Getting Latest Count of Type")

    insert_type_total_count(
        insert_type, (total_count + current_inserted_count), timestamp, mysql
    )

    # Close the cursor
    cursor.close()

    log = {
        "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EVENT_TYPE": "EXTRACT PUMP XLSX",
        "MSG_USER_FRIENDLY": f"Data Extraction Successfull: {xlsx_file}",
        "RESULT": "Success",
        "DESCRIPTION": f"Data Extraction successfully: {xlsx_file}",
    }
    insert_loggers(log, mysql)
    print(log)


def upload_file_to_s3(filename):
    """
    Upload a file to an S3 bucket.
    """
    # If S3 object_name is not provided, use the file name
    bucket_name = ""
    file_path = f"upload/{filename}"  # Replace with the path to your local file
    # object_name = "sample.txt"  # Optionally specify the S3 object name

    # Create an S3 client
    s3 = boto3.client(
        "s3",
        aws_access_key_id="",
        aws_secret_access_key="",
    )

    try:
        s3.upload_file(file_path, bucket_name, filename)
        print(
            f"File '{file_path}' uploaded to '{bucket_name}/{filename}' successfully."
        )
        return True
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return False


def download_file_from_s3(filename):
    """
    Download a file from an S3 bucket to a local path.
    """

    bucket_name = ""
    file_path = f"download/{filename}"  # Replace with the path to your local file
    s3_path = f"{filename}"

    # Create an S3 client
    s3 = boto3.client(
        "s3",
        aws_access_key_id="",
        aws_secret_access_key="",
    )

    try:
        s3.download_file(bucket_name, s3_path, file_path)
        print(
            f"File '{s3_path}' downloaded from '{bucket_name}' to '{file_path}' successfully."
        )
        return True
    except Exception as e:
        print(f"Error downloading file from S3: {e}")
        return False
