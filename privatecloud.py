from dotenv.main import load_dotenv
import os
from datetime import datetime, timedelta
from json import JSONEncoder
from flask import Flask, session, render_template, request, redirect, url_for, jsonify
import requests
from firebase_admin import credentials, auth
from authlib.integrations.flask_client import OAuth
from functools import wraps
from flask_cors import CORS, cross_origin
from flask_mysqldb import MySQL
from datetime import datetime as dt
import queries.file_meta as file_meta_object
import traceback
import sys
from utility import *
import jwt
from werkzeug.utils import secure_filename
from utility import (
    extract_pump_csv,
    extract_inlet_csv,
    extract_outlet_csv,
    upload_file_to_s3,
    download_file_from_s3,
)
from utility import (
    extract_pump_xlsx,
    extract_inlet_xlsx,
    extract_outlet_xlsx,
    get_last_type_total_count,
    get_type_total_count_by_days,
)


dir = os.path.dirname(__file__)

env_path = os.path.join(dir, ".env")
load_dotenv(dotenv_path=env_path)

# create and configure the app
app = Flask(__name__)
cors = CORS(
    app,
    origins="*",
    headers=["Content-Type", "Authorization"],
    expose_headers="Authorization",
)
app.config["CORS_HEADERS"] = "Content-Type"
app.config.from_mapping(
    SECRET_KEY="dev",
    DATABASE="",
)


def dateToString(date):
    if date == None or date == "":
        return ""
    return date.strftime("%Y-%m-%d %H:%M:%S")


# JWT Secret Key
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
# Token Valid in Minutes
app.config["JWT_TOKEN_VALID_FOR"] = os.getenv("JWT_TOKEN_VALID_FOR")

# Set the folder where the uploaded files will be stored
app.config["UPLOAD_FOLDER"] = "upload/"

# Create the upload folder if it doesn't exist
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# mysql configuration & connection
app.config["MYSQL_USER"] = os.getenv("MYSQL_USER")
app.config["MYSQL_PASSWORD"] = os.getenv("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = os.getenv("MYSQL_DB")
app.config["MYSQL_HOST"] = os.getenv("MYSQL_HOST")
mysql = MySQL(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.path == "/login":
            return decorated

        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized",
            }, 401

        try:
            data = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            print(data)
            if data["user"] is None:
                return {
                    "message": "Invalid Authentication token!",
                    "data": None,
                    "error": "Unauthorized",
                }, 401
            if (dt.timestamp(dt.utcnow()) - data["pass"]) // (
                int(app.config["JWT_TOKEN_VALID_FOR"]) * 60
            ) > 0:
                return {
                    "message": "Token Expired",
                    "data": None,
                    "error": "Unauthorized",
                }, 403
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e),
            }, 500

        return f(token, *args, **kwargs)

    return decorated


# a simple page that says hello
@app.route("/", methods=["POST", "GET"])
def index():
    session["error"] = ""
    return render_template("home.html")


@app.route("/logout")
def logout():
    session.pop("user")
    session.pop("token")
    return redirect("/")


@app.route("/signup", methods=["POST"])
@token_required
def signup(token):
    data = request.get_json()
    # print(type(data))
    user = {
        "email": data["email"],
        "password": hash(data["password"]),
        "name": data["name"],
        "role": data["role"],
        "created_date": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_active": 1,
    }

    try:
        if token:
            status_code, err = signup_user(user, mysql)

            # session["user"] = email
            # session["token"] = token
            if err is not None:
                return jsonify({"status": False, "data": err})

            return jsonify({"status": True, "message": "User added successfully!"})
        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/all-users", methods=["GET"])
@token_required
def view_all_users(token):
    try:
        if token:
            status_code, all_users, error = get_all_users(mysql)

            return (
                jsonify(
                    {
                        "status": status_code == 200,
                        "data": all_users,
                        "error": f"{error}",
                    }
                ),
                status_code,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        # return jsonify({"status": False, "data": None, "error": f"{e}"}), 500
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/active-users", methods=["GET"])
@token_required
def view_active_users(token):
    try:
        if token:
            # status_code, non_deleted_files, error = get_non_deleted_files(mysql)
            status_code, active_users, error = get_all_active_users(mysql)
            read_perm, write_perm, delete_perm, edit_perm = 0, 0, 0, 0
            for user in active_users:
                if user["Role"][:1] == "1":
                    read_perm += 1
                if user["Role"][1:2] == "1":
                    write_perm += 1
                if user["Role"][2:3] == "1":
                    edit_perm += 1
                if user["Role"][3:4] == "1":
                    delete_perm += 1
            data = {
                "active_users": len(active_users),
                "read_perm": read_perm,
                "write_perm": write_perm,
                "edit_perm": edit_perm,
                "delete_perm": delete_perm,
            }

            return (
                jsonify(
                    {"status": status_code == 200, "data": data, "error": f"{error}"}
                ),
                status_code,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        # return jsonify({"status": False, "data": None, "error": f"{e}"}), 500
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/logs", methods=["GET"])
@token_required
def get_logs_by_limit(token):
    try:
        if token:
            limit = request.args.get("limit")
            status_code, logs, error = get_logs(mysql, int(limit))

            return (
                jsonify(
                    {"status": status_code == 200, "data": logs, "error": f"{error}"}
                ),
                status_code,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        # return jsonify({"status": False, "data": None, "error": f"{e}"}), 500
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/upload", methods=["POST"])
@token_required
def fileupload(token):
    try:
        if token:
            # Get the uploaded file from the request
            if "file" not in request.files:
                return jsonify({"status": False, "message": "No File found!"})

            uploaded_file = request.files["file"]

            if uploaded_file:
                # Secure the filename to prevent malicious file uploads
                # TODO: Save file to S3 bucket
                # the upload won't work on heroku
                filename = secure_filename(uploaded_file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                uploaded_file.save(file_path)

                return jsonify(
                    {
                        "status": True,
                        "message": "File uploaded successfully!",
                        "filename": filename,
                    }
                )

            return jsonify(
                {
                    "status": False,
                    "message": "File Failed to upload!",
                    "filename": filename,
                }
            )

        return (
            jsonify({"status": False, "message": "", "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        print(e)
        return jsonify(
            {"status": False, "message": "Some error occured while uploading!"}, 500
        )


@app.route("/update-user", methods=["POST"])
@token_required
def update_user(token):
    req = request.get_json()

    try:
        if token:
            user_id = req["userId"]

            if user_id is None:
                return jsonify({"status": 500, "message": "Some error occurred!"})
            status_code, message = update_user_by_id(user_id, req, mysql)

            return jsonify({"status": status_code == 200, "message": message})

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        traceback.print_exception(*sys.exc_info())
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "message": f"{e}"})


@app.route("/get-user-by-id", methods=["POST"])
@token_required
def get_user(token):
    req = request.get_json()

    try:
        if token:
            user_id = req["userId"]
            if user_id is None:
                return jsonify({"status": 500, "message": "Some error occurred!"})

            status_code, data, error = get_user_by_id(user_id, mysql)

            return (
                jsonify({"status": status_code == 200, "data": data, "err": error}),
                status_code,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        print(e)
        traceback.print_exception(*sys.exc_info())
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "data": None, "err": "Some error occured!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data["email"]
    password = data["password"]
    try:
        user_data, token, status_code, error = sign_in_with_email_and_password(
            email, password, mysql
        )
        if user_data:
            user_data["Password"] = None
        return jsonify(
            {
                "status": status_code == 200,
                "data": user_data,
                "token": f"{token}",
                "err": error,
            }
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify(
            {"status": False, "data": None, "token": "", "err": "Some error occured"}
        )


@app.route("/change-password", methods=["POST"])
@token_required
def change_password(token):
    data = request.get_json()
    email = data["email"]
    old_password = data["old_password"]
    new_password = data["new_password"]
    try:
        if token:
            status_code, err = update_password(email, old_password, new_password, mysql)

            return jsonify(
                {
                    "status": status_code == 200,
                    "message": "Password updated successfully!",
                    "err": err,
                }
            )
        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # traceback.print_exception(*sys.exc_info())
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/deactivate", methods=["POST"])
@token_required
def deactivate(token):
    data = request.get_json()
    email = data["email"]

    try:
        if token:
            status_code, err = delete_user(email, mysql)

            return jsonify(
                {
                    "status": status_code == 200,
                    "message": "User deactivated successfully!",
                    "err": err,
                }
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/activate", methods=["POST"])
@token_required
def activate(token):
    data = request.get_json()
    email = data["email"]

    try:
        if token:
            status_code, err = activate_user(email, mysql)

            return jsonify(
                {
                    "status": status_code == 200,
                    "message": "User activated successfully!",
                    "err": err,
                }
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/get_type_total_count", methods=["GET"])
@token_required
def get_type_total_count(token):
    try:
        if token:
            days = request.args.get("days")
            if not days:
                return (
                    jsonify(
                        {"status": False, "data": None, "error": "Days not provided"}
                    ),
                    400,
                )

            fromDate = (dt.now() - timedelta(days=int(days))).strftime(
                "%Y-%m-%d 00:00:00"
            )
            toDate = (dt.now() + timedelta(days=int(1))).strftime("%Y-%m-%d 00:00:00")


            status_code, data, error = get_type_total_count_by_days(
                mysql, fromDate, toDate
            )

            # print(data, type(data))

            inlet_records, outlet_records, pump_records = [], [], []

            for d in data:
                if d["TYPE"] == "INLET":
                    inlet_records.append(d)
                elif d["TYPE"] == "OUTLET":
                    outlet_records.append(d)
                elif d["TYPE"] == "PUMP":
                    pump_records.append(d)

            final_data = {
                "fromDate": fromDate,
                "toDate": toDate,
                "inlet_records": inlet_records,
                "outlet_records": outlet_records,
                "pump_records": pump_records,
            }

            return (
                jsonify(
                    {
                        "status": status_code == 200,
                        "data": final_data,
                        "error": f"{error}",
                    }
                ),
                status_code,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )
    except Exception as e:
        print(e)
        # session["error"] = str(e)
        # return redirect("/")
        # return jsonify({"status": False, "data": None, "error": f"{e}"}), 500
        return jsonify({"status": False, "message": "Some error occurred!"})


@app.route("/insert_filemeta", methods=["POST"])
@token_required
def insert_file_metadata(token):
    try:
        if token:
            data = request.get_json()

            filename = data.get("FILENAME")
            uploaded_at = data.get("UPLOADED_AT")
            size = data.get("SIZE")
            file_location = data.get("FILE_LOCATION")
            file_type = data.get("TYPE")
            uploaded_filename = data.get("UPLOADED_FILENAME")
            data_kind = data.get("DATA_SOURCE")

            file_meta = {
                "FILENAME": filename,
                "UPLOADED_AT": uploaded_at,
                "SIZE": size,
                "FILE_LOCATION": file_location,
                "TYPE": file_type,
                "UPLOADED_FILENAME": uploaded_filename,
                "DATA_SOURCE": data_kind,
            }

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            # build a insert query
            insert_database_query = file_meta_object.insert_query(file_meta)

            # Insert data into the database
            cursor.execute(insert_database_query)
            mysql.connection.commit()
            # Close the cursor
            cursor.close()

            log = {
                "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "EVENT_TYPE": "FILE INSERTION",
                "MSG_USER_FRIENDLY": f"Data Inserted Successfully: {uploaded_filename}",
                "RESULT": "Success",
                "DESCRIPTION": f"Data Insertion Successfull: {uploaded_filename}",
            }
            insert_loggers(log, mysql)
            # print(log)
            return (
                jsonify({"status": True, "message": "Data inserted successfully"}),
                201,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "FILE INSERTION",
            "MSG_USER_FRIENDLY": f"Data Insertion Failed: {uploaded_filename}",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Insertion Failed: {uploaded_filename}: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500


@app.route("/insert_filemeta_list", methods=["POST"])
@token_required
def insert_file_metadata_list(token):
    try:
        if token:
            data = request.get_json()

            # Check if the JSON data is a list
            file_meta_array = data["FILE_META_ARRAY"]
            source_flag = int(data["SOURCE_FLAG"])

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            file_status = {}

            if source_flag == 1:
                # uploading the file from upload folder to S3

                for file_meta in file_meta_array:
                    value_sets = []

                    filename = file_meta.get("FILENAME")
                    uploaded_at = file_meta.get("UPLOADED_AT")
                    size = file_meta.get("SIZE")
                    file_location = file_meta.get("FILE_LOCATION")
                    file_type = file_meta.get("TYPE")
                    uploaded_filename = file_meta.get("UPLOADED_FILENAME")
                    data_kind = file_meta.get("DATA_SOURCE")

                    uploaded_success = upload_file_to_s3(filename)

                    if uploaded_success:
                        value_sets.append(
                            f"('{filename}', '{uploaded_at}', {size}, "
                            f"'{file_location}', '{file_type}', '{uploaded_filename}', "
                            f"'{data_kind}', NULL, NULL, FALSE)"
                        )

                    else:
                        raise Exception(
                            "uploading file to S3 from upload folder Failed!"
                        )

                    # Build the insert query with multiple value sets
                    insert_query = file_meta_object.insert_multiple_filemeta(value_sets)

                    # Execute the single insert query to insert all rows
                    cursor.execute(insert_query)

                    # Commit the changes
                    mysql.connection.commit()

                    find_id_query = file_meta_object.find_id_by_name(filename)
                    cursor.execute(find_id_query)

                    rows = cursor.fetchall()
                    total_files = len(rows)
                    file_id = int(rows[total_files - 1][0])

                    try:
                        if "csv" in file_type:
                            temp_file_path = f"upload/{filename}"
                            if data_kind == "IN":
                                extract_inlet_csv(temp_file_path, file_id, mysql)
                            elif data_kind == "OUT":
                                extract_outlet_csv(temp_file_path, file_id, mysql)
                            elif data_kind == "PUMP":
                                extract_pump_csv(temp_file_path, file_id, mysql)
                            # os.remove(temp_file_path) FILE DELETE SECTION
                        else:
                            temp_file_path = f"upload/{filename}"
                            if data_kind == "IN":
                                extract_inlet_xlsx(temp_file_path, file_id, mysql)
                            elif data_kind == "OUT":
                                extract_outlet_xlsx(temp_file_path, file_id, mysql)
                            elif data_kind == "PUMP":
                                extract_pump_xlsx(temp_file_path, file_id, mysql)
                            # os.remove(temp_file_path) FILE DELETE SECTION
                        file_status[uploaded_filename] = "success"
                    except Exception as err:
                        log = {
                            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "EVENT_TYPE": "FILE INSERTION",
                            "MSG_USER_FRIENDLY": f"Data Insertion Failed: {uploaded_filename}",
                            "RESULT": "Failed",
                            "DESCRIPTION": f"Data Insertion Failed: {uploaded_filename}: {err}",
                        }
                        insert_loggers(log, mysql)
                        file_status[uploaded_filename] = "failed"
                        delete_in_query = file_meta_object.delete_file_meta(file_id)
                        cursor.execute(delete_in_query)
                        mysql.connection.commit()

            else:
                # Prepare a list of value sets for the insert query

                for file_meta in file_meta_array:
                    value_sets = []

                    # print(file_meta)

                    filename = file_meta.get("FILENAME")
                    uploaded_at = file_meta.get("UPLOADED_AT")
                    size = file_meta.get("SIZE")
                    file_location = file_meta.get("FILE_LOCATION")
                    file_type = file_meta.get("TYPE")
                    uploaded_filename = file_meta.get("UPLOADED_FILENAME")
                    data_kind = file_meta.get("DATA_SOURCE")

                    # downloading file from S3 to "upload" folder
                    downloaded_success = download_file_from_s3(filename)

                    if downloaded_success:
                        value_sets.append(
                            f"('{filename}', '{uploaded_at}', {size}, "
                            f"'{file_location}', '{file_type}', '{uploaded_filename}', "
                            f"'{data_kind}', NULL, NULL, FALSE)"
                        )

                    else:
                        raise Exception("File download from S3 failed")

                    # Build the insert query with multiple value sets
                    insert_query = file_meta_object.insert_multiple_filemeta(value_sets)

                    # Execute the single insert query to insert all rows
                    cursor.execute(insert_query)

                    # Commit the changes
                    mysql.connection.commit()

                    find_id_query = file_meta_object.find_id_by_name(filename)
                    cursor.execute(find_id_query)

                    rows = cursor.fetchall()
                    total_files = len(rows)
                    file_id = int(rows[total_files - 1][0])

                    try:
                        if "csv" in file_type:
                            temp_file_path = f"download/{filename}"
                            if data_kind == "IN":
                                extract_inlet_csv(temp_file_path, file_id, mysql)
                            elif data_kind == "OUT":
                                extract_outlet_csv(temp_file_path, file_id, mysql)
                            elif data_kind == "PUMP":
                                extract_pump_csv(temp_file_path, file_id, mysql)
                            # os.remove(temp_file_path) FILE DELETE SECTION
                        else:
                            temp_file_path = f"download/{filename}"
                            if data_kind == "IN":
                                extract_inlet_xlsx(temp_file_path, file_id, mysql)
                            elif data_kind == "OUT":
                                extract_outlet_xlsx(temp_file_path, file_id, mysql)
                            elif data_kind == "PUMP":
                                extract_pump_xlsx(temp_file_path, file_id, mysql)
                            # os.remove(temp_file_path) FILE DELETE SECTION
                        file_status[uploaded_filename] = "success"
                    except Exception as err:
                        log = {
                            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "EVENT_TYPE": "FILE INSERTION",
                            "MSG_USER_FRIENDLY": f"Data Insertion Failed: {uploaded_filename}",
                            "RESULT": "Failed",
                            "DESCRIPTION": f"Data Insertion Failed: {uploaded_filename}: {err}",
                        }
                        insert_loggers(log, mysql)
                        file_status[uploaded_filename] = "failed"
                        print(log)
                        delete_in_query = file_meta_object.delete_file_meta(file_id)
                        cursor.execute(delete_in_query)
                        mysql.connection.commit()


            # Close the cursor
            cursor.close()

            log = {
                "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "EVENT_TYPE": "FILE INSERTION",
                "MSG_USER_FRIENDLY": f"Data Inserted Successfully: {uploaded_filename}",
                "RESULT": "Success",
                "DESCRIPTION": f"Data Insertion Successfull: {uploaded_filename}",
            }
            insert_loggers(log, mysql)

            return (
                jsonify({"status": True, "message": "Data inserted successfully", "file_status": file_status}),
                201,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "FILE INSERTION",
            "MSG_USER_FRIENDLY": f"Data Insertion Failed: {uploaded_filename}",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Insertion Failed: {uploaded_filename}: {e}",
        }
        insert_loggers(log, mysql)

        return jsonify({"status": False, "message": f"{log}"}), 500


@app.route("/delete_file_and_data", methods=["POST"])
@token_required
def soft_delete_file_metadata(token):
    try:
        if token:
            data = request.get_json()
            records = data.get("records")

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            for record in records:
                target_record_id = record.get("ID")
                delete_person = record.get("DELETED_BY")
                delete_timestamp = record.get("DELETE_TIMESTAMP")

                # execution of data_source SELECT query
                cursor.execute(
                    file_meta_object.select_get_kind_from_id(target_record_id)
                )

                results = cursor.fetchall()
                data_source = results[0][0]

                constants = {"IN": "INLET", "OUT": "OUTLET", "PUMP": "PUMP"}

                # deletion of Actual data as per data_source
                deletion_data_query = file_meta_object.delete_data(
                    target_record_id, constants[data_source]
                )

                cursor.execute(deletion_data_query)

                current_count = cursor.rowcount

                # insertion of total latest count in the TYPE_TOTAL_COUNT table
                insert_type = constants[data_source]
                total_count = 0
                timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")

                total_count = get_last_type_total_count(insert_type, mysql)

                if total_count == -1:
                    raise Exception("Getting Latest Count of Type")

                insert_type_total_count(
                    insert_type, (total_count - current_count), timestamp, mysql
                )

                # execution of file_Meta delete details updation
                cursor.execute(
                    file_meta_object.delete_meta,
                    (delete_person, True, delete_timestamp, target_record_id),
                )

            mysql.connection.commit()

            log = {
                "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "EVENT_TYPE": "FILE DELETION",
                "MSG_USER_FRIENDLY": "File & Data Deleted Successfully",
                "RESULT": "Success",
                "DESCRIPTION": f"File & Data Deletion Successfull: {target_record_id}",
            }
            insert_loggers(log, mysql)

            # Close the cursor
            cursor.close()

            # print(log)
            return (
                jsonify({"status": True, "message": "File Meta deleted successfully"}),
                201,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "FILE DELETION",
            "MSG_USER_FRIENDLY": "File & Data Deletion Failed",
            "RESULT": "Failed",
            "DESCRIPTION": f"File & Data Deletion Failed: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500


@app.route(
    "/get_all_file_metadata/<int:days>", defaults={"data_kind": None}, methods=["GET"]
)
@app.route("/get_all_file_metadata/<string:data_kind>/<int:days>", methods=["GET"])
@token_required
def get_all_file_metadata(token, data_kind, days):
    try:
        if token:
            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            if data_kind is None:
                # Execute a SELECT query to fetch all data from the FILESTORAGE_META table
                selection_query = file_meta_object.select_days_query(days)
                cursor.execute(selection_query)

            elif data_kind == "IN":
                selection_query = file_meta_object.select_meta_query("IN", days)
                cursor.execute(selection_query)

            elif data_kind == "OUT":
                selection_query = file_meta_object.select_meta_query("OUT", days)
                cursor.execute(selection_query)

            elif data_kind == "PUMP":
                selection_query = file_meta_object.select_meta_query("PUMP", days)
                cursor.execute(selection_query)

            # Fetch all rows as a list of dictionaries
            rows = cursor.fetchall()

            # Close the cursor
            cursor.close()

            # Convert the rows to a list of dictionaries
            file_metadata = []
            for row in rows:
                metadata_dict = {
                    "ID": row[0],
                    "FILENAME": row[1],
                    "UPLOADED_AT": dateToString(row[2]),
                    "SIZE": row[3],
                    "FILE_LOCATION": row[4],
                    "TYPE": row[5],
                    "UPLOADED_FILENAME": row[6],
                    "DATA_SOURCE": row[7],
                    "DELETE_TIMESTAMP": dateToString(row[8]),
                    "DELETED_BY": row[9],
                    "IS_DELETED": row[10],
                }

                file_metadata.append(metadata_dict)

            return jsonify({"status": True, "data": file_metadata}), 201

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "FILE RETRIEVAL",
            "MSG_USER_FRIENDLY": "File Meta Retrieval Failed",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Retrieval Failed: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500


@app.route("/get_kind_data_export", methods=["POST"])
@token_required
def get_kind_data_export(token):
    try:
        if token:
            data = request.get_json()
            data_source = data.get("data_source")
            filters = data.get("filters")

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            build_select_query = file_meta_object.get_total_data_by_filter_export(
                data_source, filters
            )

            cursor.execute(build_select_query)

            # Fetch all rows as a list of dictionaries
            rows = cursor.fetchall()

            desc = cursor.description
            column_names = [col[0] for col in desc]

            data = [dict(zip(column_names, row)) for row in rows]

            # Close the cursor
            cursor.close()

            return jsonify({"status": True, "data": data}), 201

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "EXPORT DATA",
            "MSG_USER_FRIENDLY": "Data Retrieval for Export Failed",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Retrieval Failed: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500


@app.route("/get_kind_data", methods=["POST"])
@token_required
def get_kind_data(token):
    try:
        if token:
            data = request.get_json()
            data_source = data.get("data_source")
            filters = data.get("filters")
            offset = int(data.get("offset"))
            limit = int(data.get("limit"))

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            build_select_query, count_query = file_meta_object.get_data_by_filters(
                data_source, filters, offset, limit
            )

            cursor.execute(count_query)

            rows = cursor.fetchall()

            total_no_of_tuples = rows[0][0]
            print(total_no_of_tuples)

            cursor.execute(build_select_query)

            # Fetch all rows as a list of dictionaries
            rows = cursor.fetchall()

            desc = cursor.description
            column_names = [col[0] for col in desc]

            data = [dict(zip(column_names, row)) for row in rows]

            # Close the cursor
            cursor.close()

            return (
                jsonify(
                    {"status": True, "data": data, "total_count": total_no_of_tuples}
                ),
                201,
            )

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "DATA RETRIEVAL",
            "MSG_USER_FRIENDLY": "Data Retrieval Failed",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Retrieval Failed: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500


@app.route("/edit_filtered_data", methods=["POST"])
@token_required
def edit_filtered_data(token):
    try:
        if token:
            data = request.get_json()
            data_source = data.get("data_source")
            filters = data.get("filters")
            column = data.get("column")
            from_replace = data.get("from_replace")
            to_replace = data.get("to_replace")

            # Create a MySQL cursor
            cursor = mysql.connection.cursor()

            edit_query = file_meta_object.edit_total_data_by_filter(
                data_source, filters, column, from_replace, to_replace
            )

            cursor.execute(edit_query)

            mysql.connection.commit()

            # Close the cursor
            cursor.close()

            log = {
                "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "EVENT_TYPE": "DATA EDIT",
                "MSG_USER_FRIENDLY": "Data Editing Successful",
                "RESULT": "Success",
                "DESCRIPTION": f"Data Editing Successful",
            }
            insert_loggers(log, mysql)

            return jsonify({"status": True, "msg": log}), 201

        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )

    except Exception as e:
        log = {
            "TIMESTAMP": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "EVENT_TYPE": "DATA EDIT",
            "MSG_USER_FRIENDLY": "Data Editing Failed",
            "RESULT": "Failed",
            "DESCRIPTION": f"Data Editing Failed: {e}",
        }
        insert_loggers(log, mysql)
        # print(log)
        return jsonify({"status": False, "message": f"{str(e)}"}), 500
    

@app.route("/get_column_names/<data_source>", methods=["GET"])
@token_required
def uploading_file(token, data_source):
    try:
        if token:
            rows = get_header_fields_func(data_source, mysql)
            return jsonify({"status": True, "data": rows}), 201
        return (
            jsonify({"status": False, "data": None, "error": "Token not provided"}),
            401,
        )        
    except Exception as e:
        return jsonify({"status": False, "message": f"{str(e)}"}), 500
    
# @app.route("/uploading", methods=["POST"])
# def uploading_file():
#     download_file_from_s3('18.csv')
#     return "success"

# THIS IS FOR TESTING EXTRACTION OF CSV DATA AND CHECKING THE DATABASE
# REMOVE BEFORE_REQUEST AUTHENTICATION BARRIER THEN TEST THIS
# @app.route("/upload", methods=["POST"])
# def fileupload():

#     # Get the uploaded file from the request
#     uploaded_file = request.files['file']
#     temp_file_path = os.path.join("C:\\Users\\user\\Downloads", uploaded_file.filename)
#     print(temp_file_path)
#     fileid = uploaded_file.filename.strip(".csv")
#     extract_outlet_csv(temp_file_path, int(fileid), mysql)
#     return {"msg":"output"}

# @app.route("/upload", methods=["POST"])
# def fileupload():

#     # Get the uploaded file from the request
#     uploaded_file = request.files['file']
#     temp_file_path = os.path.join("C:\\Users\\user\\Downloads", uploaded_file.filename)
#     # print(temp_file_path)
#     fileid = uploaded_file.filename.strip(".xlsx")
#     insert_xlsx_data_to_mysql(temp_file_path, fileid, mysql)
#     return {"msg":"output"}
