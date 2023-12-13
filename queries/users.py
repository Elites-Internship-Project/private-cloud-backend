select_all = "SELECT * FROM Users"
select_all_active = "SELECT * FROM Users WHERE IsActive = 1"


select_by_id = "SELECT * FROM Users WHERE UserId = %s"


def update_by_id(user_id, new_user_data):
    q = f"""UPDATE Users SET """

    for key, value in new_user_data.items():
        if list(new_user_data.keys()).index(key) == (len(new_user_data.keys()) - 1):
            q = q + key + "=" + f"""'{new_user_data[key]}'"""
        else:
            q = q + key + "=" + f"""'{new_user_data[key]}'""" + ","

    q = q + f"""WHERE UserId = '{user_id}'"""

    return q


def insert_user(user):
    query = f"""INSERT INTO Users(Name, Email, Role, Password, Created_Date, IsActive) VALUES (%s,%s,%s,%s,%s,%s)"""

    return query


delete_by_email = "UPDATE Users SET IsActive = 0 WHERE Email = %s"
activate_by_email = "UPDATE Users SET IsActive = 1 WHERE Email = %s"

select_by_email = "SELECT * FROM Users WHERE Email = %s and IsActive=1"


def update_pass_by_email(email, new_pass):
    query = f"""UPDATE Users SET Password = '{new_pass}' WHERE Email = '{email}'"""

    return query


# hashed_pwd = h.hash(password)
#         print(hashed_pwd)
#         update_query = "UPDATE Users SET Password = %s WHERE Email = %s"
#         cur.execute(
#             update_query,
#             [
#                 hashed_pwd,
#                 email,
#             ],
#         )
#         mysql.connection.commit()
