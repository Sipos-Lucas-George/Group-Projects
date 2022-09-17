from password_validation import *

from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import Error
from flask import Flask, render_template, request
import sqlite3
import traceback


app = Flask(__name__)


def create_connection():
    connection = None
    try:
        connection = sqlite3.connect("data.db")
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        traceback.print_exc()

    return connection


def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
        traceback.print_exc()


def execute_read_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as e:
        print(f"The error '{e}' occurred")
        traceback.print_exc()


def execute_insert_query(connection, query, password, counter):
    cursor = connection.cursor()
    try:
        cursor.execute(query, [password, counter])
        connection.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
        traceback.print_exc()


def execute_update_query(connection, password, counter_password):
    try:
        cursor = connection.cursor()
        query = "Update password_table set counter_password = ? where password = ?"
        data = (counter_password + 1, password)
        cursor.execute(query, data)
        connection.commit()

    except Exception as error:
        print("Failed to update sqlite table", error)


def execute_verify_in_database_query(connection, query, user_password):
    cursor = connection.cursor()
    found_password = 0
    users = execute_read_query(connection, query)
    for user in users:
        if check_password_hash(user[0], user_password):
            execute_update_query(connection, user[0], user[1])
            found_password = 1
            connection.commit()
    return found_password


def execute_validation_query(connection, query, user_password):
    cursor = connection.cursor()
    users = execute_read_query(connection, query)
    for user in users:
        if check_password_hash(user[0], user_password):
            return user[1]
    return 0


@app.route('/', methods=['GET', 'POST'])
def user_input():
    database_connection = create_connection()
    create_password_table = "CREATE TABLE IF NOT EXISTS password_table(password TEXT NOT NULL, counter_password INTEGER);"
    execute_query(database_connection, create_password_table)

    if request.method == 'POST':
        user_password = request.form.get("password", None)
        select_users = "SELECT * from password_table"
        sql_insert = "INSERT INTO password_table (password, counter_password) VALUES (?, ?)"

        verify_password_exists = []
        verify_password_exists = generate_password_instances(user_password)
        counter_validator = 0
        for verify in verify_password_exists:
            if verify != verify_password_exists[0] or counter_validator == 0:
                returned_value_validation = execute_validation_query(database_connection, select_users, verify)
                if returned_value_validation != 0:
                    counter_validator += returned_value_validation

        errors, message = validate_passwords(user_password, counter_validator)

        if execute_verify_in_database_query(database_connection, select_users, user_password) == 0:
            sql_counter = 1
            execute_insert_query(database_connection, sql_insert, generate_password_hash(user_password), sql_counter)

        users = execute_read_query(database_connection, select_users)
        for user in users:
            print(*user)

        print(rules(user_password))

        return render_template('statistics.html', errors=errors, message=message)
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
