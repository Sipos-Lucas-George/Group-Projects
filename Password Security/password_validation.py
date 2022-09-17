def check_len(password):
    if len(password) < 7:
        return False
    return True


def read_words(filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                yield line[:-1]
    except UnicodeDecodeError:
        pass


def check_common_passwords(password, pseudo_password):  # returns True or the name
    for word in read_words('templates/rockyou.txt'):
        if password == word or pseudo_password == word:
            return word
    return True


def english_upper_case(password):
    for letter in password:
        if letter.isupper():
            return True
    return False


def english_lower_case(password):
    for letter in password:
        if letter.islower():
            return True
    return False


def has_numerals(password):
    for letter in password:
        if letter.isdigit():
            return True
    return False


def has_symbols(password):
    symbols = "!@#$%^&*~()[]{}/;,"
    for letter in password:
        if letter in symbols:
            return True
    return False


def generate_pseudo_password(password):
    pseudo_passwd_dict = {  # and capitals !!
        "@": "a",
        "!": "i",
        "$": "s",
        "0": "o",
        "3": "e",
        "1": "i",
        "6": "g",
        "4": "a",
        "8": "b",
        "5": "s",
        "^": "a",
        "#": "h",
        "2": "s",
    }

    pseudo_password = ""
    for i in range(len(password)):
        if password[i] not in pseudo_passwd_dict.keys():
            pseudo_password += password[i]
        else:
            pseudo_password += pseudo_passwd_dict[password[i]]

    return password


def rules(password):
    errors = []
    if not check_len(password):
        errors.append("Password length should be at least 7 characters.")
    common_password_flag = check_common_passwords(password, generate_pseudo_password(password))
    if common_password_flag is not True:
        errors.append("Password is in a list of vulnerable passwords.")
    if not english_upper_case(password):
        errors.append("Password should contain at least one uppercase.")
    if not english_lower_case(password):
        errors.append("Password should contain at least one lowercase.")
    if not has_numerals(password):
        errors.append("Password should have at least one numeral.")
    if not has_symbols(password):
        errors.append("Password should have symbols.")

    return errors, len(errors)


def message_status_password(status_password):
    status_password = int(status_password)
    message = "This password is considered "
    if status_password >= 5:
        message += "weak"
    elif status_password >= 3:
        message += "decent"
    elif status_password >= 1:
        message += "strong"
    elif status_password == 0:
        message += "excellent"
    message += "."

    return message


def generate_password_instances(password):
    pseudo_password = generate_pseudo_password(password)
    lowered_password = password.lower()
    lowered_pseudo_password = pseudo_password.lower()
    return [password, pseudo_password, lowered_password, lowered_pseudo_password]


def validate_passwords(password, found_in_query_counter):
    common_error_list, number_of_errors = rules(password)
    common_error_list.append("This password, or slightly different instances of it, were used by "
                             + str(found_in_query_counter) + " users on this site.")

    if "Password is in a list of vulnerable passwords." in common_error_list:
        password_status = message_status_password(7)
    else:
        password_status = message_status_password(number_of_errors)

    return common_error_list, password_status
